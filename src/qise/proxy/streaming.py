"""SSEStreamHandler — process SSE streaming responses with guard interception.

Core strategy — non-blocking streaming:
  - Pure text deltas → pass through immediately (zero latency)
  - tool_use starts → buffer, collect full arguments, then check
  - tool_use BLOCK → send SSE error event + [DONE]
  - Text output leak detection → after stream ends (non-blocking)

tool_use buffering state machine:
  IDLE → tool_calls delta → COLLECTING
  COLLECTING → same index arguments delta → COLLECTING
  COLLECTING → finish_reason or new index → CHECK → guard pipeline
  CHECK → PASS → TRANSMIT buffered
  CHECK → BLOCK → SSE error + [DONE]
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncGenerator
from enum import Enum
from typing import Any

from qise.proxy.interceptor import ProxyInterceptor
from qise.proxy.parser import ResponseParser

logger = logging.getLogger("qise.proxy.streaming")


class StreamState(str, Enum):
    IDLE = "idle"
    COLLECTING = "collecting"
    CHECK = "check"


class BufferedToolCall:
    """Accumulates a tool call from streaming deltas."""

    def __init__(self, index: int) -> None:
        self.index = index
        self.tool_name = ""
        self.arguments_json = ""
        self.call_id = ""

    @property
    def tool_args(self) -> dict[str, Any]:
        """Parse accumulated arguments JSON."""
        if not self.arguments_json:
            return {}
        try:
            return json.loads(self.arguments_json)
        except (json.JSONDecodeError, TypeError):
            return {"_raw_arguments": self.arguments_json}

    def is_complete(self) -> bool:
        """True when we have both name and arguments are being collected."""
        return bool(self.tool_name)


class SSEStreamHandler:
    """Process SSE streaming responses with guard interception.

    Usage:
        handler = SSEStreamHandler(interceptor, session_id)
        async for chunk in handler.process_stream(upstream_response, raw_request_body):
            await response.write(chunk)
    """

    def __init__(
        self,
        interceptor: ProxyInterceptor,
        session_id: str | None = None,
    ) -> None:
        self._interceptor = interceptor
        self._session_id = session_id
        self._parser = ResponseParser()
        self._state = StreamState.IDLE

        # Buffered tool calls by index
        self._buffered: dict[int, BufferedToolCall] = {}
        # Completed tool calls waiting for transmission
        self._completed_indices: list[int] = []
        # Accumulated text for post-stream output check
        self._text_chunks: list[str] = []

    async def process_stream(
        self,
        upstream_resp: Any,
        session_id: str | None = None,
    ) -> AsyncGenerator[bytes, None]:
        """Process an SSE stream from the upstream, yielding chunks.

        Text deltas are passed through immediately.
        Tool calls are buffered until complete, then checked by guards.

        Args:
            upstream_resp: aiohttp ClientResponse from the upstream.
            session_id: Optional session ID for tracking.

        Yields:
            SSE-formatted bytes chunks.
        """
        self._session_id = session_id or self._session_id

        try:
            # Support both aiohttp ClientResponse (has .content) and
            # raw async generators (for testing)
            if hasattr(upstream_resp, "content"):
                line_iter = upstream_resp.content
            else:
                line_iter = upstream_resp

            async for line in line_iter:
                decoded = line.decode("utf-8", errors="replace") if isinstance(line, bytes) else line

                # SSE format: lines starting with "data: "
                if not decoded.startswith("data: "):
                    # Forward non-data lines (comments, empty lines)
                    yield line if isinstance(line, bytes) else decoded.encode("utf-8")
                    continue

                data = decoded[6:].strip()

                # End of stream
                if data == "[DONE]":
                    # Process any remaining buffered tool calls
                    async for chunk in self._flush_remaining():
                        yield chunk
                    yield b"data: [DONE]\n\n"
                    # Post-stream output check (non-blocking)
                    # Text is already sent, so we just log warnings
                    self._post_stream_output_check()
                    return

                # Parse the SSE data
                try:
                    chunk = json.loads(data)
                except json.JSONDecodeError:
                    # Can't parse — pass through
                    yield decoded.encode("utf-8")
                    continue

                # Process the chunk
                async for out_chunk in self._process_chunk(chunk, decoded):
                    yield out_chunk

        except Exception as e:
            logger.error("SSE stream error: %s", e)
            error_event = self._sse_error(f"Stream error: {e}")
            yield error_event.encode("utf-8")
            yield b"data: [DONE]\n\n"

    async def _process_chunk(
        self,
        chunk: dict[str, Any],
        original_line: str,
    ) -> AsyncGenerator[bytes, None]:
        """Process a single SSE chunk.

        - Text deltas: pass through immediately
        - Tool call deltas: buffer until complete, then check
        """
        choices = chunk.get("choices", [])
        if not choices:
            yield original_line.encode("utf-8")
            return

        delta = choices[0].get("delta", {})
        finish_reason = choices[0].get("finish_reason")

        # Collect text for post-stream output check
        if isinstance(delta.get("content"), str):
            self._text_chunks.append(delta["content"])
            # Text deltas pass through immediately
            yield original_line.encode("utf-8")
            return

        # Handle tool calls
        tool_calls_deltas = delta.get("tool_calls")
        if tool_calls_deltas:
            for tc_delta in tool_calls_deltas:
                index = tc_delta.get("index", 0)
                func = tc_delta.get("function", {})

                # Initialize or continue buffering
                if index not in self._buffered:
                    self._buffered[index] = BufferedToolCall(index)

                buf = self._buffered[index]

                # Accumulate name
                if func.get("name"):
                    buf.tool_name = func["name"]

                # Accumulate arguments
                if isinstance(func.get("arguments"), str):
                    buf.arguments_json += func["arguments"]

                # Accumulate call ID
                if tc_delta.get("id"):
                    buf.call_id = tc_delta["id"]

            # Don't yield yet — wait for completion
            self._state = StreamState.COLLECTING
            return

        # finish_reason="tool_calls" or "stop" — check buffered calls
        if finish_reason in ("tool_calls", "stop"):
            if self._buffered:
                async for out in self._flush_remaining():
                    yield out
            else:
                yield original_line.encode("utf-8")
            return

        # Other deltas (e.g., role) — pass through
        yield original_line.encode("utf-8")

    async def _flush_remaining(self) -> AsyncGenerator[bytes, None]:
        """Check all buffered tool calls and yield appropriate SSE events."""
        for index, buf in sorted(self._buffered.items()):
            if not buf.tool_name:
                # Incomplete tool call — pass through what we have
                continue

            # Run guard check
            result = self._interceptor.intercept_response(
                parsed=self._parser.parse(self._build_response_body(buf)),
                raw_body={},
            )

            if result.action == "block" and self._interceptor._config and self._interceptor._config.block_on_guard_block:
                logger.warning("Stream: blocked tool call %s — %s", buf.tool_name, result.block_reason)
                # Send error event and stop
                error_event = self._sse_error(
                    f"Qise blocked tool call '{buf.tool_name}': {result.block_reason}"
                )
                yield error_event.encode("utf-8")
                yield b"data: [DONE]\n\n"
                self._buffered.clear()
                return

            if result.action == "warn":
                # Add warning as SSE event, then continue
                warn_event = self._sse_warning(result.warnings)
                yield warn_event.encode("utf-8")

            # Emit the buffered tool call chunks
            yield self._emit_buffered_tool_call(buf)

        self._buffered.clear()
        self._state = StreamState.IDLE

    def _emit_buffered_tool_call(self, buf: BufferedToolCall) -> bytes:
        """Reconstruct and emit a buffered tool call as SSE."""
        chunk = {
            "choices": [
                {
                    "delta": {
                        "tool_calls": [
                            {
                                "index": buf.index,
                                "id": buf.call_id,
                                "function": {
                                    "name": buf.tool_name,
                                    "arguments": buf.arguments_json,
                                },
                            }
                        ]
                    },
                    "finish_reason": None,
                }
            ],
        }
        return f"data: {json.dumps(chunk)}\n\n".encode()

    def _build_response_body(self, buf: BufferedToolCall) -> dict[str, Any]:
        """Build a synthetic response body for the interceptor from a buffered tool call."""
        return {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": buf.call_id,
                                "function": {
                                    "name": buf.tool_name,
                                    "arguments": buf.arguments_json,
                                },
                            }
                        ],
                    },
                }
            ],
        }

    def _post_stream_output_check(self) -> None:
        """Non-blocking output check after stream completes.

        Text has already been sent to the client, so we can't block it.
        Instead, log warnings for detected leaks.
        """
        full_text = "".join(self._text_chunks)
        if not full_text:
            return

        result = self._interceptor.intercept_response(
            parsed=self._parser.parse({
                "choices": [{"message": {"role": "assistant", "content": full_text}}],
            }),
            raw_body={},
        )

        if result.action in ("warn", "block"):
            logger.warning(
                "Stream output check: %s — %s",
                result.action,
                "; ".join(result.warnings[:3]),
            )

    def _sse_error(self, message: str) -> str:
        """Format an SSE error event."""
        event_data = json.dumps({"error": message})
        return f"event: error\ndata: {event_data}\n\n"

    def _sse_warning(self, warnings: list[str]) -> str:
        """Format an SSE warning event."""
        event_data = json.dumps({"warnings": warnings[:5]})
        return f"event: warning\ndata: {event_data}\n\n"
