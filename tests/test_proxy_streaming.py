"""Tests for Qise proxy SSE streaming handler."""

from __future__ import annotations

import json
from typing import AsyncIterator

import pytest

from qise.core.shield import Shield
from qise.proxy.config import ProxyConfig
from qise.proxy.interceptor import ProxyDecision, ProxyInterceptor
from qise.proxy.streaming import AnthropicSSEStreamHandler, BufferedToolCall, SSEStreamHandler


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def shield() -> Shield:
    return Shield.from_config()


@pytest.fixture
def interceptor(shield: Shield) -> ProxyInterceptor:
    config = ProxyConfig()
    return ProxyInterceptor(shield, config)


# ---------------------------------------------------------------------------
# BufferedToolCall tests
# ---------------------------------------------------------------------------


class TestBufferedToolCall:

    def test_empty_arguments(self) -> None:
        buf = BufferedToolCall(index=0)
        assert buf.tool_args == {}
        assert not buf.is_complete()

    def test_accumulate_name_and_args(self) -> None:
        buf = BufferedToolCall(index=0)
        buf.tool_name = "bash"
        buf.arguments_json = '{"command": "ls"}'
        assert buf.is_complete()
        assert buf.tool_args == {"command": "ls"}

    def test_partial_json_arguments(self) -> None:
        buf = BufferedToolCall(index=0)
        buf.tool_name = "bash"
        # Streaming often delivers partial JSON
        buf.arguments_json = '{"command": "ls'
        assert buf.tool_args == {"_raw_arguments": '{"command": "ls'}

    def test_accumulate_incremental(self) -> None:
        buf = BufferedToolCall(index=0)
        buf.call_id = "call_1"
        buf.tool_name = "bash"
        buf.arguments_json += '{"comma'
        buf.arguments_json += 'nd": "rm'
        buf.arguments_json += ' -rf /"}'
        assert buf.tool_args == {"command": "rm -rf /"}
        assert buf.call_id == "call_1"


# ---------------------------------------------------------------------------
# SSEStreamHandler tests
# ---------------------------------------------------------------------------


class TestSSEStreamHandler:

    def test_handler_creation(self, interceptor: ProxyInterceptor) -> None:
        handler = SSEStreamHandler(interceptor)
        assert handler._state.value == "idle"

    @pytest.mark.asyncio
    async def test_text_stream_passthrough(self, interceptor: ProxyInterceptor) -> None:
        """Pure text deltas should pass through immediately."""

        async def _mock_stream() -> AsyncIterator[bytes]:
            yield b'data: {"choices":[{"delta":{"content":"Hello"},"finish_reason":null}]}\n\n'
            yield b'data: {"choices":[{"delta":{"content":" World"},"finish_reason":null}]}\n\n'
            yield b"data: [DONE]\n\n"

        handler = SSEStreamHandler(interceptor)
        chunks: list[bytes] = []
        async for chunk in handler.process_stream(_mock_stream()):
            chunks.append(chunk)

        # All chunks should be forwarded
        assert len(chunks) >= 2  # At least the two text chunks + [DONE]

    @pytest.mark.asyncio
    async def test_stream_with_done(self, interceptor: ProxyInterceptor) -> None:
        """Stream ending with [DONE] should complete normally."""

        async def _mock_stream() -> AsyncIterator[bytes]:
            yield b'data: {"choices":[{"delta":{"role":"assistant"},"finish_reason":null}]}\n\n'
            yield b"data: [DONE]\n\n"

        handler = SSEStreamHandler(interceptor)
        chunks: list[bytes] = []
        async for chunk in handler.process_stream(_mock_stream()):
            chunks.append(chunk)

        # Should include the [DONE] marker
        decoded = b"".join(chunks).decode("utf-8")
        assert "[DONE]" in decoded


    @pytest.mark.asyncio
    async def test_tool_use_streaming_pass(self, interceptor: ProxyInterceptor) -> None:
        """Safe tool calls in stream should pass through after buffering."""

        async def _mock_stream() -> AsyncIterator[bytes]:
            # Tool call delta — name
            yield b'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"bash","arguments":""}}]},"finish_reason":null}]}\n\n'
            # Tool call delta — arguments
            yield b'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\\"command\\": \\"ls\\"}"}}]},"finish_reason":null}]}\n\n'
            # Finish
            yield b'data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}\n\n'
            yield b"data: [DONE]\n\n"

        handler = SSEStreamHandler(interceptor)
        chunks: list[bytes] = []
        async for chunk in handler.process_stream(_mock_stream()):
            chunks.append(chunk)

        # Should complete without error
        decoded = b"".join(chunks).decode("utf-8")
        assert "[DONE]" in decoded

    @pytest.mark.asyncio
    async def test_non_data_lines_passthrough(self, interceptor: ProxyInterceptor) -> None:
        """Non-data lines (comments, empty) should pass through."""

        async def _mock_stream() -> AsyncIterator[bytes]:
            yield b": this is a comment\n\n"
            yield b'\n'
            yield b'data: {"choices":[{"delta":{"content":"Hi"},"finish_reason":null}]}\n\n'
            yield b"data: [DONE]\n\n"

        handler = SSEStreamHandler(interceptor)
        chunks: list[bytes] = []
        async for chunk in handler.process_stream(_mock_stream()):
            chunks.append(chunk)

        # Should include the comment line
        decoded = b"".join(chunks).decode("utf-8")
        assert "comment" in decoded

    @pytest.mark.asyncio
    async def test_unparseable_data_passthrough(self, interceptor: ProxyInterceptor) -> None:
        """Unparseable SSE data should pass through unchanged."""

        async def _mock_stream() -> AsyncIterator[bytes]:
            yield b"data: {not valid json}\n\n"
            yield b"data: [DONE]\n\n"

        handler = SSEStreamHandler(interceptor)
        chunks: list[bytes] = []
        async for chunk in handler.process_stream(_mock_stream()):
            chunks.append(chunk)

        decoded = b"".join(chunks).decode("utf-8")
        assert "not valid json" in decoded

    @pytest.mark.asyncio
    async def test_empty_stream(self, interceptor: ProxyInterceptor) -> None:
        """Empty stream should complete without error."""

        async def _mock_stream() -> AsyncIterator[bytes]:
            yield b"data: [DONE]\n\n"

        handler = SSEStreamHandler(interceptor)
        chunks: list[bytes] = []
        async for chunk in handler.process_stream(_mock_stream()):
            chunks.append(chunk)

        decoded = b"".join(chunks).decode("utf-8")
        assert "[DONE]" in decoded


class FakeAnthropicInterceptor:
    def __init__(self, action: str = "pass") -> None:
        self._config = ProxyConfig()
        self.action = action
        self.seen_tool_name = ""
        self.seen_tool_args = {}

    def intercept_response(self, parsed, raw_body, agent_name: str = "") -> ProxyDecision:
        if parsed.tool_calls:
            self.seen_tool_name = parsed.tool_calls[0].tool_name
            self.seen_tool_args = parsed.tool_calls[0].tool_args
        if self.action == "block":
            return ProxyDecision(action="block", block_reason="dangerous command")
        return ProxyDecision(action="pass")


class TestAnthropicSSEStreamHandler:

    @pytest.mark.asyncio
    async def test_text_stream_passthrough(self) -> None:
        async def _mock_stream() -> AsyncIterator[bytes]:
            yield (
                b"event: content_block_delta\n"
                b'data: {"type":"content_block_delta","index":0,'
                b'"delta":{"type":"text_delta","text":"Hello"}}\n\n'
            )
            yield b'event: message_stop\ndata: {"type":"message_stop"}\n\n'

        handler = AnthropicSSEStreamHandler(FakeAnthropicInterceptor())  # type: ignore[arg-type]
        chunks: list[bytes] = []
        async for chunk in handler.process_stream(_mock_stream()):
            chunks.append(chunk)

        decoded = b"".join(chunks).decode("utf-8")
        assert "text_delta" in decoded
        assert "message_stop" in decoded

    @pytest.mark.asyncio
    async def test_tool_use_buffered_until_guard_passes(self) -> None:
        interceptor = FakeAnthropicInterceptor()

        async def _mock_stream() -> AsyncIterator[bytes]:
            yield (
                b"event: content_block_start\n"
                b'data: {"type":"content_block_start","index":1,'
                b'"content_block":{"type":"tool_use","id":"toolu_1","name":"bash","input":{}}}\n\n'
            )
            yield (
                b"event: content_block_delta\n"
                b'data: {"type":"content_block_delta","index":1,'
                b'"delta":{"type":"input_json_delta","partial_json":"{\\"command\\":\\"ls\\"}"}}\n\n'
            )
            yield b'event: content_block_stop\ndata: {"type":"content_block_stop","index":1}\n\n'
            yield b'event: message_stop\ndata: {"type":"message_stop"}\n\n'

        handler = AnthropicSSEStreamHandler(interceptor)  # type: ignore[arg-type]
        chunks: list[bytes] = []
        async for chunk in handler.process_stream(_mock_stream()):
            chunks.append(chunk)

        decoded = b"".join(chunks).decode("utf-8")
        assert "tool_use" in decoded
        assert interceptor.seen_tool_name == "bash"
        assert interceptor.seen_tool_args == {"command": "ls"}

    @pytest.mark.asyncio
    async def test_tool_use_block_emits_anthropic_error(self) -> None:
        async def _mock_stream() -> AsyncIterator[bytes]:
            yield (
                b"event: content_block_start\n"
                b'data: {"type":"content_block_start","index":1,'
                b'"content_block":{"type":"tool_use","id":"toolu_1","name":"bash","input":{}}}\n\n'
            )
            yield (
                b"event: content_block_delta\n"
                b'data: {"type":"content_block_delta","index":1,'
                b'"delta":{"type":"input_json_delta","partial_json":"{\\"command\\":\\"rm -rf /\\"}"}}\n\n'
            )
            yield b'event: content_block_stop\ndata: {"type":"content_block_stop","index":1}\n\n'
            yield b'event: message_stop\ndata: {"type":"message_stop"}\n\n'

        handler = AnthropicSSEStreamHandler(FakeAnthropicInterceptor("block"))  # type: ignore[arg-type]
        chunks: list[bytes] = []
        async for chunk in handler.process_stream(_mock_stream()):
            chunks.append(chunk)

        decoded = b"".join(chunks).decode("utf-8")
        assert "event: error" in decoded
        assert "Qise blocked tool call" in decoded
        assert "message_stop" not in decoded
