"""Request/Response parser for OpenAI-compatible and Anthropic API formats.

Parses model requests and responses to extract:
  - User messages, tool results, tool descriptions from requests
  - Tool calls, reasoning, text content from responses
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Parsed structures
# ---------------------------------------------------------------------------


class ParsedToolCall(BaseModel):
    """A single tool call extracted from a response."""

    tool_name: str
    tool_args: dict[str, Any] = {}
    call_id: str = ""


class ParsedMessage(BaseModel):
    """A single message extracted from a request or response."""

    role: str
    content: str = ""
    tool_calls: list[ParsedToolCall] = Field(default_factory=list)
    tool_call_id: str = ""
    trust_boundary: str | None = None


class ParsedToolDef(BaseModel):
    """A tool definition extracted from the request's tools array."""

    name: str
    description: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)


class ParsedRequest(BaseModel):
    """Structured representation of a chat completion request."""

    model: str = ""
    messages: list[ParsedMessage] = Field(default_factory=list)
    tools: list[ParsedToolDef] = Field(default_factory=list)
    stream: bool = False
    raw_body: dict[str, Any] = Field(default_factory=dict)


class ParsedResponse(BaseModel):
    """Structured representation of a chat completion response."""

    content: str = ""
    tool_calls: list[ParsedToolCall] = Field(default_factory=list)
    reasoning: str = ""
    finish_reason: str = ""
    model: str = ""
    raw_body: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Trust boundary inference
# ---------------------------------------------------------------------------

_TRUST_BOUNDARY_MAP: dict[str, str] = {
    "user": "user_input",
    "tool": "tool_result",
}


def _infer_trust_boundary(role: str, msg: dict[str, Any]) -> str | None:
    """Infer the trust boundary from a message's role and content."""
    if role == "user":
        # Check if this is a tool_result message
        if msg.get("tool_call_id") or msg.get("name"):
            return "tool_result"
        return "user_input"
    if role == "assistant":
        return "agent_message"
    if role == "system":
        return "context_file"
    return None


def _extract_content_text(value: Any) -> str:
    """Extract guard-readable text from string or content-block values."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                item_type = item.get("type")
                if item_type == "text" and isinstance(item.get("text"), str):
                    parts.append(item["text"])
                elif item_type == "tool_result":
                    nested = _extract_content_text(item.get("content"))
                    if nested:
                        parts.append(nested)
        return "\n".join(part for part in parts if part)
    return ""


# ---------------------------------------------------------------------------
# RequestParser
# ---------------------------------------------------------------------------


class RequestParser:
    """Parse OpenAI-compatible chat completion and Anthropic Messages requests.

    Extracts messages, tool definitions, and metadata from request bodies
    for guard inspection.
    """

    def parse(self, body: dict[str, Any]) -> ParsedRequest:
        """Parse a chat completion request body."""
        messages: list[ParsedMessage] = []
        for msg in body.get("messages", []):
            role = msg.get("role", "")
            content = msg.get("content", "")
            if isinstance(content, list):
                # Multi-part content: extract text parts
                text_parts = []
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        text_parts.append(part.get("text", ""))
                content = "\n".join(text_parts)

            # Parse tool calls in assistant messages
            tool_calls: list[ParsedToolCall] = []
            for tc in msg.get("tool_calls", []):
                func = tc.get("function", {})
                args: dict[str, Any] = {}
                if isinstance(func.get("arguments"), str):
                    import json

                    try:
                        args = json.loads(func["arguments"])
                    except (json.JSONDecodeError, TypeError):
                        args = {}
                elif isinstance(func.get("arguments"), dict):
                    args = func["arguments"]

                tool_calls.append(
                    ParsedToolCall(
                        tool_name=func.get("name", ""),
                        tool_args=args,
                        call_id=tc.get("id", ""),
                    )
                )

            boundary = _infer_trust_boundary(role, msg)

            messages.append(
                ParsedMessage(
                    role=role,
                    content=content or "",
                    tool_calls=tool_calls,
                    tool_call_id=msg.get("tool_call_id", ""),
                    trust_boundary=boundary,
                )
            )

        # Parse tool definitions
        tools: list[ParsedToolDef] = []
        for tool in body.get("tools", []):
            func = tool.get("function", {})
            tools.append(
                ParsedToolDef(
                    name=func.get("name", ""),
                    description=func.get("description", ""),
                    parameters=func.get("parameters", {}),
                )
            )

        return ParsedRequest(
            model=body.get("model", ""),
            messages=messages,
            tools=tools,
            stream=body.get("stream", False),
            raw_body=body,
        )

    def parse_anthropic(self, body: dict[str, Any]) -> ParsedRequest:
        """Parse an Anthropic /v1/messages request body."""
        messages: list[ParsedMessage] = []

        system_text = _extract_content_text(body.get("system"))
        if system_text:
            messages.append(
                ParsedMessage(
                    role="system",
                    content=system_text,
                    trust_boundary="context_file",
                )
            )

        for msg in body.get("messages", []):
            if not isinstance(msg, dict):
                continue
            role = msg.get("role", "")
            content = msg.get("content", "")
            tool_calls: list[ParsedToolCall] = []

            if isinstance(content, list):
                text_parts: list[str] = []
                for part in content:
                    if not isinstance(part, dict):
                        continue
                    part_type = part.get("type")
                    if part_type == "text":
                        text = part.get("text", "")
                        if isinstance(text, str) and text:
                            text_parts.append(text)
                    elif part_type == "tool_result":
                        result_text = _extract_content_text(part.get("content"))
                        if result_text:
                            messages.append(
                                ParsedMessage(
                                    role="tool",
                                    content=result_text,
                                    tool_call_id=str(part.get("tool_use_id") or ""),
                                    trust_boundary="tool_result",
                                )
                            )
                    elif part_type == "tool_use":
                        tool_calls.append(
                            ParsedToolCall(
                                tool_name=str(part.get("name") or ""),
                                tool_args=part.get("input") if isinstance(part.get("input"), dict) else {},
                                call_id=str(part.get("id") or ""),
                            )
                        )

                content_text = "\n".join(text_parts)
            else:
                content_text = _extract_content_text(content)

            if content_text or tool_calls:
                messages.append(
                    ParsedMessage(
                        role=role,
                        content=content_text,
                        tool_calls=tool_calls,
                        trust_boundary=_infer_trust_boundary(role, msg),
                    )
                )

        tools: list[ParsedToolDef] = []
        for tool in body.get("tools", []):
            if not isinstance(tool, dict):
                continue
            tools.append(
                ParsedToolDef(
                    name=str(tool.get("name") or ""),
                    description=str(tool.get("description") or ""),
                    parameters=tool.get("input_schema") if isinstance(tool.get("input_schema"), dict) else {},
                )
            )

        return ParsedRequest(
            model=body.get("model", ""),
            messages=messages,
            tools=tools,
            stream=body.get("stream", False),
            raw_body=body,
        )


# ---------------------------------------------------------------------------
# ResponseParser
# ---------------------------------------------------------------------------


class ResponseParser:
    """Parse OpenAI-compatible chat completion and Anthropic Messages responses.

    Extracts tool calls, reasoning/thinking content, and text from
    response bodies for guard inspection.
    """

    def parse(self, body: dict[str, Any]) -> ParsedResponse:
        """Parse a chat completion response body."""
        content_parts: list[str] = []
        tool_calls: list[ParsedToolCall] = []
        reasoning = ""
        finish_reason = ""
        model = body.get("model", "")

        choices = body.get("choices", [])
        if choices:
            choice = choices[0]
            finish_reason = choice.get("finish_reason", "")
            message = choice.get("message", {})

            # Extract text content
            msg_content = message.get("content", "")
            if isinstance(msg_content, str):
                content_parts.append(msg_content)
            elif isinstance(msg_content, list):
                for part in msg_content:
                    if isinstance(part, dict):
                        if part.get("type") == "text":
                            content_parts.append(part.get("text", ""))
                        elif part.get("type") == "thinking":
                            reasoning += part.get("thinking", "")

            # Extract reasoning/thinking content (Anthropic-style)
            if message.get("thinking"):
                reasoning += message.get("thinking", "")

            # Extract tool calls
            for tc in message.get("tool_calls", []):
                func = tc.get("function", {})
                args: dict[str, Any] = {}
                if isinstance(func.get("arguments"), str):
                    import json

                    try:
                        args = json.loads(func["arguments"])
                    except (json.JSONDecodeError, TypeError):
                        args = {}
                elif isinstance(func.get("arguments"), dict):
                    args = func["arguments"]

                tool_calls.append(
                    ParsedToolCall(
                        tool_name=func.get("name", ""),
                        tool_args=args,
                        call_id=tc.get("id", ""),
                    )
                )

        return ParsedResponse(
            content="\n".join(content_parts),
            tool_calls=tool_calls,
            reasoning=reasoning,
            finish_reason=finish_reason,
            model=model,
            raw_body=body,
        )

    def parse_anthropic(self, body: dict[str, Any]) -> ParsedResponse:
        """Parse an Anthropic /v1/messages response body."""
        content_parts: list[str] = []
        tool_calls: list[ParsedToolCall] = []
        reasoning_parts: list[str] = []

        for block in body.get("content", []):
            if not isinstance(block, dict):
                continue
            block_type = block.get("type")
            if block_type == "text":
                text = block.get("text", "")
                if isinstance(text, str) and text:
                    content_parts.append(text)
            elif block_type == "tool_use":
                tool_calls.append(
                    ParsedToolCall(
                        tool_name=str(block.get("name") or ""),
                        tool_args=block.get("input") if isinstance(block.get("input"), dict) else {},
                        call_id=str(block.get("id") or ""),
                    )
                )
            elif block_type == "thinking":
                thinking = block.get("thinking", "")
                if isinstance(thinking, str) and thinking:
                    reasoning_parts.append(thinking)

        return ParsedResponse(
            content="\n".join(content_parts),
            tool_calls=tool_calls,
            reasoning="\n".join(reasoning_parts),
            finish_reason=str(body.get("stop_reason") or ""),
            model=str(body.get("model") or ""),
            raw_body=body,
        )

    def parse_stream_chunk(self, chunk: dict[str, Any]) -> ParsedResponse:
        """Parse a single SSE streaming chunk.

        Returns a partial ParsedResponse with whatever content is available
        in this chunk. Tool calls are accumulated incrementally.
        """
        content_parts: list[str] = []
        tool_calls: list[ParsedToolCall] = []
        reasoning = ""
        finish_reason = ""

        choices = chunk.get("choices", [])
        if choices:
            delta = choices[0].get("delta", {})
            finish_reason = choices[0].get("finish_reason", "") or ""

            # Text content
            if isinstance(delta.get("content"), str):
                content_parts.append(delta["content"])

            # Reasoning/thinking
            if delta.get("reasoning_content"):
                reasoning = delta["reasoning_content"]
            if delta.get("thinking"):
                reasoning = delta["thinking"]

            # Tool calls (incremental)
            for tc in delta.get("tool_calls", []):
                func = tc.get("function", {})
                args: dict[str, Any] = {}
                if isinstance(func.get("arguments"), str):
                    import json

                    try:
                        args = json.loads(func["arguments"])
                    except (json.JSONDecodeError, TypeError):
                        # Partial JSON in streaming — treat as raw string
                        args = {"_raw_arguments": func["arguments"]}

                tool_calls.append(
                    ParsedToolCall(
                        tool_name=func.get("name", ""),
                        tool_args=args,
                        call_id=tc.get("id", ""),
                    )
                )

        return ParsedResponse(
            content="\n".join(content_parts),
            tool_calls=tool_calls,
            reasoning=reasoning,
            finish_reason=finish_reason,
            model=chunk.get("model", ""),
            raw_body=chunk,
        )
