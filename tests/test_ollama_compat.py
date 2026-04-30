"""Tests for Ollama compatibility — ModelRouter + response parsing.

Validates that _extract_content_from_response and _parse_json_response
work correctly with Ollama's /v1/chat/completions response format,
including Qwen3 thinking mode (reasoning_content).
"""
from __future__ import annotations

import pytest

from qise.models.router import (
    ModelConfig,
    ModelRouter,
    _extract_content_from_response,
    _parse_json_response,
)


# ---------------------------------------------------------------------------
# Ollama response fixtures
# ---------------------------------------------------------------------------


def ollama_standard_response(content: str, model: str = "qwen3:4b") -> dict:
    """Simulate a standard Ollama /v1/chat/completions response."""
    return {
        "id": "chatcmpl-123",
        "object": "chat.completion",
        "created": 1234567890,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": content,
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    }


def ollama_thinking_response(
    reasoning: str, content: str, model: str = "qwen3:4b"
) -> dict:
    """Simulate Ollama response with Qwen3 thinking mode.

    Qwen3 in Ollama returns reasoning_content + content when thinking is enabled.
    """
    return {
        "id": "chatcmpl-456",
        "object": "chat.completion",
        "created": 1234567890,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "reasoning_content": reasoning,
                    "content": content,
                },
                "finish_reason": "stop",
            }
        ],
    }


def ollama_thinking_only_response(reasoning: str, model: str = "qwen3:4b") -> dict:
    """Simulate Ollama response where thinking used all tokens (content is empty)."""
    return {
        "id": "chatcmpl-789",
        "object": "chat.completion",
        "created": 1234567890,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "reasoning_content": reasoning,
                    "content": "",
                },
                "finish_reason": "length",
            }
        ],
    }


# ---------------------------------------------------------------------------
# Test _extract_content_from_response
# ---------------------------------------------------------------------------


class TestExtractContent:
    """Test _extract_content_from_response with Ollama formats."""

    def test_standard_response(self) -> None:
        """Standard Ollama response with content."""
        data = ollama_standard_response('{"verdict": "safe", "confidence": 0.9}')
        result = _extract_content_from_response(data)
        assert result == '{"verdict": "safe", "confidence": 0.9}'

    def test_thinking_mode_with_content(self) -> None:
        """Qwen3 thinking mode: has both reasoning_content and content."""
        data = ollama_thinking_response(
            reasoning="Let me analyze this step by step...",
            content='{"verdict": "suspicious", "confidence": 0.7}',
        )
        result = _extract_content_from_response(data)
        # Should return content, not reasoning
        assert result == '{"verdict": "suspicious", "confidence": 0.7}'

    def test_thinking_mode_content_only_whitespace(self) -> None:
        """Qwen3 thinking mode: content is whitespace, reasoning has answer."""
        data = ollama_thinking_response(
            reasoning="Analyzing... Final Answer: {\"verdict\": \"safe\", \"confidence\": 0.85}",
            content="   ",
        )
        result = _extract_content_from_response(data)
        # Whitespace-only content → fallback to reasoning extraction
        assert "verdict" in result
        assert "safe" in result

    def test_thinking_mode_empty_content(self) -> None:
        """Qwen3 thinking mode: content is empty string (tokens exhausted)."""
        reasoning = (
            "I need to check if this is dangerous. "
            "The command looks safe. "
            "Final Output: {\"verdict\": \"pass\", \"confidence\": 0.92}"
        )
        data = ollama_thinking_only_response(reasoning=reasoning)
        result = _extract_content_from_response(data)
        # Should extract from reasoning
        assert "verdict" in result
        assert "pass" in result

    def test_thinking_mode_json_in_reasoning(self) -> None:
        """Qwen3 thinking mode: JSON verdict embedded in reasoning."""
        reasoning = (
            "Step 1: Analyze the tool call. "
            "Step 2: This looks like a safe operation. "
            "My verdict is {\"verdict\": \"pass\", \"confidence\": 0.88, "
            "\"reasoning\": \"Standard file read operation\"}."
        )
        data = ollama_thinking_only_response(reasoning=reasoning)
        result = _extract_content_from_response(data)
        assert "verdict" in result

    def test_empty_response(self) -> None:
        """Completely empty response."""
        data = {
            "choices": [{"message": {"role": "assistant", "content": ""}}],
        }
        result = _extract_content_from_response(data)
        assert result == ""

    def test_ollama_no_usage_field(self) -> None:
        """Ollama may not return usage field — should not crash."""
        data = {
            "id": "chatcmpl-1",
            "model": "qwen3:4b",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": '{"verdict": "safe"}',
                    },
                    "finish_reason": "stop",
                }
            ],
        }
        result = _extract_content_from_response(data)
        assert "safe" in result


# ---------------------------------------------------------------------------
# Test _parse_json_response
# ---------------------------------------------------------------------------


class TestParseJsonResponse:
    """Test _parse_json_response with typical Guard output."""

    def test_clean_json(self) -> None:
        """Clean JSON response from SLM."""
        text = '{"verdict": "suspicious", "confidence": 0.75, "risk_source": "indirect_injection"}'
        result = _parse_json_response(text)
        assert result["verdict"] == "suspicious"
        assert result["confidence"] == 0.75

    def test_json_in_text(self) -> None:
        """JSON embedded in explanatory text."""
        text = 'Based on my analysis, here is the result: {"verdict": "safe", "confidence": 0.9}'
        result = _parse_json_response(text)
        assert result["verdict"] == "safe"

    def test_invalid_json_fallback(self) -> None:
        """Non-JSON text falls back to low-confidence default."""
        text = "This content appears to be safe."
        result = _parse_json_response(text)
        assert result["verdict"] == "suspicious"
        assert result["confidence"] == 0.3

    def test_qwen3_thinking_output(self) -> None:
        """Qwen3 thinking mode output with Final Answer marker."""
        text = 'Final Answer: {"verdict": "pass", "confidence": 0.85}'
        result = _parse_json_response(text)
        assert result["verdict"] == "pass"
        assert result["confidence"] == 0.85


# ---------------------------------------------------------------------------
# Test ModelRouter with Ollama config
# ---------------------------------------------------------------------------


class TestModelRouterOllamaConfig:
    """Test ModelRouter configured for Ollama endpoint."""

    def test_ollama_config_available(self) -> None:
        """Ollama endpoint is detected as available when configured."""
        router = ModelRouter(
            slm_config=ModelConfig(
                base_url="http://localhost:11434/v1",
                model="qwen3:4b",
                timeout_ms=5000,
            )
        )
        assert router.is_available("slm") is True

    def test_ollama_default_port(self) -> None:
        """Default Ollama port is 11434."""
        config = ModelConfig(
            base_url="http://localhost:11434/v1",
            model="qwen3:4b",
            timeout_ms=5000,
        )
        assert "11434" in config.base_url

    def test_ollama_timeout_5s(self) -> None:
        """Local SLM should have 5s timeout (vs 200ms default for cloud)."""
        config = ModelConfig(
            base_url="http://localhost:11434/v1",
            model="qwen3:4b",
            timeout_ms=5000,
        )
        assert config.timeout_ms == 5000

    def test_no_api_key_needed(self) -> None:
        """Ollama does not require an API key."""
        config = ModelConfig(
            base_url="http://localhost:11434/v1",
            model="qwen3:4b",
            timeout_ms=5000,
        )
        assert config.api_key is None

    def test_unavailable_when_not_configured(self) -> None:
        """SLM is unavailable when base_url/model are empty."""
        router = ModelRouter()
        # Default ModelConfig has model="" which means unavailable
        assert router.is_available("slm") is False


# ---------------------------------------------------------------------------
# Test ShieldConfig with Ollama
# ---------------------------------------------------------------------------


class TestShieldConfigOllama:
    """Test ShieldConfig supports Ollama endpoint configuration."""

    def test_ollama_config_from_dict(self) -> None:
        """ShieldConfig can be created with Ollama SLM config."""
        from qise.core.config import ShieldConfig

        config = ShieldConfig.from_dict({
            "models": {
                "slm": {
                    "base_url": "http://localhost:11434/v1",
                    "model": "qwen3:4b",
                    "timeout_ms": 5000,
                }
            }
        })
        assert config.models.slm.base_url == "http://localhost:11434/v1"
        assert config.models.slm.model == "qwen3:4b"
        assert config.models.slm.timeout_ms == 5000

    def test_ollama_env_override(self) -> None:
        """QISE_SLM_BASE_URL env var overrides config."""
        import os
        from qise.core.config import ShieldConfig

        os.environ["QISE_SLM_BASE_URL"] = "http://localhost:11434/v1"
        os.environ["QISE_SLM_MODEL"] = "qwen3:4b"
        try:
            config = ShieldConfig.default()
            assert config.models.slm.base_url == "http://localhost:11434/v1"
            assert config.models.slm.model == "qwen3:4b"
        finally:
            del os.environ["QISE_SLM_BASE_URL"]
            del os.environ["QISE_SLM_MODEL"]
