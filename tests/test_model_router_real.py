"""Tests for ModelRouter real implementation."""

import json
from unittest.mock import patch, MagicMock

import pytest

from qise.core.models import ModelUnavailableError
from qise.models.router import ModelRouter, ModelConfig, _parse_json_response


class TestParseJsonResponse:

    def test_parses_valid_json(self) -> None:
        text = '{"verdict": "safe", "confidence": 0.9}'
        result = _parse_json_response(text)
        assert result["verdict"] == "safe"
        assert result["confidence"] == 0.9

    def test_extracts_json_from_text(self) -> None:
        text = 'The analysis shows {"verdict": "suspicious", "confidence": 0.6} which indicates risk'
        result = _parse_json_response(text)
        assert result["verdict"] == "suspicious"

    def test_fallback_on_unparseable(self) -> None:
        text = "No JSON here at all"
        result = _parse_json_response(text)
        assert result["verdict"] == "suspicious"
        assert result["confidence"] == 0.3

    def test_handles_nested_json(self) -> None:
        text = '{"verdict": "malicious", "risk_attribution": {"risk_source": "injection"}}'
        result = _parse_json_response(text)
        assert result["verdict"] == "malicious"
        assert "risk_attribution" in result


class TestModelRouterIsAvailable:

    def test_not_available_with_empty_model(self) -> None:
        router = ModelRouter(slm_config=ModelConfig(base_url="http://localhost:8822/v1", model=""))
        assert router.is_available("slm") is False

    def test_not_available_with_empty_base_url(self) -> None:
        router = ModelRouter(slm_config=ModelConfig(base_url="", model="test-model"))
        assert router.is_available("slm") is False

    def test_available_when_configured(self) -> None:
        router = ModelRouter(slm_config=ModelConfig(base_url="http://localhost:8822/v1", model="test-model"))
        assert router.is_available("slm") is True

    def test_default_config_not_available(self) -> None:
        router = ModelRouter()
        assert router.is_available("slm") is False
        assert router.is_available("llm") is False
        assert router.is_available("embedding") is False


class TestModelRouterSlmCheckSync:

    def test_raises_when_not_configured(self) -> None:
        router = ModelRouter()
        with pytest.raises(ModelUnavailableError):
            router.slm_check_sync("test prompt")

    @patch("qise.models.router.httpx.post")
    def test_returns_parsed_json_on_success(self, mock_post: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": '{"verdict": "safe", "confidence": 0.9}'}}]
        }
        mock_post.return_value = mock_resp

        router = ModelRouter(slm_config=ModelConfig(
            base_url="http://localhost:8822/v1",
            model="test-slm",
            api_key="test-key",
        ))
        result = router.slm_check_sync("test prompt")
        assert result["verdict"] == "safe"
        assert result["confidence"] == 0.9

        # Verify request was correct
        call_args = mock_post.call_args
        assert "chat/completions" in call_args[0][0]
        assert call_args[1]["headers"]["Authorization"] == "Bearer test-key"
        payload = call_args[1]["json"]
        assert payload["model"] == "test-slm"
        assert payload["temperature"] == 0.1

    @patch("qise.models.router.httpx.post")
    def test_raises_on_connection_error(self, mock_post: MagicMock) -> None:
        import httpx
        mock_post.side_effect = httpx.ConnectError("Connection refused")

        router = ModelRouter(slm_config=ModelConfig(
            base_url="http://localhost:8822/v1",
            model="test-slm",
        ))
        with pytest.raises(ModelUnavailableError, match="connection failed"):
            router.slm_check_sync("test prompt")

    @patch("qise.models.router.httpx.post")
    def test_raises_on_timeout(self, mock_post: MagicMock) -> None:
        import httpx
        mock_post.side_effect = httpx.TimeoutException("Timeout")

        router = ModelRouter(slm_config=ModelConfig(
            base_url="http://localhost:8822/v1",
            model="test-slm",
        ))
        with pytest.raises(ModelUnavailableError, match="connection failed"):
            router.slm_check_sync("test prompt")

    @patch("qise.models.router.httpx.post")
    def test_raises_on_http_error(self, mock_post: MagicMock) -> None:
        import httpx
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "500", request=MagicMock(), response=mock_resp
        )
        mock_post.return_value = mock_resp

        router = ModelRouter(slm_config=ModelConfig(
            base_url="http://localhost:8822/v1",
            model="test-slm",
        ))
        with pytest.raises(ModelUnavailableError, match="HTTP 500"):
            router.slm_check_sync("test prompt")

    @patch("qise.models.router.httpx.post")
    def test_handles_non_json_response(self, mock_post: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "The content appears safe"}}]
        }
        mock_post.return_value = mock_resp

        router = ModelRouter(slm_config=ModelConfig(
            base_url="http://localhost:8822/v1",
            model="test-slm",
        ))
        result = router.slm_check_sync("test prompt")
        assert result["verdict"] == "suspicious"
        assert result["confidence"] == 0.3


class TestModelRouterLlmDeepAnalysisSync:

    def test_raises_when_not_configured(self) -> None:
        router = ModelRouter()
        with pytest.raises(ModelUnavailableError):
            router.llm_deep_analysis_sync("test", [])

    @patch("qise.models.router.httpx.post")
    def test_includes_trajectory_in_messages(self, mock_post: MagicMock) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": '{"verdict": "safe", "confidence": 0.9}'}}]
        }
        mock_post.return_value = mock_resp

        router = ModelRouter(llm_config=ModelConfig(
            base_url="http://localhost:8822/v1",
            model="test-llm",
            timeout_ms=5000,
        ))
        result = router.llm_deep_analysis_sync("test", [{"role": "user", "content": "hello"}])
        assert result["verdict"] == "safe"

        # Verify trajectory was included in messages
        payload = mock_post.call_args[1]["json"]
        messages = payload["messages"]
        assert len(messages) == 2  # system (trajectory) + user (prompt)
        assert "trajectory" in messages[0]["content"].lower()
