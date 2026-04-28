"""ModelRouter — pluggable model routing for SLM, LLM, and embedding.

Uses httpx for HTTP communication with OpenAI-compatible API endpoints.
When models are not configured (empty base_url/model), falls back to
stub behavior (raises ModelUnavailableError).
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field

from qise.core.models import ModelUnavailableError

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class ModelConfig(BaseModel):
    """Configuration for a single model endpoint."""

    base_url: str = "http://localhost:8822/v1"
    model: str = ""
    timeout_ms: int = 200
    api_key: str | None = None


class ModelResponse(BaseModel):
    """Structured response from a model call."""

    text: str = ""
    parsed: dict[str, Any] | None = Field(
        default=None,
        description="JSON-parsed response if available",
    )
    model: str = ""
    latency_ms: int = 0
    finish_reason: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_JSON_BLOCK_RE = re.compile(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", re.DOTALL)


def _parse_json_response(text: str) -> dict[str, Any]:
    """Try to parse JSON from model response text.

    1. Direct json.loads
    2. Extract first JSON object with regex
    3. Fallback: low-confidence default dict
    """
    # Try direct parse
    try:
        result = json.loads(text)
        if isinstance(result, dict):
            return result
    except (json.JSONDecodeError, TypeError):
        pass

    # Try extracting JSON object from text
    match = _JSON_BLOCK_RE.search(text)
    if match:
        try:
            result = json.loads(match.group())
            if isinstance(result, dict):
                return result
        except (json.JSONDecodeError, TypeError):
            pass

    # Fallback: unparseable response
    return {
        "verdict": "suspicious",
        "confidence": 0.3,
        "reasoning": "Failed to parse model response",
    }


def _build_headers(api_key: str | None) -> dict[str, str]:
    """Build HTTP headers for OpenAI-compatible API."""
    headers: dict[str, str] = {
        "Content-Type": "application/json",
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def _build_chat_payload(
    model: str,
    prompt: str,
    temperature: float = 0.1,
    max_tokens: int = 512,
) -> dict[str, Any]:
    """Build OpenAI Chat Completions request payload."""
    payload: dict[str, Any] = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    return payload


# ---------------------------------------------------------------------------
# ModelRouter
# ---------------------------------------------------------------------------


class ModelRouter:
    """Pluggable model router managing SLM, LLM, and embedding clients.

    Uses httpx for HTTP communication with OpenAI-compatible endpoints.
    When base_url or model is empty, acts as stub (raises ModelUnavailableError).
    """

    def __init__(
        self,
        slm_config: ModelConfig | None = None,
        llm_config: ModelConfig | None = None,
        embedding_config: ModelConfig | None = None,
    ) -> None:
        self.slm_config = slm_config or ModelConfig()
        self.llm_config = llm_config or ModelConfig()
        self.embedding_config = embedding_config or ModelConfig()

    # ------------------------------------------------------------------
    # Availability check
    # ------------------------------------------------------------------

    def is_available(self, model_type: Literal["slm", "llm", "embedding"]) -> bool:
        """Check if a model type is configured and potentially reachable.

        Returns True if base_url and model are both non-empty.
        Does not verify actual reachability (that requires a network call).
        """
        config = self._get_config(model_type)
        return bool(config.base_url and config.model)

    def _get_config(self, model_type: Literal["slm", "llm", "embedding"]) -> ModelConfig:
        """Get config by model type."""
        if model_type == "slm":
            return self.slm_config
        elif model_type == "llm":
            return self.llm_config
        else:
            return self.embedding_config

    def _require_config(self, model_type: Literal["slm", "llm", "embedding"]) -> ModelConfig:
        """Get config or raise ModelUnavailableError if not configured."""
        config = self._get_config(model_type)
        if not config.base_url or not config.model:
            raise ModelUnavailableError(
                f"{model_type.upper()} not configured. "
                f"Set base_url and model to enable {model_type} checks. "
                f"Falling back to rule-based checks."
            )
        return config

    # ------------------------------------------------------------------
    # SLM methods
    # ------------------------------------------------------------------

    def slm_check_sync(self, prompt: str) -> dict[str, Any]:
        """SLM fast-screen: classify risk from a single content item.

        Args:
            prompt: Rendered SLM prompt template with context variables.

        Returns:
            Dict with keys: verdict, confidence, risk_source, reasoning.

        Raises:
            ModelUnavailableError: If SLM is not configured or unreachable.
        """
        config = self._require_config("slm")
        headers = _build_headers(config.api_key)
        payload = _build_chat_payload(config.model, prompt)

        start = time.monotonic()
        try:
            resp = httpx.post(
                f"{config.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=config.timeout_ms / 1000.0,
            )
            resp.raise_for_status()
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            raise ModelUnavailableError(
                f"SLM connection failed: {exc}. Falling back to rules."
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise ModelUnavailableError(
                f"SLM returned HTTP {exc.response.status_code}. Falling back to rules."
            ) from exc

        latency_ms = int((time.monotonic() - start) * 1000)
        data = resp.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        parsed = _parse_json_response(content)
        parsed["_latency_ms"] = latency_ms
        parsed["_model"] = config.model
        return parsed

    async def slm_check(self, prompt: str) -> ModelResponse:
        """Async version of SLM fast-screen."""
        config = self._require_config("slm")
        headers = _build_headers(config.api_key)
        payload = _build_chat_payload(config.model, prompt)

        start = time.monotonic()
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.post(
                    f"{config.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=config.timeout_ms / 1000.0,
                )
                resp.raise_for_status()
            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                raise ModelUnavailableError(
                    f"SLM connection failed: {exc}. Falling back to rules."
                ) from exc
            except httpx.HTTPStatusError as exc:
                raise ModelUnavailableError(
                    f"SLM returned HTTP {exc.response.status_code}. Falling back to rules."
                ) from exc

        latency_ms = int((time.monotonic() - start) * 1000)
        data = resp.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        finish_reason = data.get("choices", [{}])[0].get("finish_reason")

        return ModelResponse(
            text=content,
            parsed=_parse_json_response(content),
            model=config.model,
            latency_ms=latency_ms,
            finish_reason=finish_reason,
        )

    # ------------------------------------------------------------------
    # LLM methods
    # ------------------------------------------------------------------

    def llm_deep_analysis_sync(
        self, prompt: str, trajectory: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """LLM deep analysis: full trajectory context risk reasoning.

        Args:
            prompt: Rendered LLM prompt template.
            trajectory: Full conversation history for multi-turn analysis.

        Returns:
            Dict with keys: verdict, confidence, risk_attribution: {...}.

        Raises:
            ModelUnavailableError: If LLM is not configured or unreachable.
        """
        config = self._require_config("llm")
        headers = _build_headers(config.api_key)

        # Build messages with trajectory context
        messages: list[dict[str, str]] = []
        if trajectory:
            # Inject trajectory as system context
            traj_text = json.dumps(trajectory, default=str)
            messages.append({
                "role": "system",
                "content": f"Session trajectory context:\n{traj_text}",
            })
        messages.append({"role": "user", "content": prompt})

        payload: dict[str, Any] = {
            "model": config.model,
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": 1024,
        }

        start = time.monotonic()
        try:
            resp = httpx.post(
                f"{config.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=config.timeout_ms / 1000.0,
            )
            resp.raise_for_status()
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            raise ModelUnavailableError(
                f"LLM connection failed: {exc}. Falling back to rules."
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise ModelUnavailableError(
                f"LLM returned HTTP {exc.response.status_code}. Falling back to rules."
            ) from exc

        latency_ms = int((time.monotonic() - start) * 1000)
        data = resp.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        parsed = _parse_json_response(content)
        parsed["_latency_ms"] = latency_ms
        parsed["_model"] = config.model
        return parsed

    async def llm_deep_analysis(
        self, prompt: str, trajectory: list[dict[str, Any]]
    ) -> ModelResponse:
        """Async version of LLM deep analysis."""
        config = self._require_config("llm")
        headers = _build_headers(config.api_key)

        messages: list[dict[str, str]] = []
        if trajectory:
            traj_text = json.dumps(trajectory, default=str)
            messages.append({
                "role": "system",
                "content": f"Session trajectory context:\n{traj_text}",
            })
        messages.append({"role": "user", "content": prompt})

        payload: dict[str, Any] = {
            "model": config.model,
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": 1024,
        }

        start = time.monotonic()
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.post(
                    f"{config.base_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=config.timeout_ms / 1000.0,
                )
                resp.raise_for_status()
            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                raise ModelUnavailableError(
                    f"LLM connection failed: {exc}. Falling back to rules."
                ) from exc
            except httpx.HTTPStatusError as exc:
                raise ModelUnavailableError(
                    f"LLM returned HTTP {exc.response.status_code}. Falling back to rules."
                ) from exc

        latency_ms = int((time.monotonic() - start) * 1000)
        data = resp.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        finish_reason = data.get("choices", [{}])[0].get("finish_reason")

        return ModelResponse(
            text=content,
            parsed=_parse_json_response(content),
            model=config.model,
            latency_ms=latency_ms,
            finish_reason=finish_reason,
        )

    # ------------------------------------------------------------------
    # Embedding methods
    # ------------------------------------------------------------------

    async def similar_attacks(
        self, embedding: list[float], top_k: int = 5
    ) -> list[dict[str, Any]]:
        """Retrieve similar attack patterns from the threat pattern library.

        Args:
            embedding: Vector embedding of the content to search.
            top_k: Number of similar patterns to return.

        Raises:
            ModelUnavailableError: If embedding model is not configured.
        """
        config = self._require_config("embedding")
        raise ModelUnavailableError(
            "Embedding-based similar-attack retrieval not yet implemented. "
            "Configure an embedding endpoint for future support."
        )
