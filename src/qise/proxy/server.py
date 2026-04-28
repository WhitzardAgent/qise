"""ProxyServer — aiohttp-based HTTP reverse proxy for Qise.

Intercepts Agent↔LLM traffic, runs guard checks, injects security context,
and forwards requests to the upstream LLM API.

Core flow:
  1. Parse request body
  2. Request interception (ingress checks)
  3. Inject SecurityContext (if enabled)
  4. Forward to upstream
  5. Receive response
  6. Response interception (egress/output checks)
  7. Return response to agent (or block)
"""

from __future__ import annotations

import json
import logging
from typing import Any

import aiohttp
from aiohttp import web

from qise.proxy.config import ProxyConfig
from qise.proxy.context_injector import ContextInjector
from qise.proxy.interceptor import ProxyDecision, ProxyInterceptor
from qise.proxy.parser import RequestParser, ResponseParser
from qise.proxy.streaming import SSEStreamHandler

logger = logging.getLogger("qise.proxy")


class ProxyServer:
    """aiohttp-based HTTP reverse proxy for AI agent security.

    Usage:
        from qise.core.shield import Shield
        from qise.proxy.server import ProxyServer

        shield = Shield.from_config()
        server = ProxyServer(shield)
        await server.start()
        # ... proxy is running on port 8822 ...
        await server.stop()
    """

    def __init__(
        self,
        shield: Any,
        config: ProxyConfig | None = None,
    ) -> None:
        """Initialize the proxy server.

        Args:
            shield: A Shield instance with configured pipeline.
            config: ProxyConfig for the server. If None, created from shield config.
        """
        self._shield = shield
        self._config = config or ProxyConfig.from_shield_config(shield.config)

        # Build components
        self._request_parser = RequestParser()
        self._response_parser = ResponseParser()
        self._context_injector = ContextInjector(shield.context_provider)
        self._interceptor = ProxyInterceptor(shield, self._config)

        # aiohttp app and runner
        self._app: web.Application | None = None
        self._runner: web.AppRunner | None = None
        self._session: aiohttp.ClientSession | None = None

    @property
    def config(self) -> ProxyConfig:
        return self._config

    async def start(self) -> None:
        """Start the proxy server."""
        self._app = web.Application(client_max_size=int(self._config.max_request_body_mb * 1024 * 1024))
        self._app.router.add_route("*", "/{path:.*}", self._handle_request)

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()

        site = web.TCPSite(
            self._runner,
            self._config.listen_host,
            self._config.listen_port,
        )
        await site.start()
        logger.info(
            "Qise proxy listening on %s:%d → %s",
            self._config.listen_host,
            self._config.listen_port,
            self._config.upstream_base_url or "(no upstream configured)",
        )

    async def stop(self) -> None:
        """Stop the proxy server and clean up resources."""
        if self._session:
            await self._session.close()
            self._session = None
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
        logger.info("Qise proxy stopped")

    async def _handle_request(self, request: web.Request) -> web.Response:
        """Main request handler — all paths pass through here.

        For intercept_paths (e.g., /v1/chat/completions), run guard checks.
        For all other paths, forward transparently.
        """
        path = "/" + request.match_info.get("path", "")
        path_without_query = path.split("?")[0]

        # Check if this path should be intercepted
        should_intercept = any(
            path_without_query == ip or path_without_query.startswith(ip + "/")
            for ip in self._config.intercept_paths
        )

        # Check if this path should passthrough without interception
        is_passthrough = any(
            path_without_query == pp
            for pp in self._config.passthrough_paths
        )

        if is_passthrough or not should_intercept:
            return await self._forward_request(request)

        # Intercept chat completion requests
        if path_without_query == "/v1/chat/completions" and request.method == "POST":
            return await self._handle_chat_completions(request)

        # Other paths on intercepted routes: just forward
        return await self._forward_request(request)

    async def _handle_chat_completions(self, request: web.Request) -> web.Response:
        """Handle /v1/chat/completions with full interception pipeline.

        Supports both streaming and non-streaming requests.
        """
        try:
            body = await request.json()
        except (json.JSONDecodeError, Exception) as e:
            return web.json_response(
                {"error": f"Invalid JSON in request body: {e}"},
                status=400,
            )

        # Step 1: Parse request
        parsed_request = self._request_parser.parse(body)

        # Step 2: Request interception
        request_decision = self._interceptor.intercept_request(parsed_request, body)

        if request_decision.action == "block" and self._config.block_on_guard_block:
            logger.warning("Request BLOCKED: %s", request_decision.block_reason)
            return self._block_response(request_decision)

        # Step 3: Inject security context
        forward_body = request_decision.modified_body
        if self._config.inject_security_context:
            forward_body = self._context_injector.inject(forward_body)

        # Step 4: Check if streaming
        is_stream = parsed_request.stream

        # Step 5: Forward to upstream
        if is_stream:
            return await self._handle_streaming(request, forward_body)

        # Non-streaming path
        upstream_response = await self._forward_to_upstream(request, forward_body)
        if upstream_response.status != 200:
            return upstream_response

        # Step 6: Parse response
        try:
            response_body = await upstream_response.json()
        except Exception:
            return upstream_response

        # Step 7: Response interception
        parsed_response = self._response_parser.parse(response_body)
        response_decision = self._interceptor.intercept_response(parsed_response, response_body)

        # Step 8: Return response
        if response_decision.action == "block" and self._config.block_on_guard_block:
            logger.warning("Response BLOCKED: %s", response_decision.block_reason)
            return self._block_response(response_decision)

        if response_decision.action == "warn":
            headers = {"X-Qise-Warnings": "; ".join(response_decision.warnings[:5])}
            return web.json_response(response_body, headers=headers)

        return web.json_response(response_body)

    async def _handle_streaming(
        self,
        request: web.Request,
        forward_body: dict[str, Any],
    ) -> web.StreamResponse:
        """Handle streaming (SSE) chat completion requests.

        Uses SSEStreamHandler to process chunks with guard interception.
        """
        path = "/" + request.match_info.get("path", "")
        upstream_url = self._config.upstream_base_url.rstrip("/") + path

        # Build headers
        headers = {}
        for key, value in request.headers.items():
            key_lower = key.lower()
            if key_lower in ("host", "content-length", "transfer-encoding", "accept"):
                continue
            if key_lower == "authorization" and self._config.upstream_api_key:
                continue
            headers[key] = value

        if self._config.upstream_api_key:
            headers["Authorization"] = f"Bearer {self._config.upstream_api_key}"

        session = await self._get_session()

        # Open streaming connection to upstream
        try:
            upstream_resp = await session.request(
                method="POST",
                url=upstream_url,
                headers=headers,
                json=forward_body,
                timeout=aiohttp.ClientTimeout(total=self._config.request_timeout_s),
            )
        except aiohttp.ClientError as e:
            logger.error("Upstream streaming request failed: %s", e)
            resp = web.json_response(
                {"error": f"Upstream request failed: {e}"},
                status=502,
            )
            return resp  # type: ignore[return-value]

        # Set up streaming response
        stream_resp = web.StreamResponse(
            status=upstream_resp.status,
            headers={"Content-Type": "text/event-stream", "Cache-Control": "no-cache"},
        )
        await stream_resp.prepare(request)

        # Process the SSE stream
        handler = SSEStreamHandler(self._interceptor)
        async for chunk in handler.process_stream(upstream_resp):
            await stream_resp.write(chunk)

        await upstream_resp.release()
        await stream_resp.write_eof()
        return stream_resp

    async def _forward_request(self, request: web.Request) -> web.Response:
        """Forward a request to the upstream without interception."""
        body = await request.json() if request.method in ("POST", "PUT", "PATCH") else None
        return await self._forward_to_upstream(request, body)

    async def _forward_to_upstream(
        self,
        request: web.Request,
        body: dict[str, Any] | None = None,
    ) -> web.Response:
        """Forward the request to the upstream LLM API.

        Replaces the request's Host header and Authorization with the
        upstream's base URL and API key.
        """
        path = "/" + request.match_info.get("path", "")
        upstream_url = self._config.upstream_base_url.rstrip("/") + path

        # Build headers — forward most, but replace auth
        headers = {}
        for key, value in request.headers.items():
            key_lower = key.lower()
            if key_lower in ("host", "content-length", "transfer-encoding"):
                continue
            if key_lower == "authorization" and self._config.upstream_api_key:
                continue  # Will be replaced
            headers[key] = value

        if self._config.upstream_api_key:
            headers["Authorization"] = f"Bearer {self._config.upstream_api_key}"

        # Get or create HTTP session
        session = await self._get_session()

        try:
            async with session.request(
                method=request.method,
                url=upstream_url,
                headers=headers,
                json=body,
                timeout=aiohttp.ClientTimeout(total=self._config.request_timeout_s),
            ) as resp:
                # Read the full response
                resp_body = await resp.read()
                content_type = resp.content_type

                # Build response headers (skip hop-by-hop)
                resp_headers = {}
                for key, value in resp.headers.items():
                    key_lower = key.lower()
                    if key_lower in ("transfer-encoding", "connection", "content-encoding"):
                        continue
                    resp_headers[key] = value

                return web.Response(
                    body=resp_body,
                    status=resp.status,
                    content_type=content_type,
                    headers=resp_headers,
                )
        except aiohttp.ClientError as e:
            logger.error("Upstream request failed: %s", e)
            return web.json_response(
                {"error": f"Upstream request failed: {e}"},
                status=502,
            )

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create the HTTP client session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    def _block_response(self, decision: ProxyDecision) -> web.Response:
        """Return an error response for blocked requests/responses."""
        return web.json_response(
            {
                "error": {
                    "message": decision.block_reason,
                    "type": "qise_guard_block",
                    "warnings": decision.warnings,
                    "guard_results": decision.guard_results,
                }
            },
            status=403,
        )
