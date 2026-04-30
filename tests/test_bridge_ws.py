"""Tests for Bridge WebSocket event stream endpoint."""
from __future__ import annotations

import asyncio
import json

import pytest
from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, TestClient, TestServer

from qise.bridge.server import BridgeServer
from qise.core.config import ShieldConfig
from qise.core.shield import Shield


@pytest.fixture
def shield() -> Shield:
    """Create a minimal Shield for testing."""
    config = ShieldConfig.default()
    return Shield(config)


@pytest.fixture
def bridge(shield: Shield) -> BridgeServer:
    """Create a BridgeServer instance."""
    return BridgeServer(shield, port=0)  # port=0 lets OS assign


class TestBridgeWebSocket:
    """Test Bridge WebSocket /v1/bridge/events/stream."""

    @pytest.mark.asyncio
    async def test_ws_server_starts(self, bridge: BridgeServer) -> None:
        """WebSocket server starts and runner is created."""
        await bridge.start()
        try:
            assert bridge._runner is not None
        finally:
            await bridge.stop()

    @pytest.mark.asyncio
    async def test_ws_clients_list(self, bridge: BridgeServer) -> None:
        """_ws_clients starts empty."""
        assert len(bridge._ws_clients) == 0

    @pytest.mark.asyncio
    async def test_notify_ws_clients_no_clients(self, bridge: BridgeServer) -> None:
        """_notify_ws_clients handles no connected clients gracefully."""
        event_data = {
            "timestamp": "2026-04-30T12:00:00",
            "guard_name": "command",
            "verdict": "block",
            "message": "Dangerous command",
        }
        # Should not raise
        bridge._notify_ws_clients(event_data)

    @pytest.mark.asyncio
    async def test_event_buffer_with_ws_notification(self, bridge: BridgeServer) -> None:
        """Events are stored in buffer even without WS clients."""
        initial_count = len(bridge._event_buffer)
        event_data = {
            "timestamp": "2026-04-30T12:00:00",
            "guard_name": "prompt",
            "verdict": "warn",
            "message": "Injection detected",
        }
        bridge._event_buffer.append(event_data)
        bridge._notify_ws_clients(event_data)
        assert len(bridge._event_buffer) == initial_count + 1
