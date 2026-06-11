"""Tests for managed product service lifecycle helpers."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from qise.product import service


def test_spawn_service_terminates_process_after_start_timeout(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("QISE_HOME", str(tmp_path))
    process = MagicMock()
    process.pid = 12345
    process.poll.return_value = None

    with (
        patch("qise.product.service.check_port", return_value=service.PortCheck("127.0.0.1", 8823, "available")),
        patch("qise.product.service.subprocess.Popen", return_value=process),
        patch("qise.product.service._wait_for_port", return_value=False),
        pytest.raises(RuntimeError, match="did not listen"),
    ):
        service._spawn_service("bridge", ["qise", "bridge", "start"], 8823, {})

    process.terminate.assert_called_once_with()
    process.wait.assert_called_once_with(timeout=2)


def test_start_managed_services_rolls_back_bridge_when_proxy_fails() -> None:
    bridge_record = {
        "pid": 12345,
        "port": 8823,
        "status": "running",
        "managed_by": "qise",
    }

    with (
        patch("qise.product.service.load_state", return_value={}),
        patch(
            "qise.product.service._spawn_service",
            side_effect=[bridge_record, RuntimeError("proxy failed")],
        ) as spawn,
        patch("qise.product.service._terminate_service_record") as terminate,
        pytest.raises(RuntimeError, match="proxy failed"),
    ):
        service.start_managed_services(
            config_path=None,
            proxy_port=8822,
            bridge_port=8823,
            upstream_url="https://api.example.com/v1",
        )

    assert spawn.call_count == 2
    assert spawn.call_args_list[0].args[0:3:2] == ("bridge", 8823)
    assert spawn.call_args_list[1].args[0:3:2] == ("proxy", 8822)
    terminate.assert_called_once_with(bridge_record)
