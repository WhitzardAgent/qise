"""Local product state and service helpers."""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_PROXY_PORT = 8822
DEFAULT_BRIDGE_PORT = 8823


@dataclass
class PortCheck:
    host: str
    port: int
    status: str
    detail: str = ""


def now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def qise_version() -> str:
    try:
        from qise import __version__

        return __version__
    except Exception:
        return "unknown"


def qise_home() -> Path:
    return Path(os.environ.get("QISE_HOME", "~/.qise")).expanduser()


def ensure_qise_home() -> Path:
    home = qise_home()
    home.mkdir(parents=True, exist_ok=True)
    return home


def state_path() -> Path:
    return qise_home() / "state.json"


def events_path() -> Path:
    return qise_home() / "events.jsonl"


def backups_dir() -> Path:
    return qise_home() / "backups"


def logs_dir() -> Path:
    return qise_home() / "logs"


def read_json_file(path: Path, default: Any) -> Any:
    try:
        if not path.exists():
            return default
        return json.loads(path.read_text())
    except Exception:
        return default


def write_json_file(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def load_state() -> dict[str, Any]:
    state = read_json_file(state_path(), {})
    if not isinstance(state, dict):
        return {"services": {}, "protected_agents": {}}
    state.setdefault("services", {})
    state.setdefault("protected_agents", {})
    return state


def save_state(state: dict[str, Any]) -> None:
    state["updated_at"] = now_iso()
    state["qise_version"] = qise_version()
    write_json_file(state_path(), state)


def check_port(host: str, port: int) -> PortCheck:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        sock.bind((host, port))
    except OSError as exc:
        detail = str(exc)
        if "Address already in use" in detail or getattr(exc, "errno", None) == 48:
            return PortCheck(host, port, "in_use", detail)
        return PortCheck(host, port, "unavailable", detail)
    finally:
        sock.close()
    return PortCheck(host, port, "available")


def is_pid_running(pid: int | None) -> bool:
    if not pid or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def inspect_services(state: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return service records annotated with their current runtime state."""
    raw_services = state.get("services", {})
    if not isinstance(raw_services, dict):
        return {}

    inspected: dict[str, dict[str, Any]] = {}
    for name, raw_meta in raw_services.items():
        if not isinstance(raw_meta, dict):
            continue
        meta = dict(raw_meta)
        status = str(meta.get("status") or "")
        try:
            port = int(meta.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        port_status = check_port("127.0.0.1", port).status if port > 0 else "unavailable"

        if status == "running":
            pid = meta.get("pid")
            if not isinstance(pid, int) or not is_pid_running(pid):
                meta["status"] = "stale"
                meta["detail"] = f"recorded pid {pid or '(none)'} is not running"
            elif not _looks_like_qise_process(pid):
                meta["status"] = "stale"
                meta["detail"] = f"pid {pid} is not a Qise service"
            elif port_status != "in_use":
                meta["status"] = "stale"
                meta["detail"] = f"127.0.0.1:{port} is not listening"
        elif status == "already_running" and port_status != "in_use":
            meta["status"] = "stale"
            meta["detail"] = f"127.0.0.1:{port} is no longer listening"

        meta["port_status"] = port_status
        inspected[str(name)] = meta

    return inspected


def services_are_active(services: dict[str, dict[str, Any]]) -> bool:
    """Return whether both managed protection services are currently reachable."""
    for name in ("proxy", "bridge"):
        meta = services.get(name, {})
        if meta.get("status") not in {"running", "already_running"}:
            return False
        if meta.get("port_status") != "in_use":
            return False
    return True


def _looks_like_qise_process(pid: int) -> bool:
    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except Exception:
        return False
    command = result.stdout.strip()
    return "qise" in command and ("proxy start" in command or "bridge start" in command)


def _wait_for_port(host: str, port: int, timeout_s: float = 5.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if check_port(host, port).status == "in_use":
            return True
        time.sleep(0.1)
    return False


def _spawn_service(name: str, cmd: list[str], port: int, env: dict[str, str]) -> dict[str, Any]:
    log_dir = logs_dir()
    log_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = log_dir / f"{name}.out.log"
    stderr_path = log_dir / f"{name}.err.log"

    if check_port("127.0.0.1", port).status == "in_use":
        return {
            "pid": None,
            "port": port,
            "status": "already_running",
            "managed_by": "external-or-existing-qise",
            "command": " ".join(cmd),
            "started_at": now_iso(),
            "stdout_log": str(stdout_path),
            "stderr_log": str(stderr_path),
        }

    stdout = stdout_path.open("ab")
    stderr = stderr_path.open("ab")
    proc = subprocess.Popen(
        cmd,
        stdout=stdout,
        stderr=stderr,
        env=env,
        cwd=str(Path.cwd()),
        start_new_session=True,
    )
    stdout.close()
    stderr.close()

    if not _wait_for_port("127.0.0.1", port):
        return_code = proc.poll()
        if return_code is not None:
            raise RuntimeError(f"{name} exited with code {return_code}. See {stderr_path} for details.")
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
        raise RuntimeError(f"{name} did not listen on 127.0.0.1:{port} within 5s")

    return {
        "pid": proc.pid,
        "port": port,
        "status": "running",
        "managed_by": "qise",
        "command": " ".join(cmd),
        "started_at": now_iso(),
        "stdout_log": str(stdout_path),
        "stderr_log": str(stderr_path),
    }


def _terminate_service_record(meta: dict[str, Any]) -> None:
    """Best-effort rollback for a service started in the current transaction."""
    pid = meta.get("pid")
    if meta.get("status") != "running" or meta.get("managed_by") != "qise":
        return
    if not isinstance(pid, int) or not is_pid_running(pid):
        return
    try:
        os.kill(pid, signal.SIGTERM)
        deadline = time.time() + 2
        while time.time() < deadline and is_pid_running(pid):
            time.sleep(0.05)
        if is_pid_running(pid):
            os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def _qise_service_command(config_args: list[str], service_args: list[str]) -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, *config_args, *service_args]
    return [sys.executable, "-m", "qise", *config_args, *service_args]


def start_managed_services(
    *,
    config_path: str | None,
    proxy_port: int,
    bridge_port: int = DEFAULT_BRIDGE_PORT,
    upstream_url: str,
    upstream_api_key: str = "",
) -> dict[str, Any]:
    if not upstream_url:
        raise ValueError(
            "Proxy upstream is not configured. Set integration.proxy.upstream_url, "
            "QISE_PROXY_UPSTREAM_URL, OPENAI_API_BASE, ANTHROPIC_BASE_URL, or pass --base-url."
        )

    state = load_state()
    env = os.environ.copy()
    services = state.setdefault("services", {})
    config_args = ["--config", config_path] if config_path else []

    bridge_cmd = _qise_service_command(config_args, [
        "bridge",
        "start",
        "--port",
        str(bridge_port),
    ])
    proxy_cmd = _qise_service_command(config_args, [
        "proxy",
        "start",
        "--port",
        str(proxy_port),
        "--upstream",
        upstream_url.rstrip("/"),
        "--no-reload",
    ])
    if upstream_api_key:
        proxy_cmd.extend(["--upstream-key", upstream_api_key])

    if os.environ.get("QISE_NO_START_SERVICES"):
        services["bridge"] = {
            "pid": None,
            "port": bridge_port,
            "status": "skipped",
            "managed_by": "qise-test",
            "started_at": now_iso(),
        }
        services["proxy"] = {
            "pid": None,
            "port": proxy_port,
            "status": "skipped",
            "managed_by": "qise-test",
            "upstream_url": upstream_url.rstrip("/"),
            "started_at": now_iso(),
        }
        save_state(state)
        return services

    bridge_meta = _spawn_service("bridge", bridge_cmd, bridge_port, env)
    services["bridge"] = bridge_meta
    try:
        services["proxy"] = _spawn_service("proxy", proxy_cmd, proxy_port, env)
    except Exception:
        _terminate_service_record(bridge_meta)
        services.pop("bridge", None)
        raise
    services["proxy"]["upstream_url"] = upstream_url.rstrip("/")
    save_state(state)
    return services


def stop_managed_services() -> tuple[list[str], list[str]]:
    state = load_state()
    services = state.get("services", {})
    stopped: list[str] = []
    notes: list[str] = []

    for name, meta in list(services.items()):
        if not isinstance(meta, dict):
            continue
        pid = meta.get("pid")
        status = meta.get("status")
        if status in {"skipped", "already_running"} or not pid:
            stopped.append(f"{name}: cleared {status or 'stale'} service record")
            services.pop(name, None)
            continue
        if not is_pid_running(pid):
            stopped.append(f"{name}: no running process found for pid {pid}")
            services.pop(name, None)
            continue
        if not _looks_like_qise_process(pid):
            notes.append(f"{name}: pid {pid} is running but does not look like a Qise service; not stopping")
            continue
        try:
            os.kill(pid, signal.SIGTERM)
            deadline = time.time() + 5
            while time.time() < deadline and is_pid_running(pid):
                time.sleep(0.1)
            if is_pid_running(pid):
                notes.append(f"{name}: pid {pid} did not stop after SIGTERM")
            else:
                stopped.append(f"{name}: stopped pid {pid}")
                services.pop(name, None)
        except OSError as exc:
            notes.append(f"{name}: failed to stop pid {pid}: {exc}")

    if stopped:
        state["services"] = services
        save_state(state)
    return stopped, notes
