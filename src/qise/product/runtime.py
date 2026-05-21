"""Lightweight runtime observer for `qise run`.

This is intentionally a user-space wrapper, not kernel auditing. It gives Qise
an early Observer surface by recording process, file, stdout/stderr, and best-effort
network evidence around an Agent process.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

from qise.product.events import record_runtime_event
from qise.product.service import load_state, now_iso, qise_home, save_state

_IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    ".qise",
}
_MAX_SNAPSHOT_FILES = 2500
_MAX_DIFF_ITEMS = 80
_MAX_PROCESS_ITEMS = 120
_MAX_NETWORK_ITEMS = 80
_MAX_TAIL_LINES = 80
_MAX_TAIL_CHARS = 4000


@dataclass
class RuntimeResult:
    agent_name: str
    command: list[str]
    cwd: str
    pid: int
    returncode: int
    duration_s: float
    correlation_id: str
    stdout_summary: str
    stderr_summary: str
    process_tree: list[dict[str, object]] = field(default_factory=list)
    file_changes: dict[str, object] = field(default_factory=dict)
    network: list[dict[str, object]] = field(default_factory=list)


class TailBuffer:
    def __init__(self, max_lines: int = _MAX_TAIL_LINES) -> None:
        self._lines: deque[str] = deque(maxlen=max_lines)
        self._lock = threading.Lock()

    def append(self, line: str) -> None:
        if not line:
            return
        with self._lock:
            self._lines.append(line.rstrip("\n"))

    def text(self) -> str:
        with self._lock:
            value = "\n".join(self._lines)
        if len(value) <= _MAX_TAIL_CHARS:
            return value
        return value[-_MAX_TAIL_CHARS:]


class RuntimeSampler:
    def __init__(self, root_pid: int, *, poll_interval_s: float = 1.0) -> None:
        self.root_pid = root_pid
        self.poll_interval_s = max(0.2, poll_interval_s)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._processes: dict[tuple[int, str], dict[str, object]] = {}
        self._network: dict[str, dict[str, object]] = {}
        self._lock = threading.Lock()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="qise-runtime-observer", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        self._sample_once()

    def processes(self) -> list[dict[str, object]]:
        with self._lock:
            items = list(self._processes.values())
        return sorted(
            items,
            key=lambda item: (int(item.get("pid", 0)), str(item.get("command", ""))),
        )[:_MAX_PROCESS_ITEMS]

    def network(self) -> list[dict[str, object]]:
        with self._lock:
            items = list(self._network.values())
        return sorted(items, key=lambda item: str(item.get("endpoint", "")))[:_MAX_NETWORK_ITEMS]

    def _run(self) -> None:
        while not self._stop.wait(self.poll_interval_s):
            self._sample_once()

    def _sample_once(self) -> None:
        table = _ps_table()
        descendants = _descendants(self.root_pid, table)
        if not descendants:
            return
        network = _network_for_pids([int(item["pid"]) for item in descendants])
        with self._lock:
            for item in descendants:
                key = (int(item["pid"]), str(item["command"]))
                self._processes.setdefault(key, item)
            for item in network:
                endpoint = str(item.get("endpoint", ""))
                if endpoint:
                    self._network.setdefault(endpoint, item)


def run_observed_command(
    *,
    agent_name: str,
    command: list[str],
    cwd: str | None = None,
    poll_interval_s: float = 1.0,
    snapshot_files: bool = True,
) -> RuntimeResult:
    if not command:
        raise ValueError("No command provided after `--`.")

    workdir = Path(cwd or Path.cwd()).expanduser().resolve()
    if not workdir.exists():
        raise FileNotFoundError(f"Working directory does not exist: {workdir}")
    if not workdir.is_dir():
        raise NotADirectoryError(f"Working directory is not a directory: {workdir}")

    correlation_id = f"corr_{uuid.uuid4().hex[:12]}"
    before = _snapshot_tree(workdir) if snapshot_files else {}
    env = os.environ.copy()
    env["QISE_RUNTIME_CORRELATION_ID"] = correlation_id
    env["QISE_AGENT_NAME"] = agent_name

    stdout_tail = TailBuffer()
    stderr_tail = TailBuffer()
    started = time.monotonic()
    proc = subprocess.Popen(
        command,
        cwd=str(workdir),
        env=env,
        stdin=None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        bufsize=1,
        start_new_session=True,
    )
    _save_runtime_state(
        correlation_id=correlation_id,
        agent_name=agent_name,
        command=command,
        cwd=str(workdir),
        pid=proc.pid,
        status="running",
    )

    sampler = RuntimeSampler(proc.pid, poll_interval_s=poll_interval_s)
    sampler.start()
    stdout_thread = _tee_stream(proc.stdout, sys.stdout, stdout_tail)
    stderr_thread = _tee_stream(proc.stderr, sys.stderr, stderr_tail)

    interrupted = False
    try:
        returncode = proc.wait()
    except KeyboardInterrupt:
        interrupted = True
        _terminate_process_group(proc)
        returncode = proc.wait(timeout=10)
    finally:
        sampler.stop()
        for thread in (stdout_thread, stderr_thread):
            thread.join(timeout=3)

    after = _snapshot_tree(workdir) if snapshot_files else {}
    duration_s = time.monotonic() - started
    process_tree = sampler.processes()
    if not any(int(item.get("pid", 0)) == proc.pid for item in process_tree):
        process_tree.insert(0, {"pid": proc.pid, "ppid": os.getpid(), "command": " ".join(command)})

    result = RuntimeResult(
        agent_name=agent_name,
        command=command,
        cwd=str(workdir),
        pid=proc.pid,
        returncode=130 if interrupted and returncode == 0 else int(returncode),
        duration_s=duration_s,
        correlation_id=correlation_id,
        stdout_summary=stdout_tail.text(),
        stderr_summary=stderr_tail.text(),
        process_tree=process_tree,
        file_changes=_diff_snapshots(before, after) if snapshot_files else {},
        network=sampler.network(),
    )
    record_runtime_event(
        agent_name=result.agent_name,
        command=result.command,
        cwd=result.cwd,
        pid=result.pid,
        returncode=result.returncode,
        duration_s=result.duration_s,
        correlation_id=result.correlation_id,
        stdout_summary=result.stdout_summary,
        stderr_summary=result.stderr_summary,
        process_tree=result.process_tree,
        file_changes=result.file_changes,
        network=result.network,
    )
    _save_runtime_state(
        correlation_id=correlation_id,
        agent_name=agent_name,
        command=command,
        cwd=str(workdir),
        pid=proc.pid,
        status="finished",
        returncode=result.returncode,
        duration_s=round(result.duration_s, 3),
    )
    return result


def _tee_stream(source: TextIO | None, target: TextIO, tail: TailBuffer) -> threading.Thread:
    def _run() -> None:
        if source is None:
            return
        try:
            for line in source:
                tail.append(line)
                target.write(line)
                target.flush()
        finally:
            with suppress(Exception):
                source.close()

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return thread


def _terminate_process_group(proc: subprocess.Popen[str]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except Exception:
        proc.terminate()
    deadline = time.time() + 5
    while time.time() < deadline:
        if proc.poll() is not None:
            return
        time.sleep(0.1)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except Exception:
        proc.kill()


def _snapshot_tree(root: Path) -> dict[str, tuple[int, int]]:
    snapshot: dict[str, tuple[int, int]] = {}
    count = 0
    qise_home_path = qise_home().resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        current_dir = Path(dirpath).resolve()
        if current_dir == qise_home_path or qise_home_path in current_dir.parents:
            dirnames[:] = []
            continue
        kept_dirs = []
        for name in dirnames:
            child = (current_dir / name).resolve()
            if name in _IGNORE_DIRS or child == qise_home_path or qise_home_path in child.parents:
                continue
            kept_dirs.append(name)
        dirnames[:] = kept_dirs
        for filename in filenames:
            path = Path(dirpath) / filename
            try:
                rel = str(path.relative_to(root))
                stat = path.stat()
            except OSError:
                continue
            snapshot[rel] = (int(stat.st_size), int(stat.st_mtime_ns))
            count += 1
            if count >= _MAX_SNAPSHOT_FILES:
                snapshot["__qise_snapshot_truncated__"] = (count, 0)
                return snapshot
    return snapshot


def _diff_snapshots(before: dict[str, tuple[int, int]], after: dict[str, tuple[int, int]]) -> dict[str, object]:
    before_keys = {key for key in before if not key.startswith("__qise_")}
    after_keys = {key for key in after if not key.startswith("__qise_")}
    added = sorted(after_keys - before_keys)
    deleted = sorted(before_keys - after_keys)
    modified = sorted(key for key in before_keys & after_keys if before[key] != after[key])
    truncated = "__qise_snapshot_truncated__" in before or "__qise_snapshot_truncated__" in after
    return {
        "added": added[:_MAX_DIFF_ITEMS],
        "modified": modified[:_MAX_DIFF_ITEMS],
        "deleted": deleted[:_MAX_DIFF_ITEMS],
        "counts": {
            "added": len(added),
            "modified": len(modified),
            "deleted": len(deleted),
        },
        "truncated": truncated or any(len(items) > _MAX_DIFF_ITEMS for items in (added, modified, deleted)),
    }


def _ps_table() -> dict[int, tuple[int, str]]:
    try:
        result = subprocess.run(
            ["ps", "-axo", "pid=,ppid=,command="],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except Exception:
        return {}
    table: dict[int, tuple[int, str]] = {}
    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 2:
            continue
        try:
            pid = int(parts[0])
            ppid = int(parts[1])
        except ValueError:
            continue
        command = parts[2] if len(parts) > 2 else ""
        table[pid] = (ppid, command)
    return table


def _descendants(root_pid: int, table: dict[int, tuple[int, str]]) -> list[dict[str, object]]:
    if not table:
        return []
    children: dict[int, list[int]] = {}
    for pid, (ppid, _command) in table.items():
        children.setdefault(ppid, []).append(pid)
    seen: set[int] = set()
    queue = [root_pid]
    result: list[dict[str, object]] = []
    while queue and len(result) < _MAX_PROCESS_ITEMS:
        pid = queue.pop(0)
        if pid in seen:
            continue
        seen.add(pid)
        ppid, command = table.get(pid, (0, ""))
        result.append({"pid": pid, "ppid": ppid, "command": command})
        queue.extend(children.get(pid, []))
    return result


def _network_for_pids(pids: list[int]) -> list[dict[str, object]]:
    if not pids:
        return []
    pid_arg = ",".join(str(pid) for pid in sorted(set(pids))[:_MAX_PROCESS_ITEMS])
    try:
        result = subprocess.run(
            ["lsof", "-nP", "-i", "-a", "-p", pid_arg],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except Exception:
        return []
    endpoints: list[dict[str, object]] = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        try:
            pid = int(parts[1])
        except ValueError:
            continue
        name = parts[8]
        if not name:
            continue
        endpoints.append({
            "pid": pid,
            "command": parts[0],
            "protocol": parts[7],
            "endpoint": name,
        })
    return endpoints[:_MAX_NETWORK_ITEMS]


def _save_runtime_state(
    *,
    correlation_id: str,
    agent_name: str,
    command: list[str],
    cwd: str,
    pid: int,
    status: str,
    returncode: int | None = None,
    duration_s: float | None = None,
) -> None:
    state = load_state()
    runs = state.setdefault("runtime_runs", {})
    if not isinstance(runs, dict):
        runs = {}
        state["runtime_runs"] = runs
    record = {
        "agent": agent_name,
        "command": command,
        "cwd": cwd,
        "pid": pid,
        "status": status,
        "updated_at": now_iso(),
    }
    if returncode is not None:
        record["returncode"] = returncode
    if duration_s is not None:
        record["duration_s"] = duration_s
    if status == "running":
        record["started_at"] = now_iso()
    runs[correlation_id] = record
    save_state(state)
