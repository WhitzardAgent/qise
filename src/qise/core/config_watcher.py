"""ConfigWatcher — watch shield.yaml for changes and trigger hot-reload.

Uses the watchfiles library for efficient filesystem change detection.
When the config file changes, the callback is invoked with the new ShieldConfig.

Usage:
    from qise.core.config_watcher import ConfigWatcher

    def on_config_change(new_config: ShieldConfig) -> None:
        shield.reconfigure(new_config)

    watcher = ConfigWatcher("shield.yaml", on_config_change)
    watcher.start()   # starts background thread
    # ...
    watcher.stop()    # stops watching
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Callable

from qise.core.config import ShieldConfig

logger = logging.getLogger("qise.config_watcher")


class ConfigWatcher:
    """Watch a shield.yaml file for changes and invoke a callback on reload.

    Uses watchfiles for efficient filesystem change detection. Falls back
    to polling if watchfiles is not installed.
    """

    def __init__(
        self,
        config_path: str | Path,
        callback: Callable[[ShieldConfig], None],
        poll_interval_s: float = 2.0,
    ) -> None:
        """Initialize the config watcher.

        Args:
            config_path: Path to the shield.yaml file to watch.
            callback: Function called with the new ShieldConfig when file changes.
            poll_interval_s: Fallback polling interval if watchfiles is unavailable.
        """
        self._config_path = Path(config_path).resolve()
        self._callback = callback
        self._poll_interval_s = poll_interval_s
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._use_watchfiles = False

        # Try to import watchfiles
        try:
            import watchfiles  # noqa: F401
            self._use_watchfiles = True
        except ImportError:
            logger.info("watchfiles not installed, using polling fallback for config watching")

    @property
    def config_path(self) -> Path:
        """Return the watched config file path."""
        return self._config_path

    @property
    def is_running(self) -> bool:
        """Return whether the watcher is currently running."""
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        """Start watching in a background thread."""
        if self.is_running:
            logger.warning("ConfigWatcher already running")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="qise-config-watcher",
            daemon=True,
        )
        self._thread.start()
        logger.info("ConfigWatcher started: watching %s", self._config_path)

    def stop(self) -> None:
        """Stop watching."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        logger.info("ConfigWatcher stopped")

    def _run(self) -> None:
        """Main watch loop (runs in background thread)."""
        if self._use_watchfiles:
            self._run_watchfiles()
        else:
            self._run_polling()

    def _run_watchfiles(self) -> None:
        """Watch using watchfiles library (efficient inotify/FSEvents)."""
        try:
            from watchfiles import watch
        except ImportError:
            self._run_polling()
            return

        try:
            for changes in watch(self._config_path.parent, stop_event=self._stop_event):
                for change_type, path_str in changes:
                    path = Path(path_str)
                    if path.resolve() == self._config_path:
                        logger.info("Config file changed, reloading: %s", path)
                        self._reload()
        except Exception as exc:
            if not self._stop_event.is_set():
                logger.error("ConfigWatcher error: %s", exc)

    def _run_polling(self) -> None:
        """Watch using simple polling (fallback when watchfiles is unavailable)."""
        last_mtime: float | None = None

        try:
            last_mtime = self._config_path.stat().st_mtime
        except FileNotFoundError:
            logger.warning("Config file not found: %s", self._config_path)

        while not self._stop_event.is_set():
            self._stop_event.wait(self._poll_interval_s)
            if self._stop_event.is_set():
                break

            try:
                current_mtime = self._config_path.stat().st_mtime
                if last_mtime is not None and current_mtime != last_mtime:
                    logger.info("Config file changed (polling), reloading: %s", self._config_path)
                    self._reload()
                last_mtime = current_mtime
            except FileNotFoundError:
                logger.warning("Config file disappeared: %s", self._config_path)
            except OSError:
                pass

    def _reload(self) -> None:
        """Reload the config file and invoke the callback."""
        try:
            new_config = ShieldConfig.from_yaml(self._config_path)
            self._callback(new_config)
            logger.info("Config reloaded successfully")
        except Exception as exc:
            logger.error("Failed to reload config: %s", exc)
