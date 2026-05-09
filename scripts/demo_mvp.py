#!/usr/bin/env python3
"""Python wrapper for scripts/demo_mvp.sh."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    script = Path(__file__).with_suffix(".sh")
    env = os.environ.copy()
    env.setdefault("PYTHON", sys.executable)
    return subprocess.call(["bash", str(script)], env=env)


if __name__ == "__main__":
    raise SystemExit(main())
