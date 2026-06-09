#!/usr/bin/env python3
"""Build the bundled Qise CLI runtime for the current desktop platform."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT_DIR / "src-tauri" / "resources" / "bin"
WORK_DIR = ROOT_DIR / "src-tauri" / "target" / "pyinstaller-work"
SPEC_DIR = ROOT_DIR / "src-tauri" / "target" / "pyinstaller-spec"
CONFIG_DIR = ROOT_DIR / "src-tauri" / "target" / "pyinstaller-config"


def command_works(command: list[str], *args: str) -> bool:
    return (
        subprocess.run(
            [*command, *args],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    )


def select_python() -> list[str]:
    configured = os.environ.get("QISE_DESKTOP_PYTHON", "").strip()
    if configured:
        return [configured]

    conda = shutil.which("conda")
    conda_python = [conda, "run", "-n", "qise", "python"] if conda else []
    if conda_python and command_works(conda_python, "-c", "import qise"):
        return conda_python

    return [sys.executable]


def main() -> int:
    for directory in (OUT_DIR, WORK_DIR, SPEC_DIR, CONFIG_DIR):
        directory.mkdir(parents=True, exist_ok=True)

    python_command = select_python()
    if not command_works(python_command, "-c", "import qise"):
        print(
            "Qise Desktop runtime build failed: selected Python cannot import qise.\n"
            "Set QISE_DESKTOP_PYTHON to a Python that has Qise installed.",
            file=sys.stderr,
        )
        return 1

    if not command_works(python_command, "-m", "PyInstaller", "--version"):
        print(
            "Qise Desktop runtime build failed: PyInstaller is not installed.\n"
            f"Install it with: {' '.join(python_command)} -m pip install pyinstaller",
            file=sys.stderr,
        )
        return 1

    env = os.environ.copy()
    env["PYINSTALLER_CONFIG_DIR"] = str(CONFIG_DIR)
    data_argument = f"{ROOT_DIR / 'src' / 'qise' / 'data'}{os.pathsep}qise/data"
    subprocess.run(
        [
            *python_command,
            "-m",
            "PyInstaller",
            "--clean",
            "--noconfirm",
            "--onefile",
            "--name",
            "qise",
            "--paths",
            str(ROOT_DIR / "src"),
            "--add-data",
            data_argument,
            "--collect-submodules",
            "qise",
            "--distpath",
            str(OUT_DIR),
            "--workpath",
            str(WORK_DIR),
            "--specpath",
            str(SPEC_DIR),
            str(ROOT_DIR / "src" / "qise" / "__main__.py"),
        ],
        env=env,
        check=True,
    )

    output_binary = OUT_DIR / ("qise.exe" if os.name == "nt" else "qise")
    if os.name != "nt":
        output_binary.chmod(output_binary.stat().st_mode | 0o111)
    subprocess.run([str(output_binary), "version"], check=True)
    print(f"Built bundled Qise runtime: {output_binary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
