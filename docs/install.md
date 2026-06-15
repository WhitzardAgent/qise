# Install

## Requirements

- Python 3.11+
- macOS or Linux shell for the current MVP scripts
- An existing Agent install only if you want to run `qise protect codex` against your real config

## Desktop Install

Download the latest stable desktop installer from:

https://github.com/WhitzardAgent/qise/releases/latest

Supported desktop packages:

- Windows x64 NSIS installer.
- macOS Apple Silicon DMG.

This Qise 0.2.0 build is the first updater-enabled build. Users on an earlier 0.2.0 build must install it manually once because automatic updates require a higher version number. Later releases update automatically after startup when no Agent is protected. Active protection defers the update until a later safe startup.

## Source Install

Recommended before the first PyPI release:

```bash
git clone https://github.com/WhitzardAgent/qise.git
cd qise
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[proxy]"
qise doctor
```

For development and tests:

```bash
pip install -e ".[dev,proxy]"
pytest tests/test_product_cli.py
```

## pipx After Release

Once Qise is published to PyPI, the intended command is:

```bash
pipx install qise
```

Until then, use the source install above. A Git-based pipx install may work, but source install is easier to inspect and debug during the MVP phase.

## Verify

```bash
qise version
qise doctor
qise check bash '{"command":"rm -rf /"}' || true
qise events --limit 5
```

## Uninstall Source Install

From the repository virtual environment:

```bash
pip uninstall qise
```

Qise local runtime data remains under `~/.qise/` unless you remove it manually.
