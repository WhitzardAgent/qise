# Install

## Requirements

- Python 3.11+
- macOS or Linux shell for the current MVP scripts
- An existing Agent install only if you want to run `qise protect codex` against your real config

## Source Install

Recommended before the first PyPI release:

```bash
git clone https://github.com/opq-qise/qise.git
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
