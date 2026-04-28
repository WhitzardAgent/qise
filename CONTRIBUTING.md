# Contributing to Qise

Thank you for your interest in contributing to Qise! This document provides guidelines for contributing.

## Development Setup

```bash
# Clone and install
git clone https://github.com/your-org/qise.git
cd qise
pip install -e ".[dev]"

# Start a local SLM (optional, for AI guard development)
python -m qise.serve_slm --model Qwen3-4B

# Run tests
pytest -x

# Lint
ruff check .

# Format
ruff format .

# Type check
mypy src/qise
```

## Project Structure

```
qise/
├── src/qise/
│   ├── core/           # GuardContext, AIGuardBase, Pipeline, Shield
│   ├── guards/         # Individual Guard implementations
│   ├── models/         # ModelRouter, SLM/LLM clients
│   ├── adapters/       # Framework adapters (Nanobot, Hermes, etc.)
│   ├── providers/      # SecurityContextProvider, DSL rendering
│   └── data/           # ThreatPatternLoader, BaselineManager
├── data/               # YAML data files (threat patterns, DSL templates, baselines)
├── docs/               # Documentation
├── tests/              # Test suite
└── CLAUDE.md           # AI development context
```

## Code Style

- Python 3.11+ with type hints on all public APIs
- `async/await` for all I/O-bound operations
- Pydantic v2 for all data models
- Use `ruff` for linting and formatting
- Maximum line length: 120 characters

## Adding a New Guard

1. Create a new file in `src/qise/guards/`
2. Inherit from `AIGuardBase`
3. Set `name`, `primary_strategy`, `slm_prompt_template`, `llm_prompt_template`
4. Optionally provide a `rule_fallback` (inherit from `RuleChecker`)
5. Add configuration schema to `ShieldConfig`
6. Add threat patterns to `data/threat_patterns/`
7. Write tests in `tests/`

Example:

```python
from qise.core import AIGuardBase, GuardContext, GuardResult, GuardVerdict

class MyGuard(AIGuardBase):
    name = "my_guard"
    primary_strategy = "ai"
    slm_prompt_template = "Analyze this for {risk_type}..."
    llm_prompt_template = "Given trajectory {trajectory}, analyze..."
```

## Adding a New Framework Adapter

1. Create a new file in `src/qise/adapters/`
2. Inherit from `BaseAdapter`
3. Implement all abstract methods
4. Use only the framework's official Hook/Plugin API — **never monkey-patch**
5. Handle missing capabilities gracefully (e.g., MCP has no trajectory access)
6. Write integration tests

## Adding Threat Patterns

1. Create a YAML file in `data/threat_patterns/`
2. Follow the schema in `docs/data-formats.md`
3. Include at least 2 `attack_examples` with verdicts and reasoning
4. Include `rule_signatures` where deterministic detection is possible
5. Include `mitigations` with recommended actions

## Pull Request Process

1. Create a feature branch: `feat/guard-name` or `fix/issue-description`
2. Write tests for your changes
3. Ensure all tests pass: `pytest -x`
4. Ensure linting passes: `ruff check .`
5. Ensure type checking passes: `mypy src/qise`
6. Submit PR with a clear description of the change

## Commit Messages

Use conventional commit format:

```
feat(guards): add ExfilGuard for data exfiltration detection
fix(pipeline): short-circuit on BLOCK verdict
docs(guards): update PromptGuard SLM prompt template
data(patterns): add tool_poisoning threat pattern YAML
```

## Reporting Issues

- Security vulnerabilities: See [SECURITY.md](SECURITY.md)
- Bugs: Use GitHub Issues with steps to reproduce
- Feature requests: Use GitHub Issues with use case description

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 license.
