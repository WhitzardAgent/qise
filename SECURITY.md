# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.x     | Yes (active development) |

Qise is currently in active development (Phase 1). Security updates will be applied to the latest version.

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

Instead, report them via:

- **Email**: security@qise.dev (preferred)
- **GitHub Security Advisories**: Use the "Report a vulnerability" feature on the Security tab

### What to Include

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Any suggested mitigations

### Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix development | Depends on severity |
| Disclosure | After fix is released |

## Security Scope

Qise is designed to protect AI agents at runtime. The following are in scope:

- Bypass of Qise's security guards
- Evasion of threat detection patterns
- Security vulnerabilities in Qise's own code (e.g., injection in YAML parsing)
- Compromise of baseline integrity
- Model prompt injection targeting Qise's SLM/LLM calls

The following are **out of scope** for this project:

- Vulnerabilities in agent frameworks themselves (report to respective projects)
- Model-level safety issues (alignment, harmful outputs from base models)
- Infrastructure security (container escape, OS hardening)

## Secure Development Practices

- All YAML parsing uses safe loaders (no arbitrary code execution)
- All model API calls use HTTPS with certificate verification
- No credentials are logged or stored in plaintext
- Baseline hashes use SHA-256
- All guard results include confidence scores and reasoning for auditability
