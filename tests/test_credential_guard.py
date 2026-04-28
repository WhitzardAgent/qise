"""Tests for CredentialGuard."""

from qise.core.models import GuardContext, GuardVerdict
from qise.guards.credential import CredentialGuard


class TestCredentialGuardAWS:

    def test_detects_aws_access_key(self) -> None:
        guard = CredentialGuard()
        ctx = GuardContext(tool_name="output", tool_args={"text": "Key: AKIAIOSFODNN7EXAMPLE"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK
        assert "AWS" in result.message

    def test_detects_aws_secret_key(self) -> None:
        guard = CredentialGuard()
        ctx = GuardContext(
            tool_name="output",
            tool_args={"text": "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"},
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK


class TestCredentialGuardGitHub:

    def test_detects_github_pat(self) -> None:
        guard = CredentialGuard()
        ctx = GuardContext(
            tool_name="output",
            tool_args={"text": "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"},
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK
        assert "GitHub" in result.message


class TestCredentialGuardPrivateKeys:

    def test_detects_rsa_private_key(self) -> None:
        guard = CredentialGuard()
        ctx = GuardContext(
            tool_name="output",
            tool_args={"text": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."},
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK
        assert "RSA" in result.message

    def test_detects_openssh_private_key(self) -> None:
        guard = CredentialGuard()
        ctx = GuardContext(
            tool_name="output",
            tool_args={"text": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk..."},
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK


class TestCredentialGuardGeneric:

    def test_detects_bearer_token(self) -> None:
        guard = CredentialGuard()
        ctx = GuardContext(
            tool_name="output",
            tool_args={"text": "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"},
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict in (GuardVerdict.BLOCK, GuardVerdict.WARN)

    def test_detects_jwt_token(self) -> None:
        guard = CredentialGuard()
        ctx = GuardContext(
            tool_name="output",
            tool_args={"text": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"},
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict in (GuardVerdict.BLOCK, GuardVerdict.WARN)
        assert "JWT" in result.message


class TestCredentialGuardParamNames:

    def test_detects_password_param(self) -> None:
        guard = CredentialGuard()
        ctx = GuardContext(
            tool_name="output",
            tool_args={"password": "supersecret123"},
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.WARN
        assert "password" in result.message.lower() or "sensitive" in result.message.lower()

    def test_detects_api_key_param(self) -> None:
        guard = CredentialGuard()
        ctx = GuardContext(
            tool_name="output",
            tool_args={"api_key": "somekeyvalue1234567890"},
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict in (GuardVerdict.WARN, GuardVerdict.BLOCK)

    def test_detects_token_param(self) -> None:
        guard = CredentialGuard()
        ctx = GuardContext(
            tool_name="output",
            tool_args={"token": "abcdef1234567890abcdef"},
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.WARN


class TestCredentialGuardClean:

    def test_clean_output_passes(self) -> None:
        guard = CredentialGuard()
        ctx = GuardContext(tool_name="output", tool_args={"text": "The operation completed successfully."})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.PASS

    def test_normal_file_content_passes(self) -> None:
        guard = CredentialGuard()
        ctx = GuardContext(tool_name="read_file", tool_args={"content": "Hello World\nThis is a normal file."})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.PASS


class TestCredentialGuardRecursive:

    def test_detects_nested_credentials(self) -> None:
        guard = CredentialGuard()
        ctx = GuardContext(
            tool_name="output",
            tool_args={
                "data": {
                    "config": {
                        "key": "AKIAIOSFODNN7EXAMPLE"
                    }
                }
            },
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK

    def test_detects_credentials_in_list(self) -> None:
        guard = CredentialGuard()
        ctx = GuardContext(
            tool_name="output",
            tool_args={"lines": ["normal text", "Key: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"]},
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK


class TestCredentialGuardModelDegradation:

    def test_full_check_degrades_gracefully(self) -> None:
        guard = CredentialGuard()
        ctx = GuardContext(tool_name="output", tool_args={"text": "AKIAIOSFODNN7EXAMPLE"})
        result = guard.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK  # Pure rules, always works

    def test_full_check_clean_passes(self) -> None:
        guard = CredentialGuard()
        ctx = GuardContext(tool_name="output", tool_args={"text": "Normal output"})
        result = guard.check(ctx)
        assert result.verdict == GuardVerdict.PASS
