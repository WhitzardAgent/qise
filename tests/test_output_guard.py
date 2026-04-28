"""Tests for OutputGuard."""

from qise.core.models import GuardContext, GuardVerdict
from qise.guards.output import OutputGuard


class TestOutputGuardPII:

    def test_blocks_ssn(self) -> None:
        guard = OutputGuard()
        ctx = GuardContext(tool_name="output", tool_args={"text": "SSN: 123-45-6789"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK
        assert "SSN" in result.message

    def test_blocks_credit_card(self) -> None:
        guard = OutputGuard()
        ctx = GuardContext(tool_name="output", tool_args={"text": "Card: 4111 1111 1111 1111"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK
        assert "credit" in result.message.lower()

    def test_warns_on_email(self) -> None:
        guard = OutputGuard()
        ctx = GuardContext(tool_name="output", tool_args={"text": "Contact: user@example.com"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict in (GuardVerdict.WARN, GuardVerdict.BLOCK)
        assert "email" in result.message.lower()

    def test_warns_on_phone(self) -> None:
        guard = OutputGuard()
        ctx = GuardContext(tool_name="output", tool_args={"text": "Phone: 555-123-4567"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.WARN


class TestOutputGuardCredentials:

    def test_blocks_aws_key(self) -> None:
        guard = OutputGuard()
        ctx = GuardContext(tool_name="output", tool_args={"text": "Key: AKIAIOSFODNN7EXAMPLE"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK

    def test_blocks_private_key(self) -> None:
        guard = OutputGuard()
        ctx = GuardContext(tool_name="output", tool_args={"text": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK


class TestOutputGuardClean:

    def test_clean_output_passes(self) -> None:
        guard = OutputGuard()
        ctx = GuardContext(tool_name="output", tool_args={"text": "The operation completed successfully."})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.PASS

    def test_ip_address_low_confidence(self) -> None:
        guard = OutputGuard()
        ctx = GuardContext(tool_name="output", tool_args={"text": "Server IP: 192.168.1.1"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict in (GuardVerdict.PASS, GuardVerdict.WARN)


class TestOutputGuardModelDegradation:

    def test_full_check_blocks_pii(self) -> None:
        guard = OutputGuard()
        ctx = GuardContext(tool_name="output", tool_args={"text": "SSN: 123-45-6789"})
        result = guard.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK

    def test_full_check_clean_passes(self) -> None:
        guard = OutputGuard()
        ctx = GuardContext(tool_name="output", tool_args={"text": "Normal output text"})
        result = guard.check(ctx)
        assert result.verdict == GuardVerdict.PASS
