"""Tests for NetworkGuard."""

from qise.core.models import GuardContext, GuardVerdict
from qise.guards.network import NetworkGuard


class TestNetworkGuardSSRF:

    def test_blocks_localhost(self) -> None:
        guard = NetworkGuard()
        ctx = GuardContext(tool_name="http_request", tool_args={"url": "http://127.0.0.1/admin"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK
        assert "SSRF" in result.message

    def test_blocks_private_10(self) -> None:
        guard = NetworkGuard()
        ctx = GuardContext(tool_name="http_request", tool_args={"url": "http://10.0.0.1/internal"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK

    def test_blocks_private_172(self) -> None:
        guard = NetworkGuard()
        ctx = GuardContext(tool_name="http_request", tool_args={"url": "http://172.16.0.1/internal"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK

    def test_blocks_private_192(self) -> None:
        guard = NetworkGuard()
        ctx = GuardContext(tool_name="http_request", tool_args={"url": "http://192.168.1.1/router"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK

    def test_blocks_cloud_metadata(self) -> None:
        guard = NetworkGuard()
        ctx = GuardContext(tool_name="http_request", tool_args={"url": "http://169.254.169.254/latest/meta-data/"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK

    def test_blocks_ipv6_loopback(self) -> None:
        guard = NetworkGuard()
        ctx = GuardContext(tool_name="http_request", tool_args={"url": "http://[::1]/admin"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK


class TestNetworkGuardScheme:

    def test_blocks_file_scheme(self) -> None:
        guard = NetworkGuard()
        ctx = GuardContext(tool_name="fetch", tool_args={"url": "file:///etc/passwd"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK
        assert "scheme" in result.message.lower()

    def test_blocks_ftp_scheme(self) -> None:
        guard = NetworkGuard()
        ctx = GuardContext(tool_name="fetch", tool_args={"url": "ftp://evil.com/payload"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK

    def test_blocks_data_scheme(self) -> None:
        guard = NetworkGuard()
        ctx = GuardContext(tool_name="fetch", tool_args={"url": "data:text/html,<script>alert(1)</script>"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK


class TestNetworkGuardDomainDenylist:

    def test_blocks_denylisted_domain(self) -> None:
        guard = NetworkGuard(deny_domains=["evil.com", "malware.net"])
        ctx = GuardContext(tool_name="http_request", tool_args={"url": "https://evil.com/payload"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK
        assert "domain" in result.message.lower()

    def test_allows_normal_domain(self) -> None:
        guard = NetworkGuard()
        ctx = GuardContext(tool_name="http_request", tool_args={"url": "https://api.github.com/repos"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.PASS


class TestNetworkGuardRedirects:

    def test_warns_on_follow_redirects(self) -> None:
        guard = NetworkGuard()
        ctx = GuardContext(
            tool_name="http_request",
            tool_args={"url": "https://example.com/api", "follow_redirects": True},
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.WARN
        assert "redirect" in result.message.lower()

    def test_no_warn_without_redirects(self) -> None:
        guard = NetworkGuard()
        ctx = GuardContext(
            tool_name="http_request",
            tool_args={"url": "https://example.com/api"},
        )
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.PASS


class TestNetworkGuardClean:

    def test_allows_external_ip(self) -> None:
        guard = NetworkGuard()
        # Use a public IP that's not in any denied CIDR
        ctx = GuardContext(tool_name="http_request", tool_args={"url": "http://1.1.1.1/dns-query"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.PASS

    def test_no_url_passes(self) -> None:
        guard = NetworkGuard()
        ctx = GuardContext(tool_name="bash", tool_args={"command": "ls -la"})
        result = guard.rule_fallback.check(ctx)
        assert result.verdict == GuardVerdict.PASS


class TestNetworkGuardModelDegradation:

    def test_full_check_blocks_ssrf(self) -> None:
        guard = NetworkGuard()
        ctx = GuardContext(tool_name="http_request", tool_args={"url": "http://169.254.169.254/"})
        result = guard.check(ctx)
        assert result.verdict == GuardVerdict.BLOCK

    def test_full_check_clean_passes(self) -> None:
        guard = NetworkGuard()
        ctx = GuardContext(tool_name="http_request", tool_args={"url": "http://1.1.1.1/dns-query"})
        result = guard.check(ctx)
        assert result.verdict == GuardVerdict.PASS
