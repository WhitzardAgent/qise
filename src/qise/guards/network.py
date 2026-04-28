"""NetworkGuard — pure rules guard detecting SSRF and network policy violations.

Blocks internal IP access (SSRF), forbidden URL schemes,
and domain denylist matches. Warns on redirect-following parameters.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any
from urllib.parse import urlparse

from qise.core.guard_base import AIGuardBase, RuleChecker
from qise.core.models import GuardContext, GuardResult, GuardVerdict, RiskAttribution


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_URL_KEYS = frozenset({
    "url", "uri", "endpoint", "host", "address", "target", "server",
})

_REDIRECT_KEYS = frozenset({
    "follow_redirects", "follow_redirect", "allow_redirects",
})

_DENY_CIDRS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

_ALLOWED_SCHEMES = frozenset({"http", "https", ""})  # "" for host-only args

_DENY_DOMAINS: list[str] = []  # Configurable, default empty


# ---------------------------------------------------------------------------
# RuleChecker
# ---------------------------------------------------------------------------


class NetworkGuardRuleChecker(RuleChecker):
    """Deterministic network safety checks."""

    def __init__(self, deny_domains: list[str] | None = None) -> None:
        self.deny_domains = deny_domains or list(_DENY_DOMAINS)

    def check(self, context: GuardContext) -> GuardResult:
        urls = self._extract_urls(context)

        for raw_url in urls:
            result = self._check_url(raw_url, context)
            if result is not None:
                return result

        # Check redirect parameters
        result = self._check_redirects(context)
        if result is not None:
            return result

        return GuardResult(guard_name="network", verdict=GuardVerdict.PASS)

    def _check_url(self, raw_url: str, context: GuardContext) -> GuardResult | None:
        parsed = urlparse(raw_url)
        scheme = parsed.scheme.lower()

        # 1. Forbidden scheme
        if scheme and scheme not in _ALLOWED_SCHEMES:
            return GuardResult(
                guard_name="network",
                verdict=GuardVerdict.BLOCK,
                confidence=0.9,
                message=f"Forbidden URL scheme: {scheme}://",
                risk_attribution=RiskAttribution(
                    risk_source="ssrf",
                    failure_mode="unauthorized_action",
                    real_world_harm="system_compromise",
                    confidence=0.9,
                    reasoning=f"Non-HTTP scheme: {scheme}",
                ),
            )

        # 2. Domain denylist
        hostname = parsed.hostname
        if hostname:
            for deny in self.deny_domains:
                if hostname == deny or hostname.endswith("." + deny):
                    return GuardResult(
                        guard_name="network",
                        verdict=GuardVerdict.BLOCK,
                        confidence=0.9,
                        message=f"Blocked domain: {hostname}",
                        risk_attribution=RiskAttribution(
                            risk_source="network_policy",
                            failure_mode="unauthorized_action",
                            real_world_harm="data_exfiltration",
                            confidence=0.9,
                            reasoning=f"Domain matches denylist entry: {deny}",
                        ),
                    )

        # 3. SSRF: check IP address (direct or resolved)
        if parsed.hostname:
            # Check if hostname is already an IP
            ip_result = self._check_hostname_ip(parsed.hostname)
            if ip_result is not None:
                return ip_result

        return None

    def _check_hostname_ip(self, hostname: str) -> GuardResult | None:
        """Check if a hostname resolves to a blocked IP range."""
        # Try parsing as IP directly
        try:
            ip = ipaddress.ip_address(hostname)
            return self._check_ip_against_cidrs(ip, hostname)
        except ValueError:
            pass

        # Try DNS resolution
        try:
            addrs = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for addr in addrs:
                ip_str = addr[4][0]
                try:
                    ip = ipaddress.ip_address(ip_str)
                    result = self._check_ip_against_cidrs(ip, hostname)
                    if result is not None:
                        return result
                except ValueError:
                    continue
        except (socket.gaierror, socket.timeout, OSError):
            # DNS resolution failed — warn (could be SSRF with bad DNS)
            return GuardResult(
                guard_name="network",
                verdict=GuardVerdict.WARN,
                confidence=0.5,
                message=f"Could not resolve hostname: {hostname}",
            )

        return None

    def _check_ip_against_cidrs(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address, hostname: str) -> GuardResult | None:
        """Check an IP against all denied CIDRs."""
        for cidr in _DENY_CIDRS:
            if ip in cidr:
                return GuardResult(
                    guard_name="network",
                    verdict=GuardVerdict.BLOCK,
                    confidence=0.95,
                    message=f"SSRF blocked: {hostname} resolves to internal IP {ip}",
                    risk_attribution=RiskAttribution(
                        risk_source="ssrf",
                        failure_mode="unauthorized_action",
                        real_world_harm="system_compromise",
                        confidence=0.95,
                        reasoning=f"IP {ip} falls within denied CIDR {cidr}",
                    ),
                )
        return None

    def _check_redirects(self, context: GuardContext) -> GuardResult | None:
        """Warn about redirect-following parameters."""
        for key in _REDIRECT_KEYS:
            val = context.tool_args.get(key)
            if val is True or (isinstance(val, str) and val.lower() in ("true", "yes", "1")):
                return GuardResult(
                    guard_name="network",
                    verdict=GuardVerdict.WARN,
                    confidence=0.6,
                    message="Redirect following enabled — verify final destination",
                )
        return None

    def _extract_urls(self, context: GuardContext) -> list[str]:
        """Extract URLs from tool_args."""
        urls: list[str] = []
        for key in _URL_KEYS:
            val = context.tool_args.get(key)
            if isinstance(val, str) and val:
                urls.append(val)
        return urls


# ---------------------------------------------------------------------------
# NetworkGuard
# ---------------------------------------------------------------------------


class NetworkGuard(AIGuardBase):
    """Pure rules guard detecting SSRF and network policy violations.

    No SLM/LLM needed — CIDR/scheme rules are deterministic.
    """

    name = "network"
    primary_strategy = "rules"
    slm_prompt_template = ""
    llm_prompt_template = None

    def __init__(self, deny_domains: list[str] | None = None) -> None:
        self.rule_fallback = NetworkGuardRuleChecker(deny_domains=deny_domains)
