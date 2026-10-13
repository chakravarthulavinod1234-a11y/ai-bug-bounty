"""Safety policy: AI suggestions never bypass these deterministic decisions."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

from .scope import TargetScope, validate_url_shape


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    retry_after: float = 0.0


class PolicyEngine:
    """Gate every request using explicit scope, mode, rate, and stop state."""

    SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
    SUPPORTED_CATEGORIES = {"passive_recon", "xss", "sqli"}
    ACTIVE_CATEGORIES = {"xss", "sqli"}

    def __init__(self, scope: TargetScope) -> None:
        self.scope = scope
        self._stopped = threading.Event()
        self._lock = threading.Lock()
        self._next_request_at = 0.0

    def stop(self) -> None:
        self._stopped.set()

    def reset_stop(self) -> None:
        self._stopped.clear()

    @property
    def stopped(self) -> bool:
        return self._stopped.is_set()

    def authorize(
        self,
        url: str,
        *,
        active: bool = False,
        confirmed: bool = False,
        method: str = "GET",
        category: str = "passive_recon",
    ) -> PolicyDecision:
        category = category.lower()
        method = method.upper()
        try:
            validate_url_shape(url)
        except ValueError as exc:
            return PolicyDecision(False, str(exc))
        if self.stopped:
            return PolicyDecision(False, "kill switch is active")
        dest_valid, dest_reason = self.validate_destination_ip(url)
        if not dest_valid:
            return PolicyDecision(False, dest_reason)
        if category not in self.SUPPORTED_CATEGORIES:
            return PolicyDecision(False, "unsupported test category")
        if category in self.scope.excluded_categories:
            return PolicyDecision(False, "test category is explicitly excluded")
        if method in self.scope.excluded_methods:
            return PolicyDecision(False, "HTTP method is explicitly excluded")
        if method not in self.SAFE_METHODS:
            return PolicyDecision(False, "only safe HTTP methods are permitted in Milestone 1")
        in_scope, reason = self.scope.match(url)
        if not in_scope:
            return PolicyDecision(False, reason)
        if category in self.ACTIVE_CATEGORIES and not active:
            return PolicyDecision(False, "active test categories require active=True")
        if active and not self.scope.active_testing:
            return PolicyDecision(False, "active testing is disabled in scope configuration")
        if active and not confirmed:
            return PolicyDecision(False, "explicit confirmation is required before active testing")
        with self._lock:
            now = time.monotonic()
            wait = max(0.0, self._next_request_at - now)
            if wait:
                return PolicyDecision(False, "conservative request-rate limit would be exceeded", wait)
            self._next_request_at = now + (1.0 / self.scope.requests_per_second)
        return PolicyDecision(True, "request approved by deterministic policy")

    def validate_proposal(self, url: str, *, category: str, method: str = "GET") -> PolicyDecision:
        """Validate a proposed action without authorizing its execution.

        This deliberately skips rate accounting and active confirmation. The
        latter belongs to ``authorize`` at execution time.
        """
        category = category.lower()
        method = method.upper()
        try:
            validate_url_shape(url)
        except ValueError as exc:
            return PolicyDecision(False, str(exc))
        if self.stopped:
            return PolicyDecision(False, "kill switch is active")
        dest_valid, dest_reason = self.validate_destination_ip(url)
        if not dest_valid:
            return PolicyDecision(False, dest_reason)
        if category not in self.SUPPORTED_CATEGORIES:
            return PolicyDecision(False, "unsupported test category")
        if category in self.scope.excluded_categories:
            return PolicyDecision(False, "test category is explicitly excluded")
        if method in self.scope.excluded_methods:
            return PolicyDecision(False, "HTTP method is explicitly excluded")
        if method not in self.SAFE_METHODS:
            return PolicyDecision(False, "only safe HTTP methods are permitted in Milestone 1")
        if category in self.ACTIVE_CATEGORIES and not self.scope.active_testing:
            return PolicyDecision(False, "active testing is disabled in scope configuration")
        in_scope, reason = self.scope.match(url)
        if not in_scope:
            return PolicyDecision(False, reason)
        return PolicyDecision(True, "proposal accepted by deterministic policy; execution still requires authorization")

    def authorize_redirect(self, redirect_url: str) -> PolicyDecision:
        """Redirect destinations are independently checked; scope is never inherited."""
        return self.validate_proposal(redirect_url, category="passive_recon", method="GET")

    @staticmethod
    def validate_destination_ip(url: str) -> tuple[bool, str]:
        """Validate destination host to block cloud metadata endpoints and unsafe IP ranges."""
        import ipaddress
        try:
            parsed = urlsplit(url)
            hostname = parsed.hostname
            if not hostname:
                return False, "missing hostname"
            clean = hostname.strip("[]").lower()
            if clean in {"instance-data", "metadata.google.internal", "metadata"}:
                return False, "requests to cloud metadata endpoints are strictly forbidden"
            try:
                ip = ipaddress.ip_address(clean)
                if ip.is_link_local:
                    return False, "requests to link-local metadata addresses are strictly forbidden"
                if ip.is_multicast or ip.is_unspecified:
                    return False, "requests to multicast or unspecified IP addresses are forbidden"
            except ValueError:
                pass
        except Exception as exc:
            return False, f"destination validation failed: {exc}"
        return True, "destination is valid"

    @staticmethod
    def is_explicit_local_target(url: str) -> bool:
        import ipaddress
        try:
            parsed = urlsplit(url)
            host = (parsed.hostname or "").strip("[]").lower()
            if host in {"localhost", "127.0.0.1", "::1"}:
                return True
            try:
                return ipaddress.ip_address(host).is_loopback
            except ValueError:
                return False
        except Exception:
            return False

