"""Explicit target scope models and deterministic URL matching."""

from __future__ import annotations

import ipaddress
import posixpath
from urllib.parse import SplitResult, unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ScopeEntry(BaseModel):
    """One explicitly authorized host, with exact path prefixes and exclusions."""

    model_config = ConfigDict(extra="forbid")
    host: str = Field(min_length=1)
    schemes: set[str] = Field(default_factory=lambda: {"http", "https"})
    ports: set[int] = Field(default_factory=set)
    paths: list[str] = Field(default_factory=lambda: ["/"])
    excluded_paths: list[str] = Field(default_factory=list)

    @field_validator("host", mode="before")
    @classmethod
    def normalize_host(cls, value: str) -> str:
        value = str(value).strip().lower().rstrip(".")
        if not value or "/" in value or "://" in value:
            raise ValueError("host must be a hostname or IP address, not a URL")
        ip_cand = value.strip("[]")
        try:
            return ipaddress.ip_address(ip_cand).compressed
        except ValueError:
            try:
                return value.encode("idna").decode("ascii")
            except UnicodeError as exc:
                raise ValueError("host is not a valid hostname") from exc

    @field_validator("schemes", mode="before")
    @classmethod
    def normalize_schemes(cls, values: set[str] | list[str]) -> set[str]:
        result = {str(v).lower() for v in values}
        if not result or not result <= {"http", "https"}:
            raise ValueError("schemes must contain only http and/or https")
        return result

    @field_validator("paths", "excluded_paths", mode="before")
    @classmethod
    def normalize_paths(cls, values: list[str]) -> list[str]:
        result = []
        for path in values:
            path = str(path).strip()
            if not path.startswith("/") or "?" in path or "#" in path:
                raise ValueError("paths must be URL paths beginning with '/'")
            cleaned = posixpath.normpath(path)
            if not cleaned.startswith("/"):
                cleaned = "/" + cleaned
            result.append(cleaned.rstrip("/") or "/")
        return sorted(set(result))

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, values: set[int]) -> set[int]:
        if any(port < 1 or port > 65535 for port in values):
            raise ValueError("ports must be between 1 and 65535")
        return values


class TargetScope(BaseModel):
    """Complete user-supplied scope. An empty scope authorizes nothing."""

    model_config = ConfigDict(extra="forbid")
    entries: list[ScopeEntry] = Field(default_factory=list)
    active_testing: bool = False
    excluded_methods: set[str] = Field(default_factory=set)
    excluded_categories: set[str] = Field(default_factory=set)
    request_timeout_seconds: float = Field(default=10.0, gt=0, le=60)
    requests_per_second: float = Field(default=1.0, gt=0, le=10)

    @field_validator("excluded_methods", mode="before")
    @classmethod
    def normalize_excluded_methods(cls, values: set[str] | list[str]) -> set[str]:
        return {str(value).upper() for value in values}

    @field_validator("excluded_categories", mode="before")
    @classmethod
    def normalize_excluded_categories(cls, values: set[str] | list[str]) -> set[str]:
        return {str(value).lower() for value in values}

    def match(self, url: str) -> tuple[bool, str]:
        """Return whether *url* is explicitly authorized and explain why."""
        try:
            parsed = validate_url_shape(url)
        except ValueError:
            return False, "URL is malformed or contains an invalid port"
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return False, "only absolute HTTP(S) URLs are allowed"
        if parsed.username or parsed.password:
            return False, "URLs containing credentials are forbidden"
        
        raw_host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        try:
            host = ipaddress.ip_address(raw_host.strip("[]")).compressed
        except ValueError:
            host = raw_host

        raw_path = parsed.path or "/"
        # Normalize dot-segments (RFC 3986 section 5.2.4)
        norm_path = posixpath.normpath(raw_path)
        if not norm_path.startswith("/"):
            norm_path = "/" + norm_path

        # Also inspect unquoted path to prevent percent-encoded traversal bypasses (%2e%2e)
        unquoted_path = posixpath.normpath(unquote(raw_path))
        if not unquoted_path.startswith("/"):
            unquoted_path = "/" + unquoted_path

        url_port = parsed.port or (443 if parsed.scheme == "https" else 80)

        for entry in self.entries:
            if host != entry.host or parsed.scheme not in entry.schemes:
                continue
            if entry.ports and url_port not in entry.ports:
                continue

            # Check explicit exclusions against both raw-normalized and unquoted-normalized paths
            def is_excluded(p: str) -> bool:
                return any(p == excluded or p.startswith(excluded.rstrip("/") + "/") for excluded in entry.excluded_paths)

            if is_excluded(norm_path) or is_excluded(unquoted_path):
                return False, "path is explicitly excluded"

            # Check allowed paths
            def is_allowed(p: str) -> bool:
                return any(p == allowed or allowed == "/" or p.startswith(allowed.rstrip("/") + "/") for allowed in entry.paths)

            if is_allowed(norm_path) and is_allowed(unquoted_path):
                return True, "host, scheme, port, and path match configured scope"
        return False, "destination is outside configured scope"


def validate_url_shape(url: str) -> SplitResult:
    """Validate syntax without making a network request."""
    try:
        parsed = urlsplit(url)
        parsed.port
    except ValueError as exc:
        raise ValueError(f"URL contains an invalid port: {exc}") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("URL must not contain credentials or a fragment")
    return parsed

