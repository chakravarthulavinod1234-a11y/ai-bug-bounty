"""Bounded, passive reconnaissance for explicitly authorized targets."""

from __future__ import annotations

import json
import time
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field

from .audit import AuditLogger
from .policy import PolicyDecision, PolicyEngine
from .scope import TargetScope


class DiscoveredLink(BaseModel):
    """A link discovered on an in-scope page."""

    model_config = ConfigDict(extra="forbid")
    url: str
    text: str = ""
    in_scope: bool


class DiscoveredForm(BaseModel):
    """A form discovered without submitting it."""

    model_config = ConfigDict(extra="forbid")
    action: str
    method: str
    input_names: list[str] = Field(default_factory=list)
    in_scope: bool
    requestable: bool


class ReconPage(BaseModel):
    """Passive observations from one requested page."""

    model_config = ConfigDict(extra="forbid")
    url: str
    depth: int = Field(ge=0)
    status_code: int | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    title: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)
    links: list[DiscoveredLink] = Field(default_factory=list)
    forms: list[DiscoveredForm] = Field(default_factory=list)
    technology_indicators: list[str] = Field(default_factory=list)
    bytes_read: int = 0
    truncated: bool = False
    error: str | None = None


class ReconResult(BaseModel):
    """JSON-exportable bounded reconnaissance result."""

    model_config = ConfigDict(extra="forbid")
    started_at: float
    finished_at: float
    pages: list[ReconPage]
    discovered_urls: list[str]
    requested_url_count: int
    max_depth: int
    max_urls: int
    max_page_bytes: int

    def export_json(self, path: Path) -> None:
        """Write the complete result as UTF-8 JSON."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.model_dump_json(indent=2) + "\n", encoding="utf-8")


@dataclass(frozen=True)
class ReconLimits:
    """Hard bounds for a crawl."""

    max_depth: int = 1
    max_urls: int = 25
    max_page_bytes: int = 512_000

    def __post_init__(self) -> None:
        if self.max_depth < 0:
            raise ValueError("max_depth must be non-negative")
        if self.max_urls < 1:
            raise ValueError("max_urls must be at least 1")
        if self.max_page_bytes < 1:
            raise ValueError("max_page_bytes must be at least 1")


class _PageParser(HTMLParser):
    """Extract basic metadata without executing page content."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title: str | None = None
        self.metadata: dict[str, str] = {}
        self.links: list[tuple[str, str]] = []
        self.forms: list[tuple[str, str, list[str]]] = []
        self._in_title = False
        self._title_parts: list[str] = []
        self._in_link_text = False
        self._link_href = ""
        self._link_parts: list[str] = []
        self._current_form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()
        if tag == "title":
            self._in_title = True
            self._title_parts = []
        elif tag == "meta":
            name = values.get("name") or values.get("property")
            content = values.get("content")
            if name and content:
                self.metadata[name.lower()] = content[:500]
        elif tag == "a" and values.get("href"):
            self._in_link_text = True
            self._link_href = values["href"]
            self._link_parts = []
        elif tag == "form":
            self._current_form = {
                "action": values.get("action", ""),
                "method": values.get("method", "GET").upper(),
                "input_names": [],
            }
        elif tag == "input" and self._current_form is not None and values.get("name"):
            input_names = self._current_form["input_names"]
            assert isinstance(input_names, list)
            input_names.append(values["name"])

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title" and self._in_title:
            value = " ".join("".join(self._title_parts).split())
            self.title = value[:500] or None
            self._in_title = False
        elif tag == "a" and self._in_link_text:
            text = " ".join("".join(self._link_parts).split())[:300]
            self.links.append((self._link_href, text))
            self._in_link_text = False
        elif tag == "form" and self._current_form is not None:
            self.forms.append((
                str(self._current_form["action"]),
                str(self._current_form["method"]),
                list(self._current_form["input_names"]),
            ))
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)
        elif self._in_link_text:
            self._link_parts.append(data)


class Reconnaissance:
    """Perform a small passive crawl behind the deterministic policy engine."""

    def __init__(self, scope: TargetScope, policy: PolicyEngine, audit: AuditLogger, limits: ReconLimits | None = None) -> None:
        self.scope = scope
        self.policy = policy
        self.audit = audit
        self.limits = limits or ReconLimits()

    def authorized_start_urls(self) -> list[str]:
        """Build bounded seeds from configured scope entries only."""
        urls: set[str] = set()
        for entry in self.scope.entries:
            for scheme in sorted(entry.schemes):
                ports: Iterable[int | None] = sorted(entry.ports) if entry.ports else [None]
                for port in ports:
                    host = f"[{entry.host}]" if ":" in entry.host and not entry.host.startswith("[") else entry.host
                    netloc = host if port is None else f"{host}:{port}"
                    for path in entry.paths:
                        urls.add(f"{scheme}://{netloc}{path}")
        return sorted(urls)

    def run(self, start_urls: Iterable[str] | None = None) -> ReconResult:
        started_at = time.time()
        queue: deque[tuple[str, int]] = deque()
        queued: set[str] = set()
        for url in (start_urls or self.authorized_start_urls()):
            decision = self.policy.validate_proposal(url, category="passive_recon", method="GET")
            self.audit.record("recon.seed", "approved" if decision.allowed else "rejected", url=url, reason=decision.reason)
            if decision.allowed:
                queue.append((url, 0))
                queued.add(url)
        visited: set[str] = set()
        discovered: set[str] = set(queued)
        pages: list[ReconPage] = []

        timeout = httpx.Timeout(self.scope.request_timeout_seconds)
        with httpx.Client(timeout=timeout, follow_redirects=False, headers={"User-Agent": "BountyPilot-Recon/0.1"}) as client:
            while queue and len(visited) < self.limits.max_urls:
                url, depth = queue.popleft()
                if url in visited:
                    continue
                visited.add(url)
                decision = self._authorize_request(url, depth)
                if not decision.allowed:
                    self.audit.record("recon.request", "rejected", url=url, depth=depth, reason=decision.reason)
                    continue
                page = self._request_page(client, url, depth)
                pages.append(page)
                if page.status_code is None:
                    continue
                location = page.headers.get("location")
                if location:
                    self._consider_destination(url, location, depth, queue, queued, discovered, "redirect")
                for link in page.links:
                    self._consider_destination(url, link.url, depth, queue, queued, discovered, "link")

        return ReconResult(
            started_at=started_at,
            finished_at=time.time(),
            pages=pages,
            discovered_urls=sorted(discovered),
            requested_url_count=len(visited),
            max_depth=self.limits.max_depth,
            max_urls=self.limits.max_urls,
            max_page_bytes=self.limits.max_page_bytes,
        )

    def _authorize_request(self, url: str, depth: int) -> PolicyDecision:
        decision = self.policy.authorize(url, category="passive_recon", method="GET")
        attempts = 0
        while not decision.allowed and decision.retry_after > 0 and attempts < 3:
            time.sleep(decision.retry_after + 0.01)
            attempts += 1
            decision = self.policy.authorize(url, category="passive_recon", method="GET")
        self.audit.record("recon.policy", "approved" if decision.allowed else "rejected", url=url, depth=depth, reason=decision.reason)
        return decision


    def _request_page(self, client: httpx.Client, url: str, depth: int) -> ReconPage:
        self.audit.record("recon.request", "started", url=url, depth=depth)
        try:
            with client.stream("GET", url) as response:
                headers = _safe_headers(response.headers)
                content = bytearray()
                truncated = False
                for chunk in response.iter_bytes():
                    remaining = self.limits.max_page_bytes - len(content)
                    if remaining <= 0:
                        truncated = True
                        break
                    content.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        truncated = True
                        break
                page = self._parse_page(url, depth, response.status_code, headers, bytes(content), truncated)
                self.audit.record("recon.request", "completed", url=url, depth=depth, status_code=response.status_code, bytes_read=len(content))
                return page
        except httpx.TimeoutException as exc:
            message = f"request timed out: {exc.__class__.__name__}"
        except httpx.RequestError as exc:
            message = f"request failed: {exc.__class__.__name__}"
        self.audit.record("recon.request", "failed", url=url, depth=depth, reason=message)
        return ReconPage(url=url, depth=depth, error=message)

    def _parse_page(self, url: str, depth: int, status_code: int, headers: dict[str, str], content: bytes, truncated: bool) -> ReconPage:
        content_type = headers.get("content-type", "").lower()
        parser = _PageParser()
        if "html" in content_type or content.lstrip().lower().startswith((b"<!doctype html", b"<html", b"<head")):
            try:
                parser.feed(content.decode("utf-8", errors="replace"))
            except Exception:
                pass
        links = []
        for href, text in parser.links:
            destination = urljoin(url, href)
            decision = self.policy.validate_proposal(destination, category="passive_recon", method="GET")
            links.append(DiscoveredLink(url=destination, text=text, in_scope=decision.allowed))
        forms = []
        for action, method, input_names in parser.forms:
            destination = urljoin(url, action or url)
            decision = self.policy.validate_proposal(destination, category="passive_recon", method=method)
            forms.append(DiscoveredForm(action=destination, method=method, input_names=input_names, in_scope=self.scope.match(destination)[0], requestable=decision.allowed))
        return ReconPage(
            url=url,
            depth=depth,
            status_code=status_code,
            headers=headers,
            title=parser.title,
            metadata=parser.metadata,
            links=links,
            forms=forms,
            technology_indicators=_technology_indicators(headers, parser.metadata, content),
            bytes_read=len(content),
            truncated=truncated,
        )

    def _consider_destination(self, base_url: str, destination: str, depth: int, queue: deque[tuple[str, int]], queued: set[str], discovered: set[str], kind: str) -> None:
        absolute = urljoin(base_url, destination)
        decision = self.policy.authorize_redirect(absolute)
        self.audit.record("recon.destination", "approved" if decision.allowed else "rejected", url=absolute, source=base_url, kind=kind, reason=decision.reason)
        if not decision.allowed or depth >= self.limits.max_depth or absolute in queued or len(queued) >= self.limits.max_urls:
            return
        queued.add(absolute)
        discovered.add(absolute)
        queue.append((absolute, depth + 1))


def _technology_indicators(headers: dict[str, str], metadata: dict[str, str], content: bytes) -> list[str]:
    indicators: set[str] = set()
    for header in ("server", "x-powered-by", "via", "x-generator"):
        if headers.get(header):
            indicators.add(f"{header}: {headers[header]}")
    generator = metadata.get("generator")
    if generator:
        indicators.add(f"meta generator: {generator}")
    lowered = content[:200_000].lower()
    signatures = {
        b"wp-content": "WordPress indicator",
        b"__next_data__": "Next.js indicator",
        b"data-reactroot": "React indicator",
        b"ng-version": "Angular indicator",
    }
    for signature, label in signatures.items():
        if signature in lowered:
            indicators.add(label)
    return sorted(indicators)


def _safe_headers(headers: httpx.Headers) -> dict[str, str]:
    """Keep useful response metadata while avoiding credential-like values."""
    redacted = {"set-cookie", "cookie", "authorization", "proxy-authenticate", "proxy-authorization"}
    return {key.lower(): ("[redacted]" if key.lower() in redacted else value) for key, value in headers.items()}


def result_to_json(result: ReconResult) -> str:
    """Return an exportable JSON representation for API and CLI callers."""
    return json.dumps(result.model_dump(mode="json"), indent=2)
