"""Conservative reflected-XSS detection for explicitly authorized local targets."""

from __future__ import annotations

import time
from collections.abc import Iterable, Sequence
from enum import StrEnum
from html import escape
from hashlib import sha256
from pathlib import Path
from typing import Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field

from .audit import AuditLogger
from .policy import PolicyDecision, PolicyEngine
from .recon import ReconResult


class FindingStatus(StrEnum):
    CANDIDATE = "Candidate"
    NEEDS_VERIFICATION = "Needs verification"
    VERIFIED = "Verified"
    FALSE_POSITIVE = "False positive"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class XssCandidate(BaseModel):
    """An authorized input location derived from passive reconnaissance."""

    model_config = ConfigDict(extra="forbid")
    url: str
    parameter: str = Field(min_length=1, max_length=100)
    location: str = Field(pattern=r"^(query|form)$")
    source_url: str


class ReflectionEvidence(BaseModel):
    """Minimal reproducible evidence; never stores a complete response body."""

    model_config = ConfigDict(extra="forbid")
    payload: str
    reflected: bool
    encoded_reflection: bool = False
    contexts: list[str] = Field(default_factory=list)
    potentially_executable: bool = False
    response_context: str = ""
    response_status: int | None = None


class BrowserVerification(BaseModel):
    """Result of an isolated, marker-only browser verification attempt."""

    model_config = ConfigDict(extra="forbid")
    attempted: bool
    executed: bool = False
    error: str | None = None


class XssFinding(BaseModel):
    """A finding whose status reflects the strength of the evidence."""

    model_config = ConfigDict(extra="forbid")
    finding_id: str
    candidate: XssCandidate
    status: FindingStatus
    confidence: Confidence
    evidence: ReflectionEvidence
    browser_verification: BrowserVerification | None = None
    limitations: list[str] = Field(min_length=1)


class XssAttempt(BaseModel):
    """Record of one approved or rejected payload request."""

    model_config = ConfigDict(extra="forbid")
    candidate: XssCandidate
    payload: str
    policy_allowed: bool
    policy_reason: str
    response_status: int | None = None
    error: str | None = None
    evidence: ReflectionEvidence | None = None


class XssScanResult(BaseModel):
    """Exportable scan result including attempts and non-verified findings."""

    model_config = ConfigDict(extra="forbid")
    started_at: float
    finished_at: float
    candidates: list[XssCandidate]
    attempts: list[XssAttempt]
    findings: list[XssFinding]
    payload_count: int
    max_response_bytes: int

    def export_json(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.model_dump_json(indent=2) + "\n", encoding="utf-8")


class BrowserVerifier(Protocol):
    """Browser verification contract with no tool or shell access for providers."""

    def verify(self, url: str, execution_marker: str) -> BrowserVerification:
        ...


class PlaywrightVerifier:
    """Optional isolated Playwright verifier for the controlled local marker."""

    def __init__(self, policy: PolicyEngine, timeout_ms: int = 5_000) -> None:
        self.policy = policy
        self.timeout_ms = timeout_ms

    def verify(self, url: str, execution_marker: str) -> BrowserVerification:
        try:
            from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
            from playwright.sync_api import sync_playwright
        except ImportError:
            return BrowserVerification(attempted=False, error="Playwright is not installed")
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()

                def guard(route: object, request: object) -> None:
                    request_url = getattr(request, "url")
                    request_method = getattr(request, "method")
                    decision = self.policy.validate_proposal(request_url, category="xss", method=request_method)
                    if request_url == url and decision.allowed:
                        getattr(route, "continue_")()
                    else:
                        getattr(route, "abort")()

                page.route("**/*", guard)
                page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                executed = bool(page.evaluate("marker => window.__bountypilot_xss__ === marker", execution_marker))
                context.close()
                browser.close()
                return BrowserVerification(attempted=True, executed=executed)
        except PlaywrightTimeoutError:
            return BrowserVerification(attempted=True, error="browser verification timed out")
        except Exception as exc:  # browser availability and page errors are non-verification outcomes
            return BrowserVerification(attempted=True, error=f"browser verification failed: {exc.__class__.__name__}")


class XssApprovalRequired(PermissionError):
    """Raised before any XSS request when explicit operator approval is absent."""


class XssConfig(BaseModel):
    """Conservative bounds and harmless controlled payloads."""

    model_config = ConfigDict(extra="forbid")
    payloads: list[str] = Field(default_factory=lambda: [
        "bountypilot-xss-reflection-marker",
        '"><svg/onload=window.__bountypilot_xss__=\'bountypilot-xss-executed\'>',
    ])
    max_payloads: int = Field(default=2, ge=1, le=3)
    max_response_bytes: int = Field(default=256_000, ge=1, le=2_000_000)


class XssScanner:
    """Test only recon-derived candidates after explicit active approval."""

    SENSITIVE_PARAMETER_NAMES = {"password", "passwd", "token", "csrf", "xsrf", "session", "cookie"}

    def __init__(self, scope: object, policy: PolicyEngine, audit: AuditLogger, config: XssConfig | None = None, browser_verifier: BrowserVerifier | None = None) -> None:
        self.scope = scope
        self.policy = policy
        self.audit = audit
        self.config = config or XssConfig()
        self.browser_verifier = browser_verifier

    @classmethod
    def candidates_from_recon(cls, recon: ReconResult, policy: PolicyEngine) -> list[XssCandidate]:
        candidates: dict[tuple[str, str, str], XssCandidate] = {}

        def add_url(url: str, source_url: str) -> None:
            parsed = urlsplit(url)
            for parameter, _value in parse_qsl(parsed.query, keep_blank_values=True):
                if parameter.lower() not in cls.SENSITIVE_PARAMETER_NAMES:
                    candidate = XssCandidate(url=url, parameter=parameter, location="query", source_url=source_url)
                    if policy.validate_proposal(url, category="passive_recon", method="GET").allowed:
                        candidates[(url, parameter, "query")] = candidate

        for page in recon.pages:
            if page.error:
                continue
            add_url(page.url, page.url)
            for link in page.links:
                if link.in_scope:
                    add_url(link.url, page.url)
            for form in page.forms:
                if not form.in_scope or form.method != "GET" or not form.requestable:
                    continue
                for parameter in form.input_names:
                    if parameter.lower() not in cls.SENSITIVE_PARAMETER_NAMES:
                        candidate = XssCandidate(url=form.action, parameter=parameter, location="form", source_url=page.url)
                        candidates[(form.action, parameter, "form")] = candidate
        return sorted(candidates.values(), key=lambda candidate: (candidate.url, candidate.parameter, candidate.location))

    def scan(self, recon: ReconResult, *, confirmed: bool = False) -> XssScanResult:
        if not confirmed:
            raise XssApprovalRequired("explicit approval is required; rerun with --approve after reviewing the plan")
        started_at = time.time()
        candidates = self.candidates_from_recon(recon, self.policy)
        attempts: list[XssAttempt] = []
        findings: list[XssFinding] = []
        payloads = self.config.payloads[: self.config.max_payloads]
        timeout = httpx.Timeout(getattr(self.scope, "request_timeout_seconds", 10.0))
        with httpx.Client(timeout=timeout, follow_redirects=False, headers={"User-Agent": "BountyPilot-XSS/0.1"}) as client:
            for candidate in candidates:
                for payload in payloads:
                    test_url = _inject_parameter(candidate.url, candidate.parameter, payload)
                    decision = self._authorize(test_url)
                    self.audit.record("xss.policy", "approved" if decision.allowed else "rejected", url=test_url, parameter=candidate.parameter, reason=decision.reason)
                    if not decision.allowed:
                        attempts.append(XssAttempt(candidate=candidate, payload=payload, policy_allowed=False, policy_reason=decision.reason))
                        continue
                    attempt = self._request(client, candidate, payload, test_url)
                    attempts.append(attempt)
                    if attempt.evidence and attempt.evidence.reflected:
                        finding = self._finding(candidate, payload, attempt.evidence)
                        if finding.evidence.potentially_executable and self.browser_verifier:
                            verification = self.browser_verifier.verify(test_url, "bountypilot-xss-executed")
                            finding = self._apply_browser_result(finding, verification)
                        findings.append(finding)
        return XssScanResult(started_at=started_at, finished_at=time.time(), candidates=candidates, attempts=attempts, findings=findings, payload_count=len(payloads), max_response_bytes=self.config.max_response_bytes)

    def _authorize(self, url: str) -> PolicyDecision:
        decision = self.policy.authorize(url, active=True, confirmed=True, method="GET", category="xss")
        attempts = 0
        while not decision.allowed and decision.retry_after > 0 and attempts < 3:
            time.sleep(decision.retry_after + 0.01)
            attempts += 1
            decision = self.policy.authorize(url, active=True, confirmed=True, method="GET", category="xss")
        return decision

    def _request(self, client: httpx.Client, candidate: XssCandidate, payload: str, test_url: str) -> XssAttempt:
        self.audit.record("xss.request", "started", url=test_url, parameter=candidate.parameter)
        try:
            with client.stream("GET", test_url) as response:
                body = bytearray()
                for chunk in response.iter_bytes():
                    remaining = self.config.max_response_bytes - len(body)
                    if remaining <= 0:
                        break
                    body.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        break
                location = response.headers.get("location")
                if location:
                    redirect_url = str(httpx.URL(test_url).join(location))
                    redirect_decision = self.policy.validate_proposal(redirect_url, category="xss", method="GET")
                    self.audit.record("xss.redirect", "approved" if redirect_decision.allowed else "rejected", url=redirect_url, source=test_url, reason=redirect_decision.reason)
                content_type = response.headers.get("content-type", "")
                evidence = _reflection_evidence(payload, bytes(body), response.status_code, content_type)
                self.audit.record("xss.request", "completed", url=test_url, parameter=candidate.parameter, status_code=response.status_code, reflected=evidence.reflected)
                return XssAttempt(candidate=candidate, payload=payload, policy_allowed=True, policy_reason="request approved by deterministic policy", response_status=response.status_code, evidence=evidence)

        except httpx.TimeoutException:
            error = "request timed out"
        except httpx.RequestError as exc:
            error = f"request failed: {exc.__class__.__name__}"
        self.audit.record("xss.request", "failed", url=test_url, parameter=candidate.parameter, reason=error)
        return XssAttempt(candidate=candidate, payload=payload, policy_allowed=True, policy_reason="request approved by deterministic policy", error=error)

    def _finding(self, candidate: XssCandidate, payload: str, evidence: ReflectionEvidence) -> XssFinding:
        if evidence.potentially_executable:
            status, confidence = FindingStatus.NEEDS_VERIFICATION, Confidence.MEDIUM
            limitations = ["HTTP reflection is not proof of script execution.", "Browser verification was not run or did not complete."]
        else:
            status, confidence = FindingStatus.CANDIDATE, Confidence.LOW
            limitations = ["The input was reflected as ordinary text; no executable context was established.", "Review encoding and application context before further testing."]
        digest = sha256(f"{candidate.url}\x00{candidate.parameter}\x00{payload}".encode()).hexdigest()[:12]
        return XssFinding(finding_id=f"xss-{digest}", candidate=candidate, status=status, confidence=confidence, evidence=evidence, limitations=limitations)

    @staticmethod
    def _apply_browser_result(finding: XssFinding, verification: BrowserVerification) -> XssFinding:
        if verification.executed:
            return finding.model_copy(update={"status": FindingStatus.VERIFIED, "confidence": Confidence.HIGH, "browser_verification": verification, "limitations": ["Only the controlled marker executed in an isolated browser context.", "No cookies, credentials, or user data were accessed."]})
        if verification.attempted and not verification.error:
            return finding.model_copy(update={"status": FindingStatus.FALSE_POSITIVE, "confidence": Confidence.MEDIUM, "browser_verification": verification, "limitations": ["The controlled marker did not execute in the isolated browser context.", "Other browser contexts or application states were not tested."]})
        return finding.model_copy(update={"browser_verification": verification})


def _inject_parameter(url: str, parameter: str, payload: str) -> str:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    output: list[tuple[str, str]] = []
    for key, value in pairs:
        if key == parameter and not replaced:
            output.append((key, payload))
            replaced = True
        else:
            output.append((key, value))
    if not replaced:
        output.append((parameter, payload))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(output), ""))


def _reflection_evidence(payload: str, body: bytes, status_code: int, content_type: str = "") -> ReflectionEvidence:
    text = body.decode("utf-8", errors="replace")
    encoded = escape(payload, quote=True)
    content_type_lower = content_type.lower()
    is_html_compatible = (
        not content_type_lower
        or "html" in content_type_lower
        or "xml" in content_type_lower
        or "svg" in content_type_lower
    )

    if payload in text:
        index = text.find(payload)
        before = text[:index].lower()
        contexts: set[str] = set()

        if not is_html_compatible:
            contexts.add("non_html_response")
            potentially_executable = False
        else:
            in_comment = before.rfind("<!--") > before.rfind("-->")
            if in_comment:
                contexts.add("html_comment")
                potentially_executable = "-->" in payload
            elif before.rfind("<script") > before.rfind("</script"):
                contexts.add("script")
                potentially_executable = True
            elif before.rfind("<") > before.rfind(">"):
                contexts.add("attribute_or_tag")
                potentially_executable = True
            else:
                contexts.add("html_text")
                potentially_executable = False

            if "<svg" in payload.lower() or "<script" in payload.lower() or "onerror=" in payload.lower() or "onload=" in payload.lower():
                contexts.add("payload_markup")
                if not in_comment or "-->" in payload:
                    potentially_executable = True

        snippet = text[max(0, index - 120): min(len(text), index + len(payload) + 120)]
        return ReflectionEvidence(
            payload=payload,
            reflected=True,
            contexts=sorted(contexts),
            potentially_executable=potentially_executable,
            response_context=snippet[:500],
            response_status=status_code,
        )
    if encoded in text:
        index = text.find(encoded)
        return ReflectionEvidence(
            payload=payload,
            reflected=True,
            encoded_reflection=True,
            contexts=["html_encoded"],
            response_context=text[max(0, index - 120): index + len(encoded) + 120][:500],
            response_status=status_code,
        )
    return ReflectionEvidence(payload=payload, reflected=False, response_status=status_code)

