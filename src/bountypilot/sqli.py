"""Conservative SQL injection detection for authorized local labs."""

from __future__ import annotations

import hashlib
import re
import time
from enum import StrEnum
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field

from .audit import AuditLogger
from .policy import PolicyDecision, PolicyEngine
from .recon import ReconResult
from .xss import Confidence, FindingStatus


class SqlInjectionApprovalRequired(PermissionError):
    """Raised before any SQLi request when explicit approval is absent."""


class SqlInjectionCandidate(BaseModel):
    """An input location derived from approved reconnaissance output."""

    model_config = ConfigDict(extra="forbid")
    url: str
    parameter: str = Field(min_length=1, max_length=100)
    location: str = Field(pattern=r"^(query|form)$")
    source_url: str


class ResponseObservation(BaseModel):
    """Bounded response facts used for comparison; no full body is stored."""

    model_config = ConfigDict(extra="forbid")
    label: str
    status_code: int | None
    body_length: int = 0
    body_digest: str = ""
    sql_error_signatures: list[str] = Field(default_factory=list)
    response_context: str = ""
    timed_out: bool = False


class SqlInjectionEvidence(BaseModel):
    """Reproducible comparison evidence and its limitations."""

    model_config = ConfigDict(extra="forbid")
    baseline: ResponseObservation
    probes: list[ResponseObservation]
    consistent_difference: bool
    database_error_observed: bool
    explanation: str


class SqlInjectionFinding(BaseModel):
    """Status-aware SQLi result; evidence alone cannot make it verified."""

    model_config = ConfigDict(extra="forbid")
    finding_id: str
    candidate: SqlInjectionCandidate
    status: FindingStatus
    confidence: Confidence
    evidence: SqlInjectionEvidence
    limitations: list[str] = Field(min_length=1)


class SqlInjectionAttempt(BaseModel):
    """One baseline or controlled probe request."""

    model_config = ConfigDict(extra="forbid")
    candidate: SqlInjectionCandidate
    label: str
    input_value: str
    policy_allowed: bool
    policy_reason: str
    observation: ResponseObservation | None = None
    error: str | None = None


class SqlInjectionScanResult(BaseModel):
    """Exportable bounded SQLi scan output."""

    model_config = ConfigDict(extra="forbid")
    started_at: float
    finished_at: float
    candidates: list[SqlInjectionCandidate]
    attempts: list[SqlInjectionAttempt]
    findings: list[SqlInjectionFinding]
    test_case_count: int
    max_response_bytes: int

    def export_json(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.model_dump_json(indent=2) + "\n", encoding="utf-8")


class SqlInjectionConfig(BaseModel):
    """Small non-destructive test set and response limits."""

    model_config = ConfigDict(extra="forbid")
    test_cases: list[tuple[str, str]] = Field(default_factory=lambda: [
        ("quote", "'"),
        ("double_quote", '"'),
    ])
    max_test_cases: int = Field(default=2, ge=1, le=2)
    max_response_bytes: int = Field(default=256_000, ge=1, le=2_000_000)
    min_length_delta: int = Field(default=40, ge=1, le=100_000)


class SqlInjectionScanner:
    """Compare a baseline with bounded harmless perturbations."""

    SENSITIVE_PARAMETER_NAMES = {"password", "passwd", "token", "csrf", "xsrf", "session", "cookie", "secret"}
    SQL_ERROR_PATTERNS = {
        "mysql": re.compile(r"you have an error in your sql syntax|mysql_fetch|mysqli?_", re.I),
        "postgresql": re.compile(r"postgresql|pg_query|syntax error at or near", re.I),
        "sqlite": re.compile(r"sqlite error|sqlite3::|near \"[^\"]+\": syntax error", re.I),
        "mssql": re.compile(r"sql server|odbc sql server|unclosed quotation mark", re.I),
        "oracle": re.compile(r"ora-\d{4,5}|oracle error", re.I),
    }

    def __init__(self, scope: object, policy: PolicyEngine, audit: AuditLogger, config: SqlInjectionConfig | None = None) -> None:
        self.scope = scope
        self.policy = policy
        self.audit = audit
        self.config = config or SqlInjectionConfig()

    @classmethod
    def candidates_from_recon(cls, recon: ReconResult, policy: PolicyEngine) -> list[SqlInjectionCandidate]:
        candidates: dict[tuple[str, str, str], SqlInjectionCandidate] = {}

        def add_url(url: str, source_url: str) -> None:
            parsed = urlsplit(url)
            for parameter, _value in parse_qsl(parsed.query, keep_blank_values=True):
                if parameter.lower() in cls.SENSITIVE_PARAMETER_NAMES:
                    continue
                if policy.validate_proposal(url, category="passive_recon", method="GET").allowed:
                    candidates[(url, parameter, "query")] = SqlInjectionCandidate(url=url, parameter=parameter, location="query", source_url=source_url)

        for page in recon.pages:
            if page.error:
                continue
            add_url(page.url, page.url)
            for link in page.links:
                if link.in_scope:
                    add_url(link.url, page.url)
            for form in page.forms:
                if form.in_scope and form.requestable and form.method == "GET":
                    for parameter in form.input_names:
                        if parameter.lower() not in cls.SENSITIVE_PARAMETER_NAMES:
                            candidates[(form.action, parameter, "form")] = SqlInjectionCandidate(url=form.action, parameter=parameter, location="form", source_url=page.url)
        return sorted(candidates.values(), key=lambda item: (item.url, item.parameter, item.location))

    def scan(self, recon: ReconResult, *, confirmed: bool = False) -> SqlInjectionScanResult:
        if not confirmed:
            raise SqlInjectionApprovalRequired("explicit approval is required; rerun with --approve after reviewing the candidates")
        started_at = time.time()
        candidates = self.candidates_from_recon(recon, self.policy)
        attempts: list[SqlInjectionAttempt] = []
        findings: list[SqlInjectionFinding] = []
        test_cases = self.config.test_cases[: self.config.max_test_cases]
        timeout = httpx.Timeout(getattr(self.scope, "request_timeout_seconds", 10.0))
        with httpx.Client(timeout=timeout, follow_redirects=False, headers={"User-Agent": "BountyPilot-SQLi/0.1"}) as client:
            for candidate in candidates:
                baseline_url = _inject_parameter(candidate.url, candidate.parameter, _baseline_value(candidate))
                baseline_attempt = self._request(client, candidate, "baseline", _baseline_value(candidate), baseline_url)
                attempts.append(baseline_attempt)
                if baseline_attempt.observation is None:
                    continue
                probe_attempts: list[SqlInjectionAttempt] = []
                for label, value in test_cases:
                    probe_url = _inject_parameter(candidate.url, candidate.parameter, value)
                    probe_attempt = self._request(client, candidate, label, value, probe_url)
                    attempts.append(probe_attempt)
                    probe_attempts.append(probe_attempt)
                observations = [attempt.observation for attempt in probe_attempts if attempt.observation is not None]
                if observations:
                    finding = self._evaluate(candidate, baseline_attempt.observation, observations)
                    if finding is not None:
                        findings.append(finding)
        return SqlInjectionScanResult(started_at=started_at, finished_at=time.time(), candidates=candidates, attempts=attempts, findings=findings, test_case_count=len(test_cases), max_response_bytes=self.config.max_response_bytes)

    def _authorize(self, url: str) -> PolicyDecision:
        decision = self.policy.authorize(url, active=True, confirmed=True, method="GET", category="sqli")
        attempts = 0
        while not decision.allowed and decision.retry_after > 0 and attempts < 3:
            time.sleep(decision.retry_after + 0.01)
            attempts += 1
            decision = self.policy.authorize(url, active=True, confirmed=True, method="GET", category="sqli")
        return decision

    def _request(self, client: httpx.Client, candidate: SqlInjectionCandidate, label: str, input_value: str, url: str) -> SqlInjectionAttempt:
        decision = self._authorize(url)
        self.audit.record("sqli.policy", "approved" if decision.allowed else "rejected", url=url, parameter=candidate.parameter, label=label, reason=decision.reason)
        if not decision.allowed:
            return SqlInjectionAttempt(candidate=candidate, label=label, input_value=input_value, policy_allowed=False, policy_reason=decision.reason)
        self.audit.record("sqli.request", "started", url=url, parameter=candidate.parameter, label=label)
        try:
            with client.stream("GET", url) as response:
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
                    redirect_url = str(httpx.URL(url).join(location))
                    redirect_decision = self.policy.validate_proposal(redirect_url, category="sqli", method="GET")
                    self.audit.record("sqli.redirect", "approved" if redirect_decision.allowed else "rejected", url=redirect_url, source=url, reason=redirect_decision.reason)
                observation = _observe(label, response.status_code, bytes(body), self.SQL_ERROR_PATTERNS)
                self.audit.record("sqli.request", "completed", url=url, parameter=candidate.parameter, label=label, status_code=response.status_code, body_length=observation.body_length, error_signatures=observation.sql_error_signatures)
                return SqlInjectionAttempt(candidate=candidate, label=label, input_value=input_value, policy_allowed=True, policy_reason="request approved by deterministic policy", observation=observation)
        except httpx.TimeoutException:
            error = "request timed out"
        except httpx.RequestError as exc:
            error = f"request failed: {exc.__class__.__name__}"
        self.audit.record("sqli.request", "failed", url=url, parameter=candidate.parameter, label=label, reason=error)
        return SqlInjectionAttempt(candidate=candidate, label=label, input_value=input_value, policy_allowed=True, policy_reason="request approved by deterministic policy", error=error)

    def _evaluate(self, candidate: SqlInjectionCandidate, baseline: ResponseObservation, probes: list[ResponseObservation]) -> SqlInjectionFinding | None:
        differences = [_differs(baseline, probe, self.config.min_length_delta) for probe in probes]
        consistent_difference = len(differences) >= 2 and all(differences)
        baseline_signatures = set(baseline.sql_error_signatures)
        new_signatures = [s for probe in probes for s in probe.sql_error_signatures if s not in baseline_signatures]
        error_observed = bool(new_signatures)
        if not error_observed and not consistent_difference:
            return None
        if consistent_difference and error_observed:
            explanation = "Both controlled perturbations changed the response consistently and exposed new SQL-like error indicators; this is suspicious but not proof of exploitability."
            confidence = Confidence.MEDIUM
        elif consistent_difference:
            explanation = "Both controlled perturbations produced a consistent response difference from baseline; application behavior may be input-sensitive, but SQL injection is not established."

            confidence = Confidence.LOW
        else:
            explanation = "A SQL-like error indicator appeared after a controlled perturbation; database errors can have non-SQLi causes and require manual verification."
            confidence = Confidence.LOW
        digest = hashlib.sha256(f"{candidate.url}\x00{candidate.parameter}".encode()).hexdigest()[:12]
        evidence = SqlInjectionEvidence(baseline=baseline, probes=probes, consistent_difference=consistent_difference, database_error_observed=error_observed, explanation=explanation)
        return SqlInjectionFinding(
            finding_id=f"sqli-{digest}",
            candidate=candidate,
            status=FindingStatus.NEEDS_VERIFICATION,
            confidence=confidence,
            evidence=evidence,
            limitations=["No destructive, authentication-bypass, data-extraction, or table-dumping payloads were used.", "A verified SQL injection requires controlled manual verification in the authorized lab.", "Response differences can result from ordinary input validation, routing, or generic error handling."],
        )


def _baseline_value(candidate: SqlInjectionCandidate) -> str:
    parsed = urlsplit(candidate.url)
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if key == candidate.parameter:
            return value
    return "bountypilot-baseline"


def _inject_parameter(url: str, parameter: str, value: str) -> str:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    output: list[tuple[str, str]] = []
    for key, old_value in pairs:
        if key == parameter and not replaced:
            output.append((key, value))
            replaced = True
        else:
            output.append((key, old_value))
    if not replaced:
        output.append((parameter, value))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(output), ""))


def _observe(label: str, status_code: int, body: bytes, patterns: dict[str, re.Pattern[str]]) -> ResponseObservation:
    text = body.decode("utf-8", errors="replace")
    matches = [name for name, pattern in patterns.items() if pattern.search(text)]
    context = ""
    if matches:
        for pattern in patterns.values():
            match = pattern.search(text)
            if match:
                context = text[max(0, match.start() - 120): match.end() + 120][:500]
                break
    digest = hashlib.sha256(body).hexdigest()
    return ResponseObservation(label=label, status_code=status_code, body_length=len(body), body_digest=digest, sql_error_signatures=matches, response_context=context)


def _differs(baseline: ResponseObservation, probe: ResponseObservation, min_length_delta: int) -> bool:
    if baseline.status_code != probe.status_code:
        return True
    if abs(baseline.body_length - probe.body_length) >= min_length_delta:
        return True
    return baseline.body_digest != probe.body_digest and bool(probe.sql_error_signatures)
