import threading
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from pydantic import BaseModel

from bountypilot.audit import AuditLogger
from bountypilot.policy import PolicyEngine
from bountypilot.recon import ReconLimits, Reconnaissance
from bountypilot.scope import ScopeEntry, TargetScope
from bountypilot.storage import Storage
from bountypilot.xss import (
    BrowserVerification,
    Confidence,
    FindingStatus,
    XssApprovalRequired,
    XssConfig,
    XssScanner,
)


class EchoHandler(BaseHTTPRequestHandler):
    request_count = 0

    def do_GET(self) -> None:  # noqa: N802
        type(self).request_count += 1
        path = urlsplit(self.path).path
        if path == "/":
            body = b'<html><body><a href="/echo?q=seed">echo</a><form method="post" action="/echo"><input name="q"></form></body></html>'
            status = 200
        elif path == "/echo":
            value = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
            body = f"<html><body>{value}</body></html>".encode()
            status = 200
        else:
            body = b"not found"
            status = 404
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


def make_server() -> tuple[ThreadingHTTPServer, threading.Thread, str]:
    EchoHandler.request_count = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), EchoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_port}"


def make_scope(base_url: str, *, active: bool = True) -> TargetScope:
    port = int(base_url.rsplit(":", 1)[1])
    return TargetScope(
        entries=[ScopeEntry(host="127.0.0.1", schemes={"http"}, ports={port}, paths=["/"])],
        active_testing=active,
        requests_per_second=10,
    )


def get_recon(base_url: str, scope: TargetScope, tmp_path: Path):
    storage = Storage(tmp_path / "state.sqlite3")
    recon = Reconnaissance(scope, PolicyEngine(scope), AuditLogger(storage), ReconLimits(max_depth=1, max_urls=3))
    return recon.run([base_url + "/"]), storage


class FakeVerifier(BaseModel):
    executed: bool

    def verify(self, url: str, execution_marker: str) -> BrowserVerification:
        del url, execution_marker
        return BrowserVerification(attempted=True, executed=self.executed)


def test_xss_requires_explicit_approval_before_requests(tmp_path: Path):
    server, thread, base_url = make_server()
    try:
        scope = make_scope(base_url)
        recon, storage = get_recon(base_url, scope, tmp_path)
        before = EchoHandler.request_count
        scanner = XssScanner(scope, PolicyEngine(scope), AuditLogger(storage), XssConfig(payloads=["marker"], max_payloads=1))
        with pytest.raises(XssApprovalRequired):
            scanner.scan(recon, confirmed=False)
        assert EchoHandler.request_count == before
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_plain_reflection_is_candidate_not_verified_xss(tmp_path: Path):
    server, thread, base_url = make_server()
    try:
        scope = make_scope(base_url)
        recon, storage = get_recon(base_url, scope, tmp_path)
        scanner = XssScanner(scope, PolicyEngine(scope), AuditLogger(storage), XssConfig(payloads=["plain-marker"], max_payloads=1))
        result = scanner.scan(recon, confirmed=True)

        assert result.candidates
        assert len(result.attempts) == 1
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.status == FindingStatus.CANDIDATE
        assert finding.confidence == Confidence.LOW
        assert finding.evidence.reflected is True
        assert finding.evidence.potentially_executable is False
        assert finding.evidence.response_status == 200
        assert "plain-marker" in finding.evidence.response_context
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_potential_executable_reflection_requires_browser_verification(tmp_path: Path):
    server, thread, base_url = make_server()
    try:
        scope = make_scope(base_url)
        recon, storage = get_recon(base_url, scope, tmp_path)
        payload = '"><svg/onload=window.__bountypilot_xss__=\'bountypilot-xss-executed\'>'
        scanner = XssScanner(
            scope,
            PolicyEngine(scope),
            AuditLogger(storage),
            XssConfig(payloads=[payload], max_payloads=1),
            browser_verifier=FakeVerifier(executed=True),
        )
        result = scanner.scan(recon, confirmed=True)
        assert result.findings[0].status == FindingStatus.VERIFIED
        assert result.findings[0].confidence == Confidence.HIGH
        assert result.findings[0].browser_verification is not None

        scanner_false = XssScanner(
            scope,
            PolicyEngine(scope),
            AuditLogger(storage),
            XssConfig(payloads=[payload], max_payloads=1),
            browser_verifier=FakeVerifier(executed=False),
        )
        false_result = scanner_false.scan(recon, confirmed=True)
        assert false_result.findings[0].status == FindingStatus.FALSE_POSITIVE

        scanner_unverified = XssScanner(
            scope,
            PolicyEngine(scope),
            AuditLogger(storage),
            XssConfig(payloads=[payload], max_payloads=1),
        )
        unverified_result = scanner_unverified.scan(recon, confirmed=True)
        assert unverified_result.findings[0].status == FindingStatus.NEEDS_VERIFICATION
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_active_policy_rejection_prevents_xss_request(tmp_path: Path):
    server, thread, base_url = make_server()
    try:
        scope = make_scope(base_url, active=False)
        recon, storage = get_recon(base_url, scope, tmp_path)
        before = EchoHandler.request_count
        scanner = XssScanner(scope, PolicyEngine(scope), AuditLogger(storage), XssConfig(payloads=["marker"], max_payloads=1))
        result = scanner.scan(recon, confirmed=True)
        assert result.attempts
        assert all(not attempt.policy_allowed for attempt in result.attempts)
        assert not result.findings
        assert EchoHandler.request_count == before
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_sensitive_and_post_form_inputs_are_not_candidates(tmp_path: Path):
    server, thread, base_url = make_server()
    try:
        scope = make_scope(base_url)
        recon, _storage = get_recon(base_url, scope, tmp_path)
        candidates = XssScanner.candidates_from_recon(recon, PolicyEngine(scope))
        assert all(candidate.parameter not in {"password", "token", "csrf"} for candidate in candidates)
        assert all(candidate.location == "query" for candidate in candidates)
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_xss_requests_and_policy_decisions_are_audited(tmp_path: Path):
    server, thread, base_url = make_server()
    try:
        scope = make_scope(base_url)
        recon, storage = get_recon(base_url, scope, tmp_path)
        scanner = XssScanner(scope, PolicyEngine(scope), AuditLogger(storage), XssConfig(payloads=["audit-marker"], max_payloads=1))
        scanner.scan(recon, confirmed=True)
        with storage._connect() as db:
            rows = db.execute("SELECT action, decision, details_json FROM audit_log ORDER BY id LIMIT 100").fetchall()
        events = [(row[0], row[1], json.loads(row[2])) for row in rows]
        assert any(action == "xss.policy" and decision == "approved" for action, decision, _details in events)
        assert any(action == "xss.request" and decision == "completed" for action, decision, _details in events)
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_json_response_not_marked_potentially_executable():
    from bountypilot.xss import _reflection_evidence
    payload = '"><svg/onload=alert(1)>'
    body = b'{"result": "\\"><svg/onload=alert(1)>"}'
    evidence = _reflection_evidence(payload, body, 200, content_type="application/json")
    assert evidence.reflected is True
    assert evidence.potentially_executable is False
    assert "non_html_response" in evidence.contexts

