import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from bountypilot.audit import AuditLogger
from bountypilot.policy import PolicyEngine
from bountypilot.recon import ReconLimits, Reconnaissance
from bountypilot.scope import ScopeEntry, TargetScope
from bountypilot.storage import Storage
from bountypilot.sqli import (
    SqlInjectionApprovalRequired,
    SqlInjectionConfig,
    SqlInjectionScanner,
)
from bountypilot.xss import Confidence, FindingStatus


class SqlLabHandler(BaseHTTPRequestHandler):
    request_count = 0
    mode = "vulnerable"

    def do_GET(self) -> None:  # noqa: N802
        type(self).request_count += 1
        path = urlsplit(self.path).path
        params = parse_qs(urlsplit(self.path).query)
        value = params.get("item", [""])[0]
        if path == "/":
            body = b'<html><body><a href="/item?item=1">item</a></body></html>'
            status = 200
        elif path == "/item":
            if self.mode == "vulnerable" and value in {"'", '"'}:
                body = b"Database error: SQLite error near quote: syntax error"
                status = 500
            elif self.mode == "generic-error":
                body = b"Generic validation error; request rejected"
                status = 400
            else:
                body = f"Item result for {value}".encode()
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


def make_server(mode: str = "vulnerable") -> tuple[ThreadingHTTPServer, threading.Thread, str]:
    SqlLabHandler.request_count = 0
    SqlLabHandler.mode = mode
    server = ThreadingHTTPServer(("127.0.0.1", 0), SqlLabHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_port}"


def make_scope(base_url: str, *, active: bool = True) -> TargetScope:
    port = int(base_url.rsplit(":", 1)[1])
    return TargetScope(entries=[ScopeEntry(host="127.0.0.1", schemes={"http"}, ports={port}, paths=["/"])], active_testing=active, requests_per_second=10)


def get_recon(base_url: str, scope: TargetScope, tmp_path: Path):
    storage = Storage(tmp_path / "state.sqlite3")
    recon = Reconnaissance(scope, PolicyEngine(scope), AuditLogger(storage), ReconLimits(max_depth=1, max_urls=3))
    return recon.run([base_url + "/"]), storage


def test_sqli_requires_explicit_approval(tmp_path: Path):
    server, thread, base_url = make_server()
    try:
        scope = make_scope(base_url)
        recon, storage = get_recon(base_url, scope, tmp_path)
        before = SqlLabHandler.request_count
        scanner = SqlInjectionScanner(scope, PolicyEngine(scope), AuditLogger(storage))
        with pytest.raises(SqlInjectionApprovalRequired):
            scanner.scan(recon, confirmed=False)
        assert SqlLabHandler.request_count == before
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_vulnerable_lab_produces_needs_verification_with_reproducible_evidence(tmp_path: Path):
    server, thread, base_url = make_server()
    try:
        scope = make_scope(base_url)
        recon, storage = get_recon(base_url, scope, tmp_path)
        scanner = SqlInjectionScanner(scope, PolicyEngine(scope), AuditLogger(storage), SqlInjectionConfig(min_length_delta=10))
        result = scanner.scan(recon, confirmed=True)
        assert len(result.attempts) == 3  # baseline + two controlled cases
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.status == FindingStatus.NEEDS_VERIFICATION
        assert finding.confidence == Confidence.MEDIUM
        assert finding.evidence.database_error_observed is True
        assert finding.evidence.consistent_difference is True
        assert "not proof" in finding.evidence.explanation
        assert finding.evidence.probes[0].status_code == 500
        assert finding.evidence.probes[0].response_context
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_generic_error_behavior_is_false_positive_not_a_finding(tmp_path: Path):
    server, thread, base_url = make_server("generic-error")
    try:
        scope = make_scope(base_url)
        recon, storage = get_recon(base_url, scope, tmp_path)
        scanner = SqlInjectionScanner(scope, PolicyEngine(scope), AuditLogger(storage), SqlInjectionConfig(min_length_delta=10))
        result = scanner.scan(recon, confirmed=True)
        assert result.findings == []
        assert all(attempt.observation is not None for attempt in result.attempts)
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_database_error_alone_is_not_verified(tmp_path: Path):
    server, thread, base_url = make_server()
    try:
        scope = make_scope(base_url)
        recon, storage = get_recon(base_url, scope, tmp_path)
        config = SqlInjectionConfig(test_cases=[("quote", "'")], max_test_cases=1, min_length_delta=10)
        scanner = SqlInjectionScanner(scope, PolicyEngine(scope), AuditLogger(storage), config)
        result = scanner.scan(recon, confirmed=True)
        assert result.findings[0].status == FindingStatus.NEEDS_VERIFICATION
        assert result.findings[0].confidence == Confidence.LOW
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_inactive_scope_rejects_all_sqli_requests(tmp_path: Path):
    server, thread, base_url = make_server()
    try:
        scope = make_scope(base_url, active=False)
        recon, storage = get_recon(base_url, scope, tmp_path)
        before = SqlLabHandler.request_count
        scanner = SqlInjectionScanner(scope, PolicyEngine(scope), AuditLogger(storage), SqlInjectionConfig())
        result = scanner.scan(recon, confirmed=True)
        assert result.findings == []
        assert result.attempts
        assert all(not attempt.policy_allowed for attempt in result.attempts)
        assert SqlLabHandler.request_count == before
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_sqli_candidates_exclude_out_of_scope_and_sensitive_inputs(tmp_path: Path):
    server, thread, base_url = make_server()
    try:
        scope = make_scope(base_url)
        recon, _storage = get_recon(base_url, scope, tmp_path)
        candidates = SqlInjectionScanner.candidates_from_recon(recon, PolicyEngine(scope))
        assert any(candidate.parameter == "item" for candidate in candidates)
        assert all(candidate.parameter not in {"password", "token", "csrf", "session"} for candidate in candidates)
        assert all(scope.match(candidate.url)[0] for candidate in candidates)
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_sqli_audit_contains_policy_and_request_events(tmp_path: Path):
    server, thread, base_url = make_server()
    try:
        scope = make_scope(base_url)
        recon, storage = get_recon(base_url, scope, tmp_path)
        SqlInjectionScanner(scope, PolicyEngine(scope), AuditLogger(storage), SqlInjectionConfig()).scan(recon, confirmed=True)
        with storage._connect() as db:
            rows = db.execute("SELECT action, decision, details_json FROM audit_log ORDER BY id LIMIT 100").fetchall()
        events = [(row[0], row[1], json.loads(row[2])) for row in rows]
        assert any(action == "sqli.policy" and decision == "approved" for action, decision, _details in events)
        assert any(action == "sqli.request" and decision == "completed" for action, decision, _details in events)
    finally:
        server.shutdown()
        thread.join(timeout=2)
