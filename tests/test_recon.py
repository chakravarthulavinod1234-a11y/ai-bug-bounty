import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from bountypilot.audit import AuditLogger
from bountypilot.policy import PolicyEngine
from bountypilot.recon import ReconLimits, Reconnaissance
from bountypilot.scope import ScopeEntry, TargetScope
from bountypilot.storage import Storage


class MockHandler(BaseHTTPRequestHandler):
    request_counts: dict[str, int] = {}

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        self.request_counts[path] = self.request_counts.get(path, 0) + 1
        if path == "/":
            body = b"""<!doctype html><html><head><title>Lab Home</title>
            <meta name='description' content='local lab'>
            <meta name='generator' content='TestCMS 1.0'></head><body>
            <a href='/inside'>Inside</a><a href='/excluded'>Excluded</a>
            <a href='https://example.com/outside'>External</a>
            <form action='/submit' method='post'><input name='q'></form>
            </body></html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Server", "MockServer/1.0")
            self.send_header("Set-Cookie", "session=secret-value")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/inside":
            body = b"<html><title>Inside</title><body>safe</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/redirect-in":
            self.send_response(302)
            self.send_header("Location", "/inside")
            self.end_headers()
        elif path == "/redirect-out":
            self.send_response(302)
            self.send_header("Location", "https://example.com/outside")
            self.end_headers()
        elif path == "/slow":
            time.sleep(0.2)
            body = b"slow"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *_args: object) -> None:
        return


def make_server() -> tuple[ThreadingHTTPServer, threading.Thread, str]:
    MockHandler.request_counts = {}
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_port}"


def make_recon(base_url: str, tmp_path: Path, *, excluded: list[str] | None = None, timeout: float = 2.0, max_depth: int = 1, max_urls: int = 10) -> tuple[Reconnaissance, Storage]:
    port = int(base_url.rsplit(":", 1)[1])
    scope = TargetScope(
        entries=[ScopeEntry(host="127.0.0.1", schemes={"http"}, ports={port}, paths=["/"], excluded_paths=excluded or [])],
        request_timeout_seconds=timeout,
        requests_per_second=10,
    )
    storage = Storage(tmp_path / "recon.sqlite3")
    policy = PolicyEngine(scope)
    return Reconnaissance(scope, policy, AuditLogger(storage), ReconLimits(max_depth=max_depth, max_urls=max_urls)), storage


def audit_details(storage: Storage) -> list[dict]:
    with storage._connect() as db:
        rows = db.execute("SELECT details_json FROM audit_log ORDER BY id LIMIT 100").fetchall()
    return [json.loads(row[0]) for row in rows]


def test_recon_extracts_metadata_links_forms_technologies_and_exports(tmp_path: Path):
    server, thread, base_url = make_server()
    try:
        recon, storage = make_recon(base_url, tmp_path)
        output = tmp_path / "recon.json"
        result = recon.run([base_url + "/"])
        result.export_json(output)

        root = next(page for page in result.pages if page.url == base_url + "/")
        assert root.status_code == 200
        assert root.headers["set-cookie"] == "[redacted]"
        assert root.title == "Lab Home"
        assert root.metadata["description"] == "local lab"
        assert root.metadata["generator"] == "TestCMS 1.0"
        assert any(link.url == base_url + "/inside" and link.in_scope for link in root.links)
        assert any(link.url == "https://example.com/outside" and not link.in_scope for link in root.links)
        assert root.forms[0].method == "POST"
        assert root.forms[0].in_scope is True
        assert root.forms[0].requestable is False
        assert any("server:" in indicator.lower() for indicator in root.technology_indicators)
        assert base_url + "/inside" in result.discovered_urls
        assert json.loads(output.read_text(encoding="utf-8"))["pages"]
        assert any(detail.get("status_code") == 200 for detail in audit_details(storage))
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_redirects_are_revalidated_and_out_of_scope_destination_is_not_requested(tmp_path: Path):
    server, thread, base_url = make_server()
    try:
        recon, storage = make_recon(base_url, tmp_path)
        result = recon.run([base_url + "/redirect-out"])
        assert len(result.pages) == 1
        assert result.pages[0].status_code == 302
        assert "https://example.com/outside" not in result.discovered_urls
        assert MockHandler.request_counts.get("/redirect-out") == 1
        assert any(detail.get("kind") == "redirect" and "outside" in detail.get("url", "") and detail.get("reason") for detail in audit_details(storage))

        recon_in, _ = make_recon(base_url, tmp_path / "in")
        result_in = recon_in.run([base_url + "/redirect-in"])
        assert {page.url for page in result_in.pages} == {base_url + "/redirect-in", base_url + "/inside"}
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_excluded_path_is_not_requested(tmp_path: Path):
    server, thread, base_url = make_server()
    try:
        recon, storage = make_recon(base_url, tmp_path, excluded=["/excluded"])
        result = recon.run([base_url + "/excluded"])
        assert result.pages == []
        assert MockHandler.request_counts.get("/excluded", 0) == 0
        assert any(detail.get("reason") == "path is explicitly excluded" for detail in audit_details(storage))
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_timeout_is_recorded_without_crashing(tmp_path: Path):
    server, thread, base_url = make_server()
    try:
        recon, _ = make_recon(base_url, tmp_path, timeout=0.05)
        result = recon.run([base_url + "/slow"])
        assert len(result.pages) == 1
        assert result.pages[0].error is not None
        assert "timed out" in result.pages[0].error
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_url_and_depth_limits_bound_requests(tmp_path: Path):
    server, thread, base_url = make_server()
    try:
        recon, _ = make_recon(base_url, tmp_path, max_depth=0, max_urls=1)
        result = recon.run([base_url + "/"])
        assert result.requested_url_count == 1
        assert len(result.pages) == 1
        assert MockHandler.request_counts.get("/inside", 0) == 0
    finally:
        server.shutdown()
        thread.join(timeout=2)
