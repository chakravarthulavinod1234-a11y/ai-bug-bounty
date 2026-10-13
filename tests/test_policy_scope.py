from pathlib import Path

from bountypilot.audit import AuditLogger
from bountypilot.policy import PolicyEngine
from bountypilot.scope import ScopeEntry, TargetScope
from bountypilot.storage import Storage


def test_scope_requires_exact_host_and_path():
    scope = TargetScope(entries=[ScopeEntry(host="127.0.0.1", ports={3000}, paths=["/api"], excluded_paths=["/api/admin"])])
    assert scope.match("http://127.0.0.1:3000/api/users")[0]
    assert not scope.match("http://127.0.0.1:3000/api/admin")[0]
    assert not scope.match("http://localhost:3000/api/users")[0]
    assert not scope.match("http://127.0.0.1:3001/api/users")[0]


def test_policy_requires_active_flag_and_confirmation():
    disabled = PolicyEngine(TargetScope(entries=[ScopeEntry(host="127.0.0.1", ports={3000})]))
    assert not disabled.authorize("http://127.0.0.1:3000/", active=True, confirmed=True).allowed
    enabled = PolicyEngine(TargetScope(entries=[ScopeEntry(host="127.0.0.1", ports={3000})], active_testing=True))
    assert not enabled.authorize("http://127.0.0.1:3000/", active=True, confirmed=False).allowed
    assert enabled.authorize("http://127.0.0.1:3000/", active=True, confirmed=True).allowed


def test_policy_rejects_out_of_scope_redirect_and_unsafe_method():
    engine = PolicyEngine(TargetScope(entries=[ScopeEntry(host="127.0.0.1", ports={3000})]))
    assert not engine.authorize_redirect("https://example.com/").allowed
    assert not engine.authorize("http://127.0.0.1:3000/", method="POST").allowed


def test_malformed_port_is_rejected_without_raising():
    scope = TargetScope(entries=[ScopeEntry(host="127.0.0.1", ports={3000})])
    engine = PolicyEngine(scope)

    decision = engine.authorize("http://127.0.0.1:not-a-port/")

    assert not decision.allowed
    assert "invalid port" in decision.reason
    assert not scope.match("http://127.0.0.1:not-a-port/")[0]


def test_policy_boundary_rejects_out_of_scope_input_even_when_active_confirmed():
    scope = TargetScope(
        entries=[ScopeEntry(host="127.0.0.1", ports={3000})],
        active_testing=True,
    )
    engine = PolicyEngine(scope)

    decision = engine.authorize("https://example.com/", active=True, confirmed=True)

    assert not decision.allowed
    assert "outside configured scope" in decision.reason


def test_kill_switch_blocks_requests():
    engine = PolicyEngine(TargetScope(entries=[ScopeEntry(host="127.0.0.1", ports={3000})]))
    engine.stop()
    assert not engine.authorize("http://127.0.0.1:3000/").allowed


def test_storage_and_audit_do_not_store_secret_body(tmp_path: Path):
    storage = Storage(tmp_path / "state.sqlite3")
    AuditLogger(storage).record("request", "approved", body="secret", token="hidden", url="http://127.0.0.1/")
    with storage._connect() as db:
        row = db.execute("SELECT details_json FROM audit_log LIMIT 1").fetchone()
    assert "secret" not in row[0]
    assert "hidden" not in row[0]
    assert "url" in row[0]


def test_path_traversal_dot_segments_cannot_bypass_scope_or_exclusions():
    scope = TargetScope(
        entries=[ScopeEntry(host="127.0.0.1", ports={3000}, paths=["/api"], excluded_paths=["/api/admin"])]
    )
    # Traversal to excluded path must be blocked
    matched, reason = scope.match("http://127.0.0.1:3000/api/users/../../api/admin")
    assert not matched
    assert "excluded" in reason

    # Traversal climbing above allowed root must be blocked
    matched2, reason2 = scope.match("http://127.0.0.1:3000/api/../secret")
    assert not matched2
    assert "outside" in reason2

    # Percent-encoded traversal must also be blocked
    matched3, reason3 = scope.match("http://127.0.0.1:3000/api/%2e%2e/admin")
    assert not matched3


def test_ipv6_normalization_in_scope_and_bracketed_host():
    entry = ScopeEntry(host="[::1]", ports={3000})
    assert entry.host == "::1"
    scope = TargetScope(entries=[entry])
    assert scope.match("http://[0:0:0:0:0:0:0:1]:3000/")[0]
    assert scope.match("http://[::1]:3000/")[0]


def test_cloud_metadata_link_local_blocked():
    scope = TargetScope(entries=[ScopeEntry(host="169.254.169.254")])
    engine = PolicyEngine(scope)
    decision = engine.authorize("http://169.254.169.254/latest/meta-data/")
    assert not decision.allowed
    assert "metadata" in decision.reason


def test_audit_logger_redacts_api_keys_and_cookies(tmp_path: Path):
    storage = Storage(tmp_path / "audit_test.sqlite3")
    logger = AuditLogger(storage)
    logger.record("test", "allowed", api_key="secret-key-123", cookie="session=abcdef", token="bearer token_xyz")
    with storage._connect() as db:
        row = db.execute("SELECT details_json FROM audit_log LIMIT 1").fetchone()
    logged = row[0]
    assert "secret-key-123" not in logged
    assert "abcdef" not in logged
    assert "token_xyz" not in logged
    assert "[redacted]" in logged

