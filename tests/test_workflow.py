import json
from pathlib import Path

from typer.testing import CliRunner

from bountypilot.audit import AuditLogger
from bountypilot.cli import app
from bountypilot.reporting import build_report, render_markdown, write_report
from bountypilot.scope import ScopeEntry, TargetScope
from bountypilot.storage import Storage
from bountypilot.workflow import WorkflowState, load_assessment, start_assessment


runner = CliRunner()


def test_cli_workflow_start_plan_status_and_report(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    assert runner.invoke(app, ["init"]).exit_code == 0
    assert runner.invoke(app, ["scope", "validate", "--host", "127.0.0.1", "--path", "/", "--active"]).exit_code == 0
    started = runner.invoke(app, ["start", "--target", "local mock lab"])
    assert started.exit_code == 0
    assert "Assessment started" in started.stdout
    planned = runner.invoke(app, ["plan", "--json"])
    assert planned.exit_code == 0
    assert '"actions"' in planned.stdout

    status = runner.invoke(app, ["status"])
    assert status.exit_code == 0
    assert '"plan_ready"' in status.stdout

    report = runner.invoke(app, ["report"])
    assert report.exit_code == 0
    assert (tmp_path / ".bountypilot" / "report.md").exists()
    assert (tmp_path / ".bountypilot" / "report.json").exists()
    payload = json.loads((tmp_path / ".bountypilot" / "report.json").read_text())
    assert payload["assessment_id"].startswith("bp-")
    assert payload["findings"] == []
    assert runner.invoke(app, ["findings"]).exit_code == 0
    assert runner.invoke(app, ["status"]).stdout.find('"reported"') >= 0


def test_report_contains_scope_testing_and_redacts_secret_like_content(tmp_path: Path):
    storage = Storage(tmp_path / "state.sqlite3")
    scope = TargetScope(entries=[ScopeEntry(host="127.0.0.1", schemes={"http"}, ports={3000}, paths=["/"])])
    assessment = start_assessment(storage, scope, "local lab")
    AuditLogger(storage).record("sqli.request", "completed", url="http://127.0.0.1:3000/item", authorization="Bearer should-not-appear")
    storage.add_finding(
        "sqli",
        "Needs verification",
        {
            "candidate": {"url": "http://127.0.0.1:3000/item?item=1", "parameter": "item", "location": "query"},
            "evidence": {"response_context": "Database error; token=private-value"},
        },
        severity="medium",
        confidence="low",
        assessment_id=assessment.assessment_id,
    )

    report = build_report(storage, assessment, now="2026-01-01T00:00:00+00:00")
    markdown = render_markdown(report)
    assert report["assessment_id"] == assessment.assessment_id
    assert "sqli.request" in report["testing_performed"]
    assert "private-value" not in markdown
    assert "authorization" not in json.dumps(report).lower() or "[redacted]" in json.dumps(report)
    assert "Needs verification" in markdown
    assert "reproduction_steps" in json.dumps(report)

    markdown_path = tmp_path / "out" / "assessment.md"
    json_path = tmp_path / "out" / "assessment.json"
    write_report(storage, assessment, markdown_path, json_path)
    assert markdown_path.exists()
    assert json.loads(json_path.read_text())["assessment_id"] == assessment.assessment_id


def test_scope_validate_file_and_port_and_findings_json(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["init"])

    # Test validating via --port
    port_res = runner.invoke(app, ["scope", "validate", "--host", "127.0.0.1", "--port", "3000", "--path", "/"])
    assert port_res.exit_code == 0
    assert '"ports": [\n    3000\n  ]' in port_res.stdout or "3000" in port_res.stdout

    # Test validating via --file
    scope_file = tmp_path / "test_scope.json"
    scope_file.write_text(json.dumps({
        "entries": [{"host": "127.0.0.1", "ports": [8080], "paths": ["/api"], "excluded_paths": []}],
        "active_testing": False,
        "request_timeout_seconds": 5.0,
        "requests_per_second": 2.0,
    }), encoding="utf-8")
    file_res = runner.invoke(app, ["scope", "validate", "--file", str(scope_file)])
    assert file_res.exit_code == 0
    assert "8080" in file_res.stdout

    # Start assessment and test findings --json
    runner.invoke(app, ["start", "--target", "json findings test"])
    runner.invoke(app, ["plan"])
    storage = Storage(tmp_path / ".bountypilot" / "bountypilot.sqlite3")
    assessment = load_assessment(storage)
    assert assessment is not None
    storage.add_finding("xss", "Candidate", {"finding_id": "xss-test1", "candidate": {"url": "http://127.0.0.1:8080/api"}}, severity="low", confidence="low", assessment_id=assessment.assessment_id)

    findings_json = runner.invoke(app, ["findings", "--json"])
    assert findings_json.exit_code == 0
    data = json.loads(findings_json.stdout)
    assert len(data) == 1
    assert data[0]["kind"] == "xss"


def test_storage_finding_deduplication(tmp_path: Path):
    storage = Storage(tmp_path / "dedup.sqlite3")
    aid = "bp-test123456"
    f1 = {"finding_id": "xss-abc123", "candidate": {"url": "http://127.0.0.1/item", "parameter": "q"}}
    id1 = storage.add_finding("xss", "Candidate", f1, severity="low", confidence="low", assessment_id=aid)
    assert id1 == 1

    # Adding the same finding again with upgraded status
    id2 = storage.add_finding("xss", "Verified", f1, severity="high", confidence="high", assessment_id=aid)
    assert id2 == 1  # Updated in place, not duplicated

    findings = storage.list_findings(assessment_id=aid)
    assert len(findings) == 1
    assert findings[0]["status"] == "Verified"
    assert findings[0]["severity"] == "high"

