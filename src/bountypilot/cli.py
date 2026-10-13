"""Command-line interface for BountyPilot AI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from .audit import AuditLogger
from .config import AppConfig
from .planner import Planner
from .policy import PolicyEngine
from .providers import load_provider_from_env
from .recon import ReconLimits, ReconResult, Reconnaissance, result_to_json
from .reporting import write_report
from .scope import ScopeEntry, TargetScope
from .storage import Storage
from .sqli import SqlInjectionApprovalRequired, SqlInjectionConfig, SqlInjectionScanner
from .workflow import WorkflowState, initialize_project, load_assessment, require_assessment, start_assessment, transition, update_metadata
from .xss import PlaywrightVerifier, XssApprovalRequired, XssConfig, XssScanner

app = typer.Typer(help="Policy-first AI-assisted security testing for explicitly authorized targets.")
scope_app = typer.Typer(help="Validate and inspect explicit target scope.")
test_app = typer.Typer(help="Run explicitly approved, conservative vulnerability checks.")
app.add_typer(scope_app, name="scope")
app.add_typer(test_app, name="test")
console = Console()


def get_storage() -> Storage:
    return Storage(AppConfig().database_path)


def get_configured_scope(storage: Storage) -> TargetScope:
    """Load and revalidate persisted scope before using it."""
    raw_scope = storage.get_metadata("scope")
    if raw_scope is None:
        return TargetScope()
    try:
        return TargetScope.model_validate(raw_scope)
    except ValueError as exc:
        raise typer.BadParameter(f"stored scope is invalid: {exc}") from exc


def assessment_or_error(storage: Storage):
    try:
        return require_assessment(storage)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


def require_reviewed_plan(storage: Storage) -> None:
    """Prevent execution from skipping the plan-review stage."""
    if storage.get_metadata("workflow.plan") is None:
        raise typer.BadParameter("no reviewed plan is saved; run bountypilot plan before reconnaissance or active checks")


@app.command()
def init() -> None:
    """Initialize local SQLite state with an empty deny-by-default scope."""
    storage = get_storage()
    storage.set_metadata("scope", TargetScope().model_dump(mode="json"))
    initialize_project(storage)
    AuditLogger(storage).record("init", "created", data_dir=str(storage.database_path.parent))
    console.print(f"[green]Initialized[/green] local state at {storage.database_path}")
    console.print("No targets are authorized yet; validate scope, then run start.")


@scope_app.command("validate")
def scope_validate(
    host: Annotated[str | None, typer.Option(help="Exact authorized hostname or IP address.")] = None,
    path: Annotated[str, typer.Option(help="Authorized path prefix.")] = "/",
    exclude: Annotated[list[str] | None, typer.Option(help="Explicitly excluded path prefix; repeatable.")] = None,
    port: Annotated[list[int] | None, typer.Option(help="Authorized port; repeatable.")] = None,
    scheme: Annotated[list[str] | None, typer.Option(help="Authorized scheme (http/https); repeatable.")] = None,
    active: Annotated[bool, typer.Option(help="Enable active testing only with explicit operator confirmation.")] = False,
    file: Annotated[Path | None, typer.Option("--file", help="Path to scope JSON configuration file to validate and load.")] = None,
) -> None:
    """Validate and persist an explicit target scope configuration."""
    try:
        if file is not None:
            scope = TargetScope.model_validate_json(file.read_text(encoding="utf-8"))
        elif host is not None:
            ports = set(port) if port else set()
            schemes = set(scheme) if scheme else {"http", "https"}
            entry = ScopeEntry(host=host, paths=[path], excluded_paths=exclude or [], ports=ports, schemes=schemes)
            scope = TargetScope(entries=[entry], active_testing=active)
        else:
            raise ValueError("either --host or --file must be specified")
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    storage = get_storage()
    storage.set_metadata("scope", scope.model_dump(mode="json"))
    AuditLogger(storage).record("scope.validate", "accepted", active=scope.active_testing, entry_count=len(scope.entries))
    console.print("[green]Scope is valid and stored.[/green]")
    console.print_json(json.dumps(scope.model_dump(mode="json")))


@app.command()
def start(
    target: Annotated[str, typer.Option(help="Short description of the authorized target.")] = "authorized target",
) -> None:
    """Start a persisted assessment using the validated authorized scope."""
    storage = get_storage()
    try:
        assessment = start_assessment(storage, get_configured_scope(storage), target)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    AuditLogger(storage).record("start", "created", assessment_id=assessment.assessment_id, target_description=target)
    console.print(f"[green]Assessment started[/green]: {assessment.assessment_id}")
    console.print("Review the plan before approving any active checks.")


@app.command()
def status() -> None:
    """Show scope, assessment lifecycle state, and kill-switch state."""
    storage = get_storage()
    scope = get_configured_scope(storage).model_dump(mode="json")
    assessment = load_assessment(storage)
    console.print_json(json.dumps({
        "scope": scope,
        "kill_switch": storage.get_metadata("kill_switch") or False,
        "assessment": assessment.model_dump(mode="json") if assessment else None,
    }))


@app.command()
def stop() -> None:
    """Activate the persistent kill switch and stop the current assessment."""
    storage = get_storage()
    storage.set_metadata("kill_switch", True)
    if load_assessment(storage):
        transition(storage, WorkflowState.STOPPED)
    AuditLogger(storage).record("stop", "activated")
    console.print("[yellow]Kill switch activated.[/yellow] New requests must stop.")


@app.command()
def plan(
    target: Annotated[str | None, typer.Option(help="Optional target description override.")] = None,
    exclude_category: Annotated[list[str] | None, typer.Option(help="Exclude a supported category; repeatable.")] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Print the complete structured plan as JSON.")] = False,
) -> None:
    """Generate and persist a policy-validated plan for review; execute nothing."""
    storage = get_storage()
    assessment = assessment_or_error(storage)
    scope = assessment.scope
    policy = PolicyEngine(scope)
    if storage.get_metadata("kill_switch"):
        policy.stop()
    try:
        provider = load_provider_from_env()
        security_plan = Planner(scope, policy, provider=provider).create_plan(
            target_description=target or assessment.target_description,
            excluded_categories=set(exclude_category or set()),
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    update_metadata(storage, "plan", security_plan.model_dump(mode="json"))
    transition(storage, WorkflowState.PLAN_READY, assessment=assessment)
    AuditLogger(storage).record("plan", "created", assessment_id=assessment.assessment_id, action_count=len(security_plan.actions), generated_by=security_plan.generated_by)
    if json_output:
        console.print_json(json.dumps(security_plan.model_dump(mode="json")))
        return
    console.print(f"[green]Plan created and saved for review[/green] ({security_plan.generated_by}); no actions executed.")
    table = Table("Priority", "Category", "Risk", "Approval", "Action")
    for action in security_plan.actions:
        table.add_row(str(action.priority), action.category, action.risk, "required" if action.requires_approval else "not required", action.name)
    console.print(table)
    if security_plan.active_approval_required:
        console.print("[yellow]Active actions are proposals only and require --approve on the specific test command.[/yellow]")



@app.command()
def recon(
    max_depth: Annotated[int, typer.Option(help="Maximum link depth to crawl.")] = 1,
    max_urls: Annotated[int, typer.Option(help="Maximum number of URLs to request.")] = 25,
    max_page_bytes: Annotated[int, typer.Option(help="Maximum response bytes read per page.")] = 512_000,
    output: Annotated[Path | None, typer.Option(help="Write the JSON result to this path.")] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Print the complete JSON result.")] = False,
) -> None:
    """Run permitted bounded passive reconnaissance and save its result."""
    storage = get_storage()
    assessment = assessment_or_error(storage)
    require_reviewed_plan(storage)
    scope = assessment.scope
    policy = PolicyEngine(scope)
    if storage.get_metadata("kill_switch"):
        policy.stop()
    try:
        limits = ReconLimits(max_depth=max_depth, max_urls=max_urls, max_page_bytes=max_page_bytes)
        result = Reconnaissance(scope, policy, AuditLogger(storage), limits).run()
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    output = output or AppConfig().data_dir / "recon.json"
    result.export_json(output)
    update_metadata(storage, "recon_result", result.model_dump(mode="json"))
    transition(storage, WorkflowState.RECON_COMPLETE, assessment=assessment)
    console.print(f"[green]Reconnaissance JSON written to[/green] {output}")
    if json_output:
        console.print(result_to_json(result))
        return
    console.print(f"[green]Reconnaissance complete[/green]: {result.requested_url_count} URL(s) requested, {len(result.pages)} page(s) observed.")
    console.print(f"Discovered {len(result.discovered_urls)} in-scope URL(s); no active tests were executed.")


def _load_recon(storage: Storage, recon_file: Path | None) -> tuple[ReconResult, Path]:
    path = recon_file or AppConfig().data_dir / "recon.json"
    try:
        return ReconResult.model_validate_json(path.read_text(encoding="utf-8")), path
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(f"invalid or missing reconnaissance result {path}: {exc}") from exc


@test_app.command("xss")
def test_xss(
    recon_file: Annotated[Path | None, typer.Option("--recon", help="Path to a saved reconnaissance JSON result.")] = None,
    approve: Annotated[bool, typer.Option("--approve", help="Explicitly approve active XSS requests.")] = False,
    max_payloads: Annotated[int, typer.Option(help="Maximum harmless payloads per candidate.")] = 2,
    browser_verify: Annotated[bool, typer.Option(help="Use isolated Playwright marker verification when available.")] = False,
    output: Annotated[Path | None, typer.Option(help="Write the JSON scan result to this path.")] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Print the complete JSON scan result.")] = False,
) -> None:
    """Run conservative reflected-XSS checks after explicit approval."""
    storage = get_storage()
    assessment = assessment_or_error(storage)
    require_reviewed_plan(storage)
    recon_result, _ = _load_recon(storage, recon_file)
    policy = PolicyEngine(assessment.scope)
    if storage.get_metadata("kill_switch"):
        policy.stop()
    try:
        config = XssConfig(max_payloads=max_payloads)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    scanner = XssScanner(assessment.scope, policy, AuditLogger(storage), config, PlaywrightVerifier(policy) if browser_verify else None)
    try:
        result = scanner.scan(recon_result, confirmed=approve)
    except XssApprovalRequired as exc:
        raise typer.BadParameter(str(exc)) from exc
    for finding in result.findings:
        severity = "high" if finding.status.value == "Verified" else "medium" if finding.evidence.potentially_executable else "low"
        storage.add_finding("xss", finding.status.value, finding.model_dump(mode="json"), severity=severity, confidence=finding.confidence.value, assessment_id=assessment.assessment_id)
    update_metadata(storage, "xss_result", result.model_dump(mode="json"))
    transition(storage, WorkflowState.CHECKS_COMPLETE, assessment=assessment)
    output = output or AppConfig().data_dir / "xss-result.json"
    result.export_json(output)
    if json_output:
        console.print_json(json.dumps(result.model_dump(mode="json")))
        return
    console.print(f"[green]XSS result written to[/green] {output}")
    console.print(f"{len(result.attempts)} request attempt(s), {len(result.findings)} finding(s); statuses remain evidence-based.")


@test_app.command("sqli")
def test_sqli(
    recon_file: Annotated[Path | None, typer.Option("--recon", help="Path to a saved reconnaissance JSON result.")] = None,
    approve: Annotated[bool, typer.Option("--approve", help="Explicitly approve active SQLi requests.")] = False,
    max_test_cases: Annotated[int, typer.Option(help="Maximum controlled test cases per candidate.")] = 2,
    output: Annotated[Path | None, typer.Option(help="Write the JSON scan result to this path.")] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Print the complete JSON scan result.")] = False,
) -> None:
    """Run bounded SQLi checks after explicit approval."""
    storage = get_storage()
    assessment = assessment_or_error(storage)
    require_reviewed_plan(storage)
    recon_result, _ = _load_recon(storage, recon_file)
    policy = PolicyEngine(assessment.scope)
    if storage.get_metadata("kill_switch"):
        policy.stop()
    try:
        config = SqlInjectionConfig(max_test_cases=max_test_cases)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    scanner = SqlInjectionScanner(assessment.scope, policy, AuditLogger(storage), config)
    try:
        result = scanner.scan(recon_result, confirmed=approve)
    except SqlInjectionApprovalRequired as exc:
        raise typer.BadParameter(str(exc)) from exc
    for finding in result.findings:
        severity = "medium" if finding.confidence == "medium" else "low"
        storage.add_finding("sqli", finding.status.value, finding.model_dump(mode="json"), severity=severity, confidence=finding.confidence.value, assessment_id=assessment.assessment_id)
    update_metadata(storage, "sqli_result", result.model_dump(mode="json"))
    transition(storage, WorkflowState.CHECKS_COMPLETE, assessment=assessment)
    output = output or AppConfig().data_dir / "sqli-result.json"
    result.export_json(output)
    if json_output:
        console.print_json(json.dumps(result.model_dump(mode="json")))
        return
    console.print(f"[green]SQLi result written to[/green] {output}")
    console.print(f"{len(result.attempts)} request attempt(s), {len(result.findings)} finding(s); no result is automatically verified.")


@app.command()
def findings(
    json_output: Annotated[bool, typer.Option("--json", help="Print findings as JSON.")] = False,
) -> None:
    """List stored status-aware XSS and SQLi findings."""
    storage = get_storage()
    assessment = assessment_or_error(storage)
    rows = storage.list_findings(assessment_id=assessment.assessment_id)
    if json_output:
        console.print_json(json.dumps(rows))
        return
    if not rows:
        console.print("No findings recorded.")
        return
    table = Table("ID", "Kind", "Status", "Severity", "Confidence")
    for row in rows:
        table.add_row(str(row["id"]), row["kind"], row["status"], row["severity"] or "-", row["confidence"] or "-")
    console.print(table)



@app.command()
def report(
    output: Annotated[Path | None, typer.Option(help="Markdown output path.")] = None,
    json_output: Annotated[Path | None, typer.Option("--json-output", help="JSON output path.")] = None,
) -> None:
    """Generate sanitized Markdown and JSON assessment reports."""
    storage = get_storage()
    assessment = assessment_or_error(storage)
    markdown_path = output or AppConfig().data_dir / "report.md"
    json_path = json_output or AppConfig().data_dir / "report.json"
    write_report(storage, assessment, markdown_path, json_path)
    transition(storage, WorkflowState.REPORTED, assessment=assessment)
    AuditLogger(storage).record("report", "created", assessment_id=assessment.assessment_id)
    console.print(f"[green]Markdown report written to[/green] {markdown_path}")
    console.print(f"[green]JSON report written to[/green] {json_path}")


if __name__ == "__main__":
    app()
