"""Safe Markdown and JSON reporting for persisted BountyPilot assessments."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .scope import TargetScope
from .storage import Storage
from .workflow import Assessment

_SECRET_KEY_PARTS = (
    "password",
    "passwd",
    "token",
    "secret",
    "cookie",
    "authorization",
    "credential",
    "api_key",
    "apikey",
    "access_token",
    "private_key",
    "session",
)

_SECRET_VALUE = re.compile(
    r"(bearer\s+)[A-Za-z0-9._~+/=-]+|(password|passwd|token|secret|sessionid|api_key|apikey|access_token)=([^&\s]+)",
    re.IGNORECASE,
)


def _safe_text(value: str) -> str:
    value = _SECRET_VALUE.sub("[redacted]", value)
    return value[:2_000]



def sanitize(value: Any, key: str = "") -> Any:
    """Remove common secret-bearing fields and redact secret-like text."""
    if any(part in key.lower() for part in _SECRET_KEY_PARTS):
        return "[redacted]"
    if isinstance(value, str):
        return _safe_text(value)
    if isinstance(value, dict):
        return {str(k): sanitize(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize(item, key) for item in value]
    return value


def _scope_summary(scope: TargetScope) -> dict[str, Any]:
    return {
        "entries": [
            {
                "host": entry.host,
                "schemes": sorted(entry.schemes),
                "ports": sorted(entry.ports),
                "paths": entry.paths,
                "excluded_paths": entry.excluded_paths,
            }
            for entry in scope.entries
        ],
        "active_testing": scope.active_testing,
        "excluded_methods": sorted(scope.excluded_methods),
        "excluded_categories": sorted(scope.excluded_categories),
        "request_timeout_seconds": scope.request_timeout_seconds,
        "requests_per_second": scope.requests_per_second,
    }


def _finding_summary(row: dict[str, Any]) -> dict[str, Any]:
    evidence = sanitize(row.get("evidence", {}))
    kind = row.get("kind", "unknown")
    status = row.get("status", "Unknown")
    if kind == "xss":
        reproduction = [
            "Use the authorized endpoint and input location shown in the evidence.",
            "Repeat the same controlled input in the saved result; do not use it against an unauthorized target.",
            "For Verified XSS only, repeat browser verification in an isolated lab context.",
        ]
        impact = "Potential client-side script execution in the affected input context; impact depends on encoding, browser context, and reachable data."
        remediation = "Apply context-aware output encoding, use safe DOM APIs, validate input where appropriate, and deploy a restrictive Content Security Policy."
    elif kind == "sqli":
        reproduction = [
            "Use the authorized endpoint and parameter shown in the evidence.",
            "Send the saved baseline input, then the small controlled probe values, one request at a time.",
            "Compare status, bounded response context, and response behavior; do not escalate to extraction or destructive queries.",
        ]
        impact = "Potential server-side query manipulation; actual impact is unverified unless separately confirmed in the authorized lab."
        remediation = "Use parameterized queries or prepared statements, avoid string-built SQL, constrain database privileges, and return generic error messages."
    else:
        reproduction = ["Review the stored evidence and audit trail in the authorized assessment workspace."]
        impact = "Impact has not been classified."
        remediation = "Investigate the observed behavior and apply the least-privilege remediation appropriate to the confirmed root cause."
    return {
        "id": row.get("id"),
        "kind": kind,
        "created_at": row.get("created_at"),
        "status": status,
        "severity": row.get("severity"),
        "confidence": row.get("confidence"),
        "affected_endpoint": _affected_endpoint(evidence),
        "input_location": _input_location(evidence),
        "evidence": evidence,
        "reproduction_steps": reproduction,
        "impact": impact,
        "suggested_remediation": remediation,
    }


def _affected_endpoint(evidence: Any) -> str | None:
    if isinstance(evidence, dict):
        candidate = evidence.get("candidate")
        if isinstance(candidate, dict):
            return candidate.get("url")
    return None


def _input_location(evidence: Any) -> str | None:
    if isinstance(evidence, dict):
        candidate = evidence.get("candidate")
        if isinstance(candidate, dict):
            location = candidate.get("location")
            parameter = candidate.get("parameter")
            if location and parameter:
                return f"{location} parameter: {parameter}"
    return None


def build_report(storage: Storage, assessment: Assessment, *, now: str | None = None) -> dict[str, Any]:
    """Build a sanitized report payload without including raw secrets or bodies."""
    findings = [_finding_summary(row) for row in storage.list_findings(assessment_id=assessment.assessment_id)]
    events = storage.list_audit_events(limit=500)
    testing = sorted({event["action"] for event in events if event["action"] not in {"init", "scope.validate", "start", "stop", "report"}})
    not_performed = [
        "No tests outside the configured scope were performed.",
        "No credential attacks, login bypass, destructive actions, data extraction, or table dumping were performed.",
    ]
    if not any(event["action"].startswith("recon") for event in events):
        not_performed.append("Passive reconnaissance was not run.")
    if not any(event["action"].startswith("xss") for event in events):
        not_performed.append("XSS checks were not run.")
    if not any(event["action"].startswith("sqli") for event in events):
        not_performed.append("SQL injection checks were not run.")
    payload = {
        "assessment_id": assessment.assessment_id,
        "generated_at": now or datetime.now(timezone.utc).isoformat(),
        "assessment_started_at": assessment.started_at,
        "target_description": assessment.target_description,
        "authorized_scope": _scope_summary(assessment.scope),
        "testing_performed": testing,
        "findings": findings,
        "limitations_and_tests_not_performed": not_performed,
    }
    return sanitize(payload)


def render_markdown(report: dict[str, Any]) -> str:
    """Render a readable Markdown report from the sanitized payload."""
    scope = report.get("authorized_scope", {})
    if not isinstance(scope, dict):
        scope = {"entries": []}
    lines = [
        "# BountyPilot AI Security Assessment",
        "",
        f"- **Assessment identifier:** `{report['assessment_id']}`",
        f"- **Generated at:** `{report['generated_at']}`",
        f"- **Assessment started:** `{report['assessment_started_at']}`",
        f"- **Target description:** {report['target_description']}",
        "",
        "## Authorized scope",
        "",
    ]
    for entry in scope.get("entries", []):

        ports = ", ".join(str(port) for port in entry["ports"]) or "default ports"
        lines.append(f"- `{entry['host']}` ({', '.join(entry['schemes'])}; {ports}) paths: {', '.join(f'`{path}`' for path in entry['paths'])}")
        if entry["excluded_paths"]:
            lines.append(f"  - Excluded paths: {', '.join(f'`{path}`' for path in entry['excluded_paths'])}")
    lines.extend(["", "## Testing performed", ""])
    lines.extend(f"- `{item}`" for item in report["testing_performed"])
    lines.extend(["", "## Findings", ""])
    findings = report["findings"]
    if not findings:
        lines.append("No findings were recorded.")
    for finding in findings:
        lines.extend([
            f"### {finding['kind'].upper()} — {finding['status']}",
            "",
            f"- **Finding ID:** `{finding['id']}`",
            f"- **Severity:** {finding['severity'] or 'not assigned'}",
            f"- **Confidence:** {finding['confidence'] or 'not assigned'}",
            f"- **Affected endpoint:** `{finding['affected_endpoint'] or 'not available'}`",
            f"- **Input location:** {finding['input_location'] or 'not available'}",
            "",
            "**Evidence**",
            "",
            "```json",
            json.dumps(finding["evidence"], indent=2),
            "```",
            "",
            "**Reproduction steps**",
            "",
        ])
        lines.extend(f"{index}. {step}" for index, step in enumerate(finding["reproduction_steps"], 1))
        lines.extend(["", f"**Impact:** {finding['impact']}", "", f"**Suggested remediation:** {finding['suggested_remediation']}", ""])
    lines.extend(["## Limitations and tests not performed", ""])
    lines.extend(f"- {item}" for item in report["limitations_and_tests_not_performed"])
    lines.append("")
    return "\n".join(lines)


def write_report(storage: Storage, assessment: Assessment, markdown_path: Path, json_path: Path) -> dict[str, Any]:
    report = build_report(storage, assessment)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
