"""Persisted, explicit assessment lifecycle for the CLI workflow."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from .scope import TargetScope
from .storage import Storage


class WorkflowState(StrEnum):
    INITIALIZED = "initialized"
    STARTED = "started"
    PLAN_READY = "plan_ready"
    RECON_COMPLETE = "recon_complete"
    CHECKS_COMPLETE = "checks_complete"
    REPORTED = "reported"
    STOPPED = "stopped"


class Assessment(BaseModel):
    """Assessment identity and lifecycle state; active approval is never persisted as true."""

    model_config = ConfigDict(extra="forbid")
    assessment_id: str = Field(min_length=1)
    started_at: str
    target_description: str = Field(min_length=1, max_length=200)
    state: WorkflowState
    scope: TargetScope
    active_approval_consumed: bool = False


def initialize_project(storage: Storage) -> None:
    """Create deny-by-default project metadata without starting an assessment."""
    storage.set_metadata("assessment", None)
    storage.set_metadata("workflow_state", WorkflowState.INITIALIZED.value)
    storage.set_metadata("kill_switch", False)


def start_assessment(storage: Storage, scope: TargetScope, target_description: str) -> Assessment:
    """Start a new assessment only when at least one explicit target exists."""
    if not scope.entries:
        raise ValueError("cannot start an assessment with an empty authorized scope")
    assessment = Assessment(
        assessment_id=f"bp-{uuid4().hex[:12]}",
        started_at=datetime.now(timezone.utc).isoformat(),
        target_description=target_description,
        state=WorkflowState.STARTED,
        scope=scope,
    )
    save_assessment(storage, assessment)
    return assessment


def load_assessment(storage: Storage) -> Assessment | None:
    raw = storage.get_metadata("assessment")
    if raw is None:
        return None
    return Assessment.model_validate(raw)


def save_assessment(storage: Storage, assessment: Assessment) -> None:
    storage.set_metadata("assessment", assessment.model_dump(mode="json"))
    storage.set_metadata("workflow_state", assessment.state.value)


def require_assessment(storage: Storage) -> Assessment:
    assessment = load_assessment(storage)
    if assessment is None:
        raise ValueError("no assessment is active; run bountypilot start after configuring scope")
    return assessment


def transition(storage: Storage, state: WorkflowState, *, assessment: Assessment | None = None) -> Assessment:
    current = assessment or require_assessment(storage)
    updated = current.model_copy(update={"state": state})
    save_assessment(storage, updated)
    return updated


def update_metadata(storage: Storage, key: str, value: Any) -> None:
    """Store structured workflow artifacts under a namespaced metadata key."""
    storage.set_metadata(f"workflow.{key}", value)
