"""Vendor-neutral provider contracts for structured planning proposals."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol


import os


class PlanningProvider(Protocol):
    """A provider may propose structured actions but cannot execute tools."""

    def propose_actions(self, context: dict[str, Any]) -> Sequence[dict[str, Any]]:
        """Return JSON-like action objects for trusted application validation."""
        ...


class StaticPlanningProvider:
    """Small adapter useful for configuration and tests without a network call."""

    def __init__(self, actions: Sequence[dict[str, Any]]) -> None:
        self.actions = list(actions)

    def propose_actions(self, context: dict[str, Any]) -> Sequence[dict[str, Any]]:
        del context
        return list(self.actions)


def load_provider_from_env() -> PlanningProvider | None:
    """Load configured AI provider adapter based on environment variables.

    Defaults to None, which signals Planner to use the deterministic RuleBasedPlanner.
    """
    provider_name = os.getenv("BOUNTYPILOT_LLM_PROVIDER", "none").strip().lower()
    if provider_name in {"", "none", "local", "rule_based"}:
        return None
    if provider_name in {"static", "mock"}:
        return StaticPlanningProvider([])
    raise ValueError(
        f"unsupported BOUNTYPILOT_LLM_PROVIDER '{provider_name}'; "
        "valid options are 'none' (default local rule-based planner) or 'mock'"
    )

