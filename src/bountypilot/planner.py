"""Policy-checked security testing plans with a rule-based fallback."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from typing import Any, Literal
from urllib.parse import urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .policy import PolicyDecision, PolicyEngine
from .providers import PlanningProvider
from .scope import TargetScope

ActionCategory = Literal["passive_recon", "xss", "sqli"]
RiskLevel = Literal["low", "medium", "high"]
SUPPORTED_CATEGORIES = frozenset({"passive_recon", "xss", "sqli"})
ACTIVE_CATEGORIES = frozenset({"xss", "sqli"})


class PlanningContext(BaseModel):
    """Validated input supplied to a provider; no shell or tool handles exist."""

    model_config = ConfigDict(extra="forbid")
    scope: TargetScope
    target_description: str = Field(default="authorized target", min_length=1, max_length=200)
    excluded_categories: set[str] = Field(default_factory=set)

    @field_validator("excluded_categories", mode="before")
    @classmethod
    def normalize_categories(cls, values: Iterable[str]) -> set[str]:
        return {str(value).strip().lower() for value in values}


class PlanAction(BaseModel):
    """One proposed action, awaiting trusted policy validation and execution."""

    model_config = ConfigDict(extra="forbid")
    action_id: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9][a-z0-9_-]*$")
    category: ActionCategory
    name: str = Field(min_length=1, max_length=120)
    url: str
    method: str = "GET"
    purpose: str = Field(min_length=1, max_length=500)
    expected_evidence: list[str] = Field(min_length=1, max_length=10)
    verification_criteria: list[str] = Field(min_length=1, max_length=10)
    priority: int = Field(ge=1, le=100)
    risk: RiskLevel
    requires_approval: bool
    policy_reason: str | None = None

    @field_validator("method", mode="before")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return str(value).upper()

    @field_validator("expected_evidence", "verification_criteria", mode="before")
    @classmethod
    def normalize_lists(cls, values: Iterable[str]) -> list[str]:
        result = [str(value).strip() for value in values if str(value).strip()]
        if not result:
            raise ValueError("must contain at least one non-empty item")
        return result

    def is_active(self) -> bool:
        return self.category in ACTIVE_CATEGORIES


class SecurityPlan(BaseModel):
    """Ordered, fully policy-validated plan; it contains proposals only."""

    model_config = ConfigDict(extra="forbid")
    target_description: str
    actions: list[PlanAction]
    generated_by: Literal["rule_based", "provider"]
    active_approval_required: bool

    @field_validator("actions")
    @classmethod
    def require_ordered_unique_actions(cls, actions: list[PlanAction]) -> list[PlanAction]:
        ids = [action.action_id for action in actions]
        if len(ids) != len(set(ids)):
            raise ValueError("plan action IDs must be unique")
        if actions != sorted(actions, key=lambda action: (action.priority, action.action_id)):
            raise ValueError("plan actions must be ordered by priority")
        return actions


class RuleBasedPlanner:
    """Deterministic fallback used when no provider is configured."""

    def propose(self, context: PlanningContext) -> list[dict[str, Any]]:
        actions: list[dict[str, Any]] = []
        for index, url in enumerate(_authorized_urls(context.scope), start=1):
            actions.append(
                {
                    "action_id": f"recon-{index}",
                    "category": "passive_recon",
                    "name": "Collect HTTP metadata",
                    "url": url,
                    "method": "GET",
                    "purpose": "Observe response status, headers, and content type without sending attack payloads.",
                    "expected_evidence": ["status code", "response headers", "content type"],
                    "verification_criteria": ["request completed within configured timeout", "response metadata is recorded without storing secrets"],
                    "priority": index,
                    "risk": "low",
                    "requires_approval": False,
                }
            )
            if context.scope.active_testing and "xss" not in context.excluded_categories and "xss" not in context.scope.excluded_categories:
                actions.append(_active_action("xss", url, index + 10, "reflected XSS candidate screening"))
            if context.scope.active_testing and "sqli" not in context.excluded_categories and "sqli" not in context.scope.excluded_categories:
                actions.append(_active_action("sqli", url, index + 20, "SQL injection candidate screening"))
        return actions


def _active_action(category: str, url: str, priority: int, label: str) -> dict[str, Any]:
    return {
        "action_id": f"{category}-{priority}",
        "category": category,
        "name": label,
        "url": url,
        "method": "GET",
        "purpose": "Propose a conservative local-lab check; do not execute until the operator explicitly approves it.",
        "expected_evidence": ["request/response pair", "sanitized marker observation"],
        "verification_criteria": ["scope remains valid", "evidence is reproducible", "finding is not reported without verification"],
        "priority": priority,
        "risk": "high",
        "requires_approval": True,
    }


def _authorized_urls(scope: TargetScope) -> list[str]:
    urls: list[str] = []
    for entry in scope.entries:
        for scheme in sorted(entry.schemes):
            for port in sorted(entry.ports) if entry.ports else [None]:
                host = f"[{entry.host}]" if _is_ipv6(entry.host) else entry.host
                netloc = host if port is None else f"{host}:{port}"
                for path in entry.paths:
                    urls.append(urlunsplit((scheme, netloc, path, "", "")))
    return sorted(set(urls))


def _is_ipv6(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).version == 6
    except ValueError:
        return False


class Planner:
    """Build and validate plans; provider output is never trusted directly."""

    def __init__(self, scope: TargetScope, policy: PolicyEngine, provider: PlanningProvider | None = None) -> None:
        self.scope = scope
        self.policy = policy
        self.provider = provider
        self.fallback = RuleBasedPlanner()

    def create_plan(self, *, target_description: str = "authorized target", excluded_categories: set[str] | None = None) -> SecurityPlan:
        context = PlanningContext(scope=self.scope, target_description=target_description, excluded_categories=excluded_categories or set())
        if not context.excluded_categories <= SUPPORTED_CATEGORIES:
            unsupported = sorted(context.excluded_categories - SUPPORTED_CATEGORIES)
            raise ValueError(f"unsupported excluded test categories: {', '.join(unsupported)}")
        if self.provider is None:
            raw_actions = self.fallback.propose(context)
            generated_by: Literal["rule_based", "provider"] = "rule_based"
        else:
            raw_actions = self.provider.propose_actions(context.model_dump(mode="json"))
            generated_by = "provider"
        actions = [self._validate_action(raw, excluded_categories=context.excluded_categories) for raw in raw_actions]
        actions.sort(key=lambda action: (action.priority, action.action_id))
        return SecurityPlan(
            target_description=target_description,
            actions=actions,
            generated_by=generated_by,
            active_approval_required=any(action.is_active() for action in actions),
        )

    def _validate_action(self, raw: dict[str, Any], *, excluded_categories: set[str]) -> PlanAction:
        try:
            action = PlanAction.model_validate(raw)
        except Exception as exc:
            raise ValueError(f"provider returned an invalid plan action: {exc}") from exc
        if action.category in self.scope.excluded_categories or action.category in excluded_categories:
            raise ValueError(f"plan action {action.action_id} uses an excluded test category")
        if action.category in ACTIVE_CATEGORIES and not self.scope.active_testing:
            raise ValueError(f"plan action {action.action_id} proposes active testing while active testing is disabled")
        if action.category in ACTIVE_CATEGORIES and not action.requires_approval:
            raise ValueError(f"plan action {action.action_id} must require approval")
        if action.category in ACTIVE_CATEGORIES and action.risk != "high":
            raise ValueError(f"plan action {action.action_id} must be labeled high risk")
        if action.category == "passive_recon" and action.requires_approval:
            raise ValueError(f"passive action {action.action_id} cannot be marked as active approval-required")
        decision: PolicyDecision = self.policy.validate_proposal(action.url, category=action.category, method=action.method)
        if not decision.allowed:
            raise ValueError(f"plan action {action.action_id} rejected by policy: {decision.reason}")
        return action.model_copy(update={"policy_reason": decision.reason})

    def authorize_for_execution(self, action: PlanAction, *, confirmed: bool = False) -> PolicyDecision:
        """Execution gate; callers must explicitly approve active actions."""
        return self.policy.authorize(action.url, active=action.is_active(), confirmed=confirmed, method=action.method, category=action.category)
