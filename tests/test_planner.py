import pytest

from bountypilot.planner import Planner
from bountypilot.policy import PolicyEngine
from bountypilot.providers import StaticPlanningProvider
from bountypilot.scope import ScopeEntry, TargetScope


def make_scope(*, active: bool = False, excluded_categories: set[str] | None = None, excluded_methods: set[str] | None = None) -> TargetScope:
    return TargetScope(
        entries=[ScopeEntry(host="127.0.0.1", schemes={"http"}, ports={3000}, paths=["/"])],
        active_testing=active,
        excluded_categories=excluded_categories or set(),
        excluded_methods=excluded_methods or set(),
    )


def test_local_planner_produces_passive_plan_without_provider():
    scope = make_scope(active=False)
    plan = Planner(scope, PolicyEngine(scope)).create_plan(target_description="Juice Shop lab")

    assert plan.generated_by == "rule_based"
    assert plan.actions
    assert all(action.category == "passive_recon" for action in plan.actions)
    assert all(not action.requires_approval for action in plan.actions)
    assert all(action.policy_reason for action in plan.actions)
    assert [action.priority for action in plan.actions] == sorted(action.priority for action in plan.actions)


def test_local_planner_distinguishes_active_actions_and_execution_requires_approval():
    scope = make_scope(active=True)
    planner = Planner(scope, PolicyEngine(scope))
    plan = planner.create_plan()

    active_action = next(action for action in plan.actions if action.category == "xss")
    assert active_action.requires_approval
    assert not planner.authorize_for_execution(active_action).allowed
    assert planner.authorize_for_execution(active_action, confirmed=True).allowed


def test_local_planner_respects_category_exclusions_and_ipv6_scope():
    scope = TargetScope(
        entries=[ScopeEntry(host="::1", schemes={"http"}, ports={3000, 3001}, paths=["/"])],
        active_testing=True,
    )
    plan = Planner(scope, PolicyEngine(scope)).create_plan(excluded_categories={"xss"})

    assert all(action.category != "xss" for action in plan.actions)
    assert any(action.category == "sqli" for action in plan.actions)
    assert all("http://[::1]:" in action.url for action in plan.actions)
    assert {action.url for action in plan.actions if action.category == "passive_recon"} == {
        "http://[::1]:3000/",
        "http://[::1]:3001/",
    }


def test_mocked_provider_actions_are_structured_and_policy_checked():
    scope = make_scope(active=True)
    provider = StaticPlanningProvider(
        [
            {
                "action_id": "headers",
                "category": "passive_recon",
                "name": "Inspect headers",
                "url": "http://127.0.0.1:3000/",
                "method": "GET",
                "purpose": "Understand server metadata.",
                "expected_evidence": ["headers"],
                "verification_criteria": ["response received"],
                "priority": 1,
                "risk": "low",
                "requires_approval": False,
            }
        ]
    )

    plan = Planner(scope, PolicyEngine(scope), provider).create_plan()

    assert plan.generated_by == "provider"
    assert plan.actions[0].action_id == "headers"


def test_provider_out_of_scope_action_is_rejected():
    scope = make_scope(active=True)
    provider = StaticPlanningProvider(
        [
            {
                "action_id": "outside",
                "category": "passive_recon",
                "name": "Outside target",
                "url": "https://example.com/",
                "method": "GET",
                "purpose": "This must not be accepted.",
                "expected_evidence": ["none"],
                "verification_criteria": ["never"],
                "priority": 1,
                "risk": "low",
                "requires_approval": False,
            }
        ]
    )

    with pytest.raises(ValueError, match="rejected by policy"):
        Planner(scope, PolicyEngine(scope), provider).create_plan()


def test_provider_cannot_use_excluded_category_or_unsafe_method():
    scope = make_scope(active=True, excluded_categories={"xss"}, excluded_methods={"POST"})
    xss_provider = StaticPlanningProvider(
        [
            {
                "action_id": "blocked-xss",
                "category": "xss",
                "name": "Blocked XSS",
                "url": "http://127.0.0.1:3000/",
                "method": "GET",
                "purpose": "Blocked.",
                "expected_evidence": ["none"],
                "verification_criteria": ["never"],
                "priority": 1,
                "risk": "high",
                "requires_approval": True,
            }
        ]
    )
    with pytest.raises(ValueError, match="excluded test category"):
        Planner(scope, PolicyEngine(scope), xss_provider).create_plan()

    post_provider = StaticPlanningProvider(
        [
            {
                "action_id": "blocked-post",
                "category": "passive_recon",
                "name": "Blocked POST",
                "url": "http://127.0.0.1:3000/",
                "method": "POST",
                "purpose": "Blocked.",
                "expected_evidence": ["none"],
                "verification_criteria": ["never"],
                "priority": 1,
                "risk": "low",
                "requires_approval": False,
            }
        ]
    )
    with pytest.raises(ValueError, match="HTTP method is explicitly excluded"):
        Planner(scope, PolicyEngine(scope), post_provider).create_plan()


def test_provider_active_action_must_require_approval_and_active_scope():
    action = {
        "action_id": "xss-1",
        "category": "xss",
        "name": "XSS",
        "url": "http://127.0.0.1:3000/",
        "method": "GET",
        "purpose": "Active check.",
        "expected_evidence": ["marker"],
        "verification_criteria": ["reproducible"],
        "priority": 1,
        "risk": "high",
        "requires_approval": False,
    }
    with pytest.raises(ValueError, match="must require approval"):
        Planner(make_scope(active=True), PolicyEngine(make_scope(active=True)), StaticPlanningProvider([action])).create_plan()
    with pytest.raises(ValueError, match="must be labeled high risk"):
        Planner(
            make_scope(active=True),
            PolicyEngine(make_scope(active=True)),
            StaticPlanningProvider([{**action, "requires_approval": True, "risk": "medium"}]),
        ).create_plan()
    with pytest.raises(ValueError, match="active testing while active testing is disabled"):
        Planner(make_scope(active=False), PolicyEngine(make_scope(active=False)), StaticPlanningProvider([action])).create_plan()


def test_load_provider_from_env(monkeypatch):
    from bountypilot.providers import load_provider_from_env, StaticPlanningProvider
    monkeypatch.delenv("BOUNTYPILOT_LLM_PROVIDER", raising=False)
    assert load_provider_from_env() is None

    monkeypatch.setenv("BOUNTYPILOT_LLM_PROVIDER", "none")
    assert load_provider_from_env() is None

    monkeypatch.setenv("BOUNTYPILOT_LLM_PROVIDER", "mock")
    prov = load_provider_from_env()
    assert isinstance(prov, StaticPlanningProvider)

    monkeypatch.setenv("BOUNTYPILOT_LLM_PROVIDER", "unsupported_provider")
    with pytest.raises(ValueError, match="unsupported BOUNTYPILOT_LLM_PROVIDER"):
        load_provider_from_env()

