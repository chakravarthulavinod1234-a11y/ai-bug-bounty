import json
import tomllib
from pathlib import Path

from bountypilot.scope import TargetScope


ROOT = Path(__file__).parents[1]


def test_pyproject_declares_console_script_and_small_runtime_dependency_set():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = data["project"]
    assert project["requires-python"] == ">=3.11"
    assert project["scripts"]["bountypilot"] == "bountypilot.cli:app"
    assert set(project["dependencies"]) == {
        "httpx>=0.27,<1",
        "pydantic>=2.6,<3",
        "rich>=13.7,<14",
        "typer>=0.12,<1",
    }
    assert project["optional-dependencies"]["test"] == ["pytest>=8,<9"]
    assert project["optional-dependencies"]["browser"] == ["playwright>=1.40,<2"]


def test_sample_scope_is_local_lab_only_and_validates():
    sample = json.loads((ROOT / "examples" / "scope.json").read_text(encoding="utf-8"))
    scope = TargetScope.model_validate(sample)
    assert len(scope.entries) == 1
    assert scope.entries[0].host == "127.0.0.1"
    assert scope.entries[0].ports == {3000}
    assert all("example.com" not in entry.host for entry in scope.entries)


def test_gitignore_covers_local_state_credentials_and_generated_reports():
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for pattern in (".venv/", ".env", ".bountypilot/", "*.sqlite3", "*.egg-info/", "report.md", "report.json", "*.pem", "credentials*.json"):
        assert pattern in ignore
