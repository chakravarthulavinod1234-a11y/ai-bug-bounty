"""Application configuration and local state paths."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field


class AppConfig(BaseModel):
    """Paths and safety defaults used by the CLI."""

    data_dir: Path = Field(default=Path(".bountypilot"))
    database_name: str = "bountypilot.sqlite3"

    @property
    def database_path(self) -> Path:
        return self.data_dir / self.database_name
