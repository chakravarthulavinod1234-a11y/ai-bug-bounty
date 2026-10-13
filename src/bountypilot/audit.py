import json
from typing import Any

from .reporting import sanitize
from .storage import Storage


class AuditLogger:
    """Record decisions without storing response bodies or secrets."""

    def __init__(self, storage: Storage) -> None:
        self.storage = storage

    def record(self, action: str, decision: str, **details: Any) -> None:
        safe_details = {
            key: value
            for key, value in details.items()
            if key.lower() not in {"body", "response_body", "raw_body"}
        }
        sanitized = sanitize(safe_details)
        with self.storage._connect() as db:
            db.execute(
                "INSERT INTO audit_log(action, decision, details_json) VALUES (?, ?, ?)",
                (action, decision, json.dumps(sanitized)),
            )

