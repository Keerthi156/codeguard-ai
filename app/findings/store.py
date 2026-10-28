"""SQLite persistence for findings and sanitized test evidence.

The database file is created on demand at data/codeguard.db. Queries are
parameterized. Authorization headers and bearer tokens are not stored.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from app.findings.classifier import Finding
from app.runner.executor import Evidence, TestResult

DEFAULT_DB_PATH = Path("data") / "codeguard.db"
_BODY_LIMIT = 300
_BEARER = re.compile(r"Bearer\s+\S+", re.IGNORECASE)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    target_revision TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_run_id INTEGER NOT NULL,
    route TEXT NOT NULL,
    method TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL,
    source_lines TEXT NOT NULL,
    created_at TEXT NOT NULL,
    target_revision TEXT,
    FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
);

CREATE TABLE IF NOT EXISTS test_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    test_id TEXT NOT NULL,
    status_code INTEGER,
    access TEXT,
    matches_expected INTEGER,
    outcome TEXT,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    identity TEXT NOT NULL,
    body TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);
"""


class FindingStore:
    """Store findings and sanitized evidence in SQLite."""

    def __init__(self, path: str | Path = DEFAULT_DB_PATH) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(_SCHEMA)
            connection.commit()

    def save_finding(self, finding: Finding, results: Sequence[TestResult] = ()) -> int:
        """Insert a scan run, the finding, and sanitized evidence. Returns the run id."""
        evidence_rows = _evidence_rows(finding, results)
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT INTO scan_runs (created_at, target_revision) VALUES (?, ?)",
                (_iso(finding.created_at), finding.target_revision),
            )
            run_id = int(cursor.lastrowid or 0)
            connection.execute(
                """
                INSERT INTO findings (
                    id, scan_run_id, route, method, status, reason,
                    source_lines, created_at, target_revision
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.id,
                    run_id,
                    finding.route,
                    finding.method,
                    finding.status,
                    finding.reason,
                    json.dumps(finding.source_lines),
                    _iso(finding.created_at),
                    finding.target_revision,
                ),
            )
            connection.executemany(
                """
                INSERT INTO test_results (
                    finding_id, test_id, status_code, access, matches_expected,
                    outcome, method, path, identity, body
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                evidence_rows,
            )
            connection.commit()
        return run_id

    def load_finding(self, finding_id: str) -> Finding:
        """Reload one finding and its sanitized evidence."""
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, route, method, status, reason, source_lines, created_at, target_revision
                FROM findings
                WHERE id = ?
                """,
                (finding_id,),
            ).fetchone()
            if row is None:
                raise KeyError(finding_id)
            evidence_rows = connection.execute(
                """
                SELECT method, path, identity, status_code, body
                FROM test_results
                WHERE finding_id = ?
                ORDER BY id
                """,
                (finding_id,),
            ).fetchall()
        return Finding(
            id=row["id"],
            route=row["route"],
            method=row["method"],
            status=row["status"],
            reason=row["reason"],
            evidence=[
                Evidence(
                    method=item["method"],
                    path=item["path"],
                    identity=item["identity"],
                    status_code=item["status_code"],
                    body=_sanitize_body(item["body"]),
                )
                for item in evidence_rows
            ],
            source_lines=json.loads(row["source_lines"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            target_revision=row["target_revision"],
        )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            yield connection
        finally:
            connection.close()


def _evidence_rows(finding: Finding, results: Sequence[TestResult]) -> list[tuple[object, ...]]:
    selected = [result for result in results if _result_matches(result, finding)]
    if selected:
        return [
            (
                finding.id,
                result.test_id,
                result.status_code,
                result.access,
                _flag(result.matches_expected),
                result.outcome,
                result.evidence.method,
                result.evidence.path,
                result.evidence.identity,
                _sanitize_body(result.evidence.body),
            )
            for result in selected
        ]
    return [
        (
            finding.id,
            f"{finding.id}-evidence-{index}",
            item.status_code,
            None,
            None,
            None,
            item.method,
            item.path,
            item.identity,
            _sanitize_body(item.body),
        )
        for index, item in enumerate(finding.evidence, start=1)
    ]


def _result_matches(result: TestResult, finding: Finding) -> bool:
    if result.evidence.method.upper() != finding.method.upper():
        return False
    return result.evidence.path == finding.route or finding.route.split("{", 1)[0] in result.evidence.path


def _flag(value: bool | None) -> int | None:
    if value is None:
        return None
    return 1 if value else 0


def _sanitize_body(body: str) -> str:
    return _BEARER.sub("Bearer [redacted]", body)[:_BODY_LIMIT]


def _iso(value: datetime) -> str:
    return value.isoformat()
