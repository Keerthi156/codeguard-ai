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
from datetime import datetime, timezone
from pathlib import Path

from app.ai.model_run import ModelRun
from app.findings.classifier import Finding
from app.runner.executor import Evidence, TestResult

DEFAULT_DB_PATH = Path("data") / "codeguard.db"
_BODY_LIMIT = 300
_BEARER = re.compile(r"Bearer\s+\S+", re.IGNORECASE)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    target_revision TEXT,
    provider TEXT NOT NULL DEFAULT '',
    model_name TEXT NOT NULL DEFAULT '',
    model_calls INTEGER NOT NULL DEFAULT 0,
    tests_proposed INTEGER NOT NULL DEFAULT 0,
    tests_accepted INTEGER NOT NULL DEFAULT 0,
    tests_rejected INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER,
    latency_ms INTEGER NOT NULL DEFAULT 0,
    model_summary TEXT NOT NULL DEFAULT ''
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
    label TEXT NOT NULL DEFAULT '',
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
            _ensure_label_column(connection)
            _ensure_scan_columns(connection)
            connection.commit()

    def save_finding(self, finding: Finding, results: Sequence[TestResult] = ()) -> int:
        """Insert a scan run, the finding, and sanitized evidence. Returns the run id."""
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT INTO scan_runs (created_at, target_revision) VALUES (?, ?)",
                (_iso(finding.created_at), finding.target_revision),
            )
            run_id = int(cursor.lastrowid or 0)
            _insert_finding(connection, run_id, finding, results)
            connection.commit()
        return run_id

    def save_scan(
        self,
        findings: Sequence[Finding],
        results: Sequence[TestResult] = (),
        model_run: ModelRun | None = None,
    ) -> int:
        """Insert one scan run and every finding, storing sanitized evidence only."""
        created_at = findings[0].created_at if findings else datetime.now(timezone.utc)
        revision = findings[0].target_revision if findings else None
        summary = "" if model_run is None else model_run.text()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO scan_runs (
                    created_at, target_revision, provider, model_name, model_calls,
                    tests_proposed, tests_accepted, tests_rejected, total_tokens,
                    latency_ms, model_summary
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _iso(created_at),
                    revision,
                    "" if model_run is None else model_run.provider,
                    "" if model_run is None else model_run.model_name,
                    0 if model_run is None else model_run.calls,
                    0 if model_run is None else model_run.proposed,
                    0 if model_run is None else model_run.accepted,
                    0 if model_run is None else model_run.rejected,
                    None if model_run is None else model_run.total_tokens,
                    0 if model_run is None else model_run.latency_ms,
                    summary,
                ),
            )
            run_id = int(cursor.lastrowid or 0)
            for finding in findings:
                connection.execute("DELETE FROM test_results WHERE finding_id = ?", (finding.id,))
                connection.execute("DELETE FROM findings WHERE id = ?", (finding.id,))
                _insert_finding(connection, run_id, finding, results)
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
                SELECT method, path, identity, status_code, body, label
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
                    label=item["label"] or "",
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


def _insert_finding(
    connection: sqlite3.Connection,
    run_id: int,
    finding: Finding,
    results: Sequence[TestResult],
) -> None:
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
            outcome, method, path, identity, body, label
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        _evidence_rows(finding, results),
    )


def _evidence_rows(finding: Finding, results: Sequence[TestResult]) -> list[tuple[object, ...]]:
    if finding.evidence:
        used: set[int] = set()
        rows: list[tuple[object, ...]] = []
        for index, item in enumerate(finding.evidence, start=1):
            matched = _match_result(item, results, used)
            rows.append(
                (
                    finding.id,
                    matched.test_id if matched is not None else f"{finding.id}-evidence-{index}",
                    item.status_code,
                    None if matched is None else matched.access,
                    None if matched is None else _flag(matched.matches_expected),
                    None if matched is None else matched.outcome,
                    item.method,
                    item.path,
                    item.identity,
                    _sanitize_body(item.body),
                    item.label,
                )
            )
        return rows
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
            result.evidence.label,
        )
        for result in results
        if _result_matches(result, finding)
    ]


def _ensure_scan_columns(connection: sqlite3.Connection) -> None:
    existing = {row[1] for row in connection.execute("PRAGMA table_info(scan_runs)")}
    additions = (
        ("provider", "TEXT NOT NULL DEFAULT ''"),
        ("model_name", "TEXT NOT NULL DEFAULT ''"),
        ("model_calls", "INTEGER NOT NULL DEFAULT 0"),
        ("tests_proposed", "INTEGER NOT NULL DEFAULT 0"),
        ("tests_accepted", "INTEGER NOT NULL DEFAULT 0"),
        ("tests_rejected", "INTEGER NOT NULL DEFAULT 0"),
        ("total_tokens", "INTEGER"),
        ("latency_ms", "INTEGER NOT NULL DEFAULT 0"),
        ("model_summary", "TEXT NOT NULL DEFAULT ''"),
    )
    for name, declaration in additions:
        if name not in existing:
            connection.execute(f"ALTER TABLE scan_runs ADD COLUMN {name} {declaration}")


def _ensure_label_column(connection: sqlite3.Connection) -> None:
    columns = {row[1] for row in connection.execute("PRAGMA table_info(test_results)")}
    if "label" not in columns:
        connection.execute("ALTER TABLE test_results ADD COLUMN label TEXT NOT NULL DEFAULT ''")


def _match_result(item: Evidence, results: Sequence[TestResult], used: set[int]) -> TestResult | None:
    for index, result in enumerate(results):
        if index in used:
            continue
        evidence = result.evidence
        if (
            evidence.method == item.method
            and evidence.path == item.path
            and evidence.identity == item.identity
            and evidence.status_code == item.status_code
        ):
            used.add(index)
            return result
    return None


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
