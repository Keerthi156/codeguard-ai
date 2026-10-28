"""SQLite persistence for sanitized findings."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from app.findings.classifier import Finding
from app.findings.store import FindingStore
from app.runner.executor import Evidence


def test_store_saves_and_reloads_finding(tmp_path) -> None:
    database = tmp_path / "nested" / "codeguard.db"
    finding = Finding(
        id="get-documents-id",
        route="/documents/{id}",
        method="GET",
        status="Confirmed",
        reason="A non-owner received access the matrix denies",
        evidence=[
            Evidence(
                method="GET",
                path="/documents/101",
                identity="bob' OR '1'='1",
                status_code=200,
                body="Bearer secret-token was not stored",
            )
        ],
        source_lines=[74, 77],
        created_at=datetime(2026, 10, 27, 21, 0, tzinfo=timezone.utc),
        target_revision="abc123def",
    )
    store = FindingStore(database)

    run_id = store.save_finding(finding)
    loaded = store.load_finding(finding.id)

    assert database.is_file()
    assert run_id == 1
    assert loaded.id == finding.id
    assert loaded.route == finding.route
    assert loaded.method == "GET"
    assert loaded.status == "Confirmed"
    assert loaded.reason == finding.reason
    assert loaded.source_lines == [74, 77]
    assert loaded.created_at == finding.created_at
    assert loaded.target_revision == "abc123def"
    assert loaded.evidence[0].identity == "bob' OR '1'='1"
    assert loaded.evidence[0].path == "/documents/101"
    assert loaded.evidence[0].status_code == 200
    assert "secret-token" not in loaded.evidence[0].body
    assert "Bearer [redacted]" in loaded.evidence[0].body
    assert b"secret-token" not in database.read_bytes()

    with sqlite3.connect(database) as connection:
        runs = connection.execute("SELECT COUNT(*) FROM scan_runs").fetchone()
        stored = connection.execute(
            "SELECT body FROM test_results WHERE finding_id = ?",
            (finding.id,),
        ).fetchone()
    assert runs is not None and runs[0] == 1
    assert stored is not None
    assert "secret-token" not in stored[0]
