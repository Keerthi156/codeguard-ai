"""The HTML report is rendered from SQLite and does not touch the network."""

from __future__ import annotations

import json
import re
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from app.ai.model_run import ModelRun
from app.cli import main
from app.findings.classifier import Finding
from app.findings.store import FindingStore
from app.runner.executor import Evidence

_FOOTER = (
    "Built during the Meta Global AI Developer Hackathon (Oct 27 to Nov 4, 2026). "
    "Fixtures are intentionally vulnerable and for local use only."
)
ROOT = Path(__file__).resolve().parents[1]
VULNERABLE = ROOT / "fixtures" / "codeguard.vulnerable.yaml"
SECURE = ROOT / "fixtures" / "codeguard.secure.yaml"
_WHEN = datetime(2026, 10, 29, 18, 0, tzinfo=timezone.utc)
_LONG_BEFORE = (
    "GET /documents/101 as bob: 200 allowed; "
    "GET /documents/101 as unauthenticated: 200 allowed; "
    "GET /documents/202 as bob: 401 denied"
)
_LONG_AFTER = (
    "GET /documents/101 as bob: 404 denied; "
    "GET /documents/101 as unauthenticated: 401 denied; "
    "GET /documents/202 as bob: 404 denied"
)
_DIFF = "\n".join(
    (
        "--- a/app.py",
        "+++ b/app.py",
        "@@ -1,1 +1,2 @@",
        "-    return document",
        "+    if document.owner != user:",
        "",
    )
)


def test_vulnerable_report_lists_both_routes(tmp_path: Path) -> None:
    database = tmp_path / "codeguard.db"
    out = tmp_path / "latest.html"
    _seed_verified(database, model_name="muse-spark-1.3")

    code = main(["report", "--config", str(VULNERABLE), "--db", str(database), "--out", str(out)])
    page = out.read_text(encoding="utf-8")

    assert code == 0
    assert "GET /documents/{id}" in page
    assert "PUT /documents/{id}" in page
    assert "VERIFIED" in page
    assert "Verified and Hardened" in page
    assert 'class="badge ok"' in page
    assert "if document.owner != user" in page
    assert "muse-spark-1.3" in page
    assert "EXPLOIT (non-owner bob):" in page
    assert "CONTROL (owner alice):" in page
    assert "DENIED (unauthenticated):" in page
    assert "What this shows:" in page
    assert _FOOTER in page
    assert "No Confirmed findings" not in page


def test_stored_markup_is_escaped(tmp_path: Path) -> None:
    database = tmp_path / "codeguard.db"
    out = tmp_path / "latest.html"
    _seed_verified(
        database,
        reason="<script>alert(1)</script>",
        root_cause="<script>alert(1)</script>",
        diff=_DIFF + "\n+    # <script>alert(1)</script>\n",
    )

    code = main(["report", "--config", str(VULNERABLE), "--db", str(database), "--out", str(out)])
    page = out.read_text(encoding="utf-8")

    assert code == 0
    assert "<script>" not in page
    assert "&lt;script&gt;" in page


def test_stored_tokens_are_redacted(tmp_path: Path) -> None:
    database = tmp_path / "codeguard.db"
    out = tmp_path / "latest.html"
    _seed_verified(
        database,
        reason="owner check missing sk-supersecretvalue",
        body="Bearer bob-token-value",
        diff=_DIFF + "\n+    # fw_live_examplekey sk-supersecretvalue\n",
        root_cause="handler skips ownership b10_examplekey99",
    )

    code = main(["report", "--config", str(VULNERABLE), "--db", str(database), "--out", str(out)])
    page = out.read_text(encoding="utf-8")

    assert code == 0
    for secret in ("sk-supersecretvalue", "bob-token-value", "fw_live_examplekey", "b10_examplekey99"):
        assert secret not in page
    assert "[redacted]" in page


def test_secure_fixture_reports_no_confirmed_findings(tmp_path: Path) -> None:
    database = tmp_path / "codeguard.db"
    out = tmp_path / "latest.html"
    store = FindingStore(database)
    store.save_scan([], _model_run("muse-spark-1.3"))

    code = main(["report", "--config", str(SECURE), "--db", str(database), "--out", str(out)])
    page = out.read_text(encoding="utf-8")

    assert code == 0
    assert "No Confirmed findings" in page
    assert "GET /documents/{id}" not in page
    assert "PUT /documents/{id}" not in page
    assert _FOOTER in page


def test_report_uses_only_the_latest_fix_run(tmp_path: Path) -> None:
    database = tmp_path / "codeguard.db"
    out = tmp_path / "latest.html"
    store = FindingStore(database)
    older = _stamp(10, 0)
    newer = _stamp(12, 0)
    store.save_scan(
        [
            _finding("get-documents-id", "GET", "old reason", "", created_at=older),
            _finding("put-documents-id", "PUT", "old reason", "", created_at=older),
        ],
        model_run=_model_run("old-model"),
    )
    _verification(
        store,
        "get-documents-id",
        attempt=1,
        when=older.replace(minute=5),
        final_status="Verification failed",
        verdict="VERIFICATION FAILED",
        reason="bypass found via DELETE /older as bob -> 200",
        outcome="bypass",
        before=_LONG_BEFORE,
        after=_LONG_AFTER,
    )
    _verification(
        store,
        "get-documents-id",
        attempt=2,
        when=older.replace(minute=6),
        final_status="Verification failed",
        verdict="rejected",
        reason="model fix was not JSON: leftover",
    )
    _verification(
        store,
        "get-documents-id",
        attempt=3,
        when=older.replace(minute=7),
        final_status="Verified",
        verdict="VERIFIED",
        reason="older run verified",
        outcome="hardened",
    )
    store.save_regression_test(
        finding_id="get-documents-id",
        method="GET",
        route="/documents/{id}",
        operation="read",
        file_path="regression_tests/old_should_not_show.py",
        root_cause="old root cause marker",
        policy="owner allow, non-owner deny",
        revision="old",
        created_at=older.replace(minute=8),
    )
    store.save_scan(
        [
            _finding("get-documents-id", "GET", "the handler does not compare the caller with the owner", "", created_at=newer),
            _finding("put-documents-id", "PUT", "the handler does not compare the caller with the owner", "", created_at=newer),
        ],
        model_run=_model_run("muse-spark-1.3"),
    )
    _verification(
        store,
        "get-documents-id",
        attempt=1,
        when=newer.replace(minute=1),
        final_status="Verification failed",
        verdict="VERIFICATION FAILED",
        reason="bypass found via PUT /documents/101 as bob -> 200",
        outcome="bypass",
        line="Bypass check: BYPASS FOUND via PUT /documents/101 as bob -> 200",
    )
    _verification(
        store,
        "get-documents-id",
        attempt=2,
        when=newer.replace(minute=2),
        final_status="Verification failed",
        verdict="rejected",
        reason="duplicate marker that must not appear",
    )
    _verification(
        store,
        "get-documents-id",
        attempt=2,
        when=newer.replace(minute=3),
        final_status="Verification failed",
        verdict="rejected",
        reason="model fix was not JSON: Expecting value",
    )
    _verification(
        store,
        "get-documents-id",
        attempt=3,
        when=newer.replace(minute=4),
        final_status="Verified",
        verdict="VERIFIED",
        reason="exploit blocked, owner access works, and regression passed",
        outcome="hardened",
        before=_LONG_BEFORE,
        after=_LONG_AFTER,
        diff=_DIFF,
    )
    _verification(
        store,
        "put-documents-id",
        attempt=1,
        when=newer.replace(minute=5),
        final_status="Verified",
        verdict="VERIFIED",
        reason="exploit blocked, owner access works, and regression passed",
        outcome="hardened",
        diff=_DIFF,
    )
    code = main(["report", "--config", str(VULNERABLE), "--db", str(database), "--out", str(out)])
    page = out.read_text(encoding="utf-8")
    history = (
        "Attempt 1: bypass found via PUT /documents/101 as bob -&gt; 200 | "
        "Attempt 2: model reply was not JSON | "
        "Attempt 3: VERIFIED and HARDENED"
    )
    outside = _without_details(page)

    assert code == 0
    assert "DELETE /older" not in page
    assert "older run verified" not in page
    assert "old root cause marker" not in page
    assert "old_should_not_show.py" not in page
    assert "duplicate marker that must not appear" not in page
    assert "old-model" not in page
    assert page.count(history) == 1
    assert page.count("Attempt 1:") == 2
    assert page.count("Attempt 2:") == 1
    assert page.count("Attempt 3:") == 1
    assert "Verified and Hardened" in page
    assert 'class="badge ok"' in page
    assert "<details>" in page
    assert "Full request details" in page
    assert "GET /documents/101 as bob: 200 allowed" in page
    assert "GET /documents/101 as bob: 200 allowed" not in outside
    assert "3 tests, 2 allowed (BAD)" in outside
    assert "0 allowed (OK)" in outside
    assert _FOOTER in page
    assert "muse-spark-1.3" in page


def test_report_makes_no_network_calls(tmp_path: Path, monkeypatch) -> None:
    database = tmp_path / "codeguard.db"
    out = tmp_path / "latest.html"
    _seed_verified(database)

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("network call")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)

    code = main(["report", "--config", str(VULNERABLE), "--db", str(database), "--out", str(out)])

    assert code == 0
    assert out.is_file()
    page = out.read_text(encoding="utf-8")
    assert "http://" not in page
    assert "https://" not in page


def _seed_verified(
    database: Path,
    *,
    model_name: str = "muse-spark-1.3",
    reason: str = "the handler does not compare the caller with the owner",
    body: str = "",
    diff: str = _DIFF,
    root_cause: str = "the handler does not compare the caller with the owner",
) -> None:
    store = FindingStore(database)
    findings = [
        _finding("get-documents-id", "GET", reason, body),
        _finding("put-documents-id", "PUT", reason, body),
    ]
    store.save_scan(findings, model_run=_model_run(model_name))
    for finding, operation in ((findings[0], "read"), (findings[1], "write")):
        store.save_verification(
            finding.id,
            diff,
            json.dumps(
                [
                    {
                        "check": "exploit",
                        "result": "pass",
                        "before": "2 allowed (BAD)",
                        "after": "0 allowed (OK)",
                        "detail": "exploit check passed",
                    }
                ]
            ),
            "Verified",
            _WHEN,
            attempt=1,
            verdict="VERIFIED",
            variant_results=json.dumps(
                {
                    "outcome": "hardened",
                    "line": "Bypass check: 14 variants, 0 bypasses (HARDENED)",
                    "variants": [],
                }
            ),
        )
        store.save_regression_test(
            finding_id=finding.id,
            method=finding.method,
            route=finding.route,
            operation=operation,
            file_path=f"regression_tests/{finding.method.lower()}_documents_id_{operation}.py",
            root_cause=root_cause,
            policy="owner allow, non-owner deny",
            revision="abc123",
            created_at=_WHEN,
        )


def _stamp(hour: int, minute: int) -> datetime:
    return datetime(2026, 10, 29, hour, minute, tzinfo=timezone.utc)


def _without_details(page: str) -> str:
    return re.sub(r"<details>.*?</details>", "", page, flags=re.DOTALL)


def _verification(
    store: FindingStore,
    finding_id: str,
    *,
    attempt: int,
    when: datetime,
    final_status: str,
    verdict: str,
    reason: str,
    outcome: str = "",
    line: str = "",
    before: str = "2 allowed (BAD)",
    after: str = "0 allowed (OK)",
    diff: str = "",
) -> None:
    variant: dict[str, object] = {"outcome": outcome, "variants": []}
    if line:
        variant["line"] = line
    elif outcome == "hardened":
        variant["line"] = "Bypass check: 14 variants, 0 bypasses (HARDENED)"
    store.save_verification(
        finding_id,
        diff,
        json.dumps(
            [
                {
                    "check": "exploit",
                    "result": "pass",
                    "before": before,
                    "after": after,
                    "detail": "exploit check passed",
                }
            ]
        ),
        final_status,
        when,
        attempt=attempt,
        failure_reason=reason,
        verdict=verdict,
        variant_results=json.dumps(variant),
    )


def _finding(
    finding_id: str,
    method: str,
    reason: str,
    body: str,
    *,
    created_at: datetime | None = None,
) -> Finding:
    return Finding(
        id=finding_id,
        route="/documents/{id}",
        method=method,
        status="Verified",
        reason=reason,
        evidence=[
            Evidence(
                method=method,
                path="/documents/101",
                identity="bob",
                status_code=200,
                body=body,
                label="EXPLOIT",
            ),
            Evidence(
                method=method,
                path="/documents/101",
                identity="alice",
                status_code=200,
                body="",
                label="CONTROL",
            ),
            Evidence(
                method=method,
                path="/documents/101",
                identity="unauthenticated",
                status_code=401,
                body="",
                label="DENIED",
            ),
        ],
        created_at=created_at or _WHEN,
        target_revision="abc123",
    )


def _model_run(model_name: str) -> ModelRun:
    return ModelRun(
        provider="mock",
        model_name=model_name,
        calls=2,
        proposed=8,
        accepted=8,
        rejected=0,
        total_tokens=40,
        latency_ms=15,
        tool_trace=(("list_routes", "routes", 1), ("submit_plan", "cases=8", 2)),
        tool_mode="function",
    )
