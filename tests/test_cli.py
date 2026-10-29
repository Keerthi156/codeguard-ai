"""CLI scan of the local fixture apps."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from app.cli import main
from app.findings.classifier import evidence_line
from app.findings.store import FindingStore

ROOT = Path(__file__).resolve().parents[1]
_TOKENS = ("alice-token", "bob-token")


@pytest.fixture
def mock_ai(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("USE_MOCK_AI", "true")


def test_module_entrypoint_requires_a_command() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "app.cli"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 2
    for token in _TOKENS:
        assert token not in completed.stdout
        assert token not in completed.stderr


def test_vulnerable_scan_reports_confirmed_findings(mock_ai: None, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    database = tmp_path / "codeguard.db"

    code = main(
        [
            "scan",
            "--config",
            str(ROOT / "fixtures" / "codeguard.vulnerable.yaml"),
            "--db",
            str(database),
        ]
    )
    captured = capsys.readouterr()

    assert code == 1
    for method in ("GET", "PUT"):
        line = _finding_line(captured.out, method)
        assert "/documents/{id}" in line
        assert "Confirmed" in line
        exploit = f"EXPLOIT: {method} /documents/101 as bob -> 200, body shows owner alice"
        control = f"CONTROL: {method} /documents/101 as alice -> 200 (owner access works)"
        assert exploit in line
        assert captured.out.index(exploit) < captured.out.index(control)
    assert "2 findings, 2 confirmed" in captured.out
    assert "Model tests: 8" in captured.out
    assert "Required tests: 10" in captured.out
    assert "Provider: MOCK (development only)" in captured.out
    assert captured.out.index("2 findings, 2 confirmed") < captured.out.index("Model run")
    _assert_no_tokens(captured.out, captured.err)
    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            "SELECT method, route, status FROM findings ORDER BY method"
        ).fetchall()
        runs = connection.execute("SELECT COUNT(*) FROM scan_runs").fetchone()
        stored_run = connection.execute(
            "SELECT provider, model_summary FROM scan_runs"
        ).fetchone()
    assert rows == [("GET", "/documents/{id}", "Confirmed"), ("PUT", "/documents/{id}", "Confirmed")]
    assert runs == (1,)
    assert stored_run is not None
    assert stored_run[0] == "mock"
    assert stored_run[1] in captured.out
    assert "Provider: MOCK (development only)" in stored_run[1]
    store = FindingStore(database)
    for method, finding_id in (("GET", "get-documents-id"), ("PUT", "put-documents-id")):
        loaded = store.load_finding(finding_id)
        first = evidence_line(loaded.evidence[0])
        assert first == f"EXPLOIT: {method} /documents/101 as bob -> 200, body shows owner alice"
        assert loaded.evidence[0].identity == "bob"
        assert len(loaded.evidence[0].body) <= 300
    stored = database.read_bytes()
    for token in _TOKENS:
        assert token.encode() not in stored


def test_secure_scan_reports_no_confirmed_findings(mock_ai: None, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    database = tmp_path / "codeguard.db"

    code = main(
        [
            "scan",
            "--config",
            str(ROOT / "fixtures" / "codeguard.secure.yaml"),
            "--db",
            str(database),
        ]
    )
    captured = capsys.readouterr()

    assert code == 0
    assert "Confirmed" not in captured.out
    assert "0 findings, 0 confirmed" in captured.out
    _assert_no_tokens(captured.out, captured.err)
    with sqlite3.connect(database) as connection:
        findings = connection.execute("SELECT COUNT(*) FROM findings").fetchone()
        runs = connection.execute("SELECT COUNT(*) FROM scan_runs").fetchone()
    assert findings == (0,)
    assert runs == (1,)


def test_non_localhost_config_exits_without_requests(
    mock_ai: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config_path = tmp_path / "codeguard.yaml"
    config_path.write_text(
        "\n".join(
            [
                "base_url: http://example.com",
                "target_app: fixtures.vulnerable_api.app:app",
                "source_dir: fixtures/vulnerable_api",
                "users:",
                "  - name: alice",
                "    token: alice-token",
                "resources:",
                "  - id: 101",
                "    owner: alice",
                "routes:",
                "  - method: GET",
                "    path: /documents/{id}",
                "    operation: read",
                "",
            ]
        ),
        encoding="utf-8",
    )

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("request sent")

    monkeypatch.setattr("app.cli.subprocess.Popen", refuse)
    monkeypatch.setattr("app.cli.execute_plan", refuse)
    monkeypatch.setattr("app.runner.executor.httpx.AsyncClient.request", refuse)

    code = main(["scan", "--config", str(config_path), "--db", str(tmp_path / "codeguard.db")])
    captured = capsys.readouterr()

    assert code == 2
    assert "127.0.0.1 or http://localhost" in captured.err
    assert not (tmp_path / "codeguard.db").exists()
    _assert_no_tokens(captured.out, captured.err)


def _finding_line(output: str, method: str) -> str:
    prefix = f"{method} /documents/{{id}}"
    for line in output.splitlines():
        if line.startswith(prefix):
            return line
    raise AssertionError(f"missing {method} /documents/{{id}}")


def _assert_no_tokens(*chunks: str) -> None:
    combined = "\n".join(chunks)
    for token in _TOKENS:
        assert token not in combined
