"""Regression export and the regress command."""

from __future__ import annotations

import importlib.util
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.analyzer.auth_checks import assess_routes
from app.cli import main
from app.findings.classifier import Finding
from app.findings.regression import export_verified
from app.remediation.patcher import materialize, propose_patch
from app.target_config import load_target_config

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "fixtures" / "vulnerable_api"
CONFIG = ROOT / "fixtures" / "codeguard.vulnerable.yaml"
_TOKENS = ("alice-token", "bob-token", "sk-test-secret-key")


def _finding(status: str = "Verified", method: str = "GET") -> Finding:
    return Finding(
        id="get-documents-id" if method == "GET" else "put-documents-id",
        route="/documents/{id}",
        method=method,
        status=status,  # type: ignore[arg-type]
        reason="non-owner was allowed",
        created_at=datetime(2026, 10, 28, tzinfo=timezone.utc),
        target_revision="abc123",
    )


def _export(tmp_path: Path, status: str = "Verified", method: str = "GET") -> Path | None:
    config = load_target_config(CONFIG)
    return export_verified(
        _finding(status, method),
        config,
        root_cause="the handler ignores ownership sk-test-secret-key alice-token",
        db_path=tmp_path / "codeguard.db",
        output_dir=tmp_path / "regression_tests",
        when=datetime(2026, 10, 28, tzinfo=timezone.utc),
    )


def test_verified_finding_exports_a_pytest_file(tmp_path: Path) -> None:
    path = _export(tmp_path)
    assert path is not None
    text = path.read_text(encoding="utf-8")
    assert path.name == "get_documents_id_read.py"
    assert "# Finding: get-documents-id" in text
    assert "# Route: GET /documents/{id}" in text
    assert "# Date: 2026-10-28" in text
    assert "# Revision: abc123" in text
    assert "# Root cause:" in text
    assert "Policy assumption:" in text
    assert "def test_owner_alice_101" in text
    assert "def test_exploit_non_owner_bob_101" in text
    assert "def test_exploit_unauthenticated_101" in text
    assert "CODEGUARD_BASE_URL" in text
    compile(text, str(path), "exec")
    for secret in _TOKENS:
        assert secret not in text
    with sqlite3.connect(tmp_path / "codeguard.db") as connection:
        row = connection.execute(
            "SELECT finding_id, method, route, operation, file_path FROM regression_tests"
        ).fetchone()
    assert row == ("get-documents-id", "GET", "/documents/{id}", "read", str(path.resolve()))
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", str(path), "--collect-only", "-q", "--noconftest", f"--rootdir={path.parent}"],
        cwd=path.parent,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "test_exploit_non_owner_bob_101" in completed.stdout


def test_unverified_finding_is_not_exported(tmp_path: Path) -> None:
    assert _export(tmp_path, status="Confirmed") is None
    assert _export(tmp_path, status="Fix proposed") is None
    assert list((tmp_path / "regression_tests").glob("*.py")) == []
    database = tmp_path / "codeguard.db"
    if database.exists():
        with sqlite3.connect(database) as connection:
            count = connection.execute("SELECT COUNT(*) FROM regression_tests").fetchone()
        assert count == (0,)


def test_generated_test_refuses_a_non_localhost_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _export(tmp_path)
    assert path is not None
    spec = importlib.util.spec_from_file_location("saved_regression", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("CODEGUARD_BASE_URL", "http://example.com")
    with pytest.raises(BaseException, match="127.0.0.1 or http://localhost"):
        module._base_url()


def test_regress_reports_a_config_error_without_starting_a_server(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("server started")

    monkeypatch.setattr("app.findings.regression.subprocess.Popen", refuse)
    code = main(["regress", "--config", str(tmp_path / "missing.yaml"), "--db", str(tmp_path / "codeguard.db")])
    captured = capsys.readouterr()
    assert code == 2
    assert "config error" in captured.err


@pytest.mark.slow
def test_regress_passes_against_the_patched_copy(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    before = (SOURCE / "app.py").read_bytes()
    database = tmp_path / "codeguard.db"
    output = tmp_path / "regression_tests"
    _export_both(database, output)
    copied = _patched_copy()
    try:
        code = main(
            [
                "regress",
                "--config",
                str(CONFIG),
                "--source-dir",
                str(copied),
                "--db",
                str(database),
            ]
        )
    finally:
        shutil.rmtree(copied, ignore_errors=True)
    captured = capsys.readouterr()
    assert code == 0, captured.out + captured.err
    assert "pass" in captured.out
    assert "REGRESSION:" not in captured.out
    assert (SOURCE / "app.py").read_bytes() == before
    for secret in _TOKENS:
        assert secret not in captured.out
        assert secret not in captured.err


@pytest.mark.slow
def test_regress_names_both_routes_on_the_vulnerable_fixture(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    before = (SOURCE / "app.py").read_bytes()
    database = tmp_path / "codeguard.db"
    _export_both(database, tmp_path / "regression_tests")
    code = main(
        [
            "regress",
            "--config",
            str(CONFIG),
            "--source-dir",
            str(SOURCE),
            "--db",
            str(database),
        ]
    )
    captured = capsys.readouterr()
    assert code == 1
    assert "REGRESSION: GET /documents/{id} is vulnerable again" in captured.out
    assert "REGRESSION: PUT /documents/{id} is vulnerable again" in captured.out
    assert "fail" in captured.out
    assert (SOURCE / "app.py").read_bytes() == before
    for secret in _TOKENS:
        assert secret not in captured.out
        assert secret not in captured.err


def _export_both(database: Path, output: Path) -> None:
    config = load_target_config(CONFIG)
    for method in ("GET", "PUT"):
        export_verified(
            _finding("Verified", method),
            config,
            root_cause="the handler ignores ownership",
            db_path=database,
            output_dir=output,
            when=datetime(2026, 10, 28, tzinfo=timezone.utc),
        )


def _patched_copy() -> Path:
    config = load_target_config(CONFIG)
    routes = [item for item in assess_routes(SOURCE) if item.path == "/documents/{id}"]
    patches: list[tuple[str, str]] = []
    temps: list[Path] = []
    for route in routes:
        proposal = propose_patch(
            _finding("Confirmed", route.method),
            source_dir=SOURCE,
            route_file=route.file,
            handler_source=route.source,
            line_numbers=route.line_numbers,
            matrix=config.matrix(),
            canned=True,
        )
        temps.append(Path(proposal.temp_copy_path))
        patches.append((proposal.file, proposal.diff))
    for path in temps:
        shutil.rmtree(path, ignore_errors=True)
    return materialize(SOURCE, patches)
