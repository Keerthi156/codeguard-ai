"""Fix-gate tests. Plans come from the mock provider and patches from a canned or fake reply."""

from __future__ import annotations

import difflib
import json
import socket
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from app.cli import main
from app.config import Settings
from app.findings.classifier import Finding
from app.remediation.verifier import _detail_line, _pytest_note, _report, _typed_approval, run_fix
from app.runner.executor import Evidence, TestResult
from app.schemas import TestCase

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "fixtures" / "vulnerable_api"
_TOKENS = ("alice-token", "bob-token")
_KEY = "sk-test-secret-key"


def _settings() -> Settings:
    return Settings(
        model_api_key=_KEY,
        model_name="muse-spark-1.3",
        model_base_url="http://127.0.0.1:9/v1",
        use_mock_ai=False,
    )


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _config(tmp_path: Path) -> Path:
    text = (ROOT / "fixtures" / "codeguard.vulnerable.yaml").read_text(encoding="utf-8")
    text = text.replace("http://127.0.0.1:8001", f"http://127.0.0.1:{_free_port()}")
    source = SOURCE.as_posix()
    text = text.replace("source_dir: fixtures/vulnerable_api", f"source_dir: {source}")
    path = tmp_path / "codeguard.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
    }


def _diff(original: str, patched: str) -> str:
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile="a/app.py",
            tofile="b/app.py",
        )
    )


def _payloads(diffs: dict[str, str]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        message = json.loads(body["messages"][1]["content"])
        content = json.dumps(
            {
                "file": "app.py",
                "unified_diff": diffs[message["method"]],
                "root_cause": "the handler does not compare the caller with the owner",
                "side_effects": "described for the test",
            }
        )
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": content}}]})

    return httpx.MockTransport(handler)


def _original() -> str:
    return (SOURCE / "app.py").read_text(encoding="utf-8")


def _deny_everyone(original: str) -> dict[str, str]:
    get_old = "    return _existing_document(id)\n"
    get_new = '    raise HTTPException(status_code=404, detail="Document not found")\n'
    put_old = "    document = _existing_document(id)\n"
    put_new = put_old + '    raise HTTPException(status_code=404, detail="Document not found")\n'
    return {
        "GET": _diff(original, original.replace(get_old, get_new, 1)),
        "PUT": _diff(original, original.replace(put_old, put_new, 1)),
    }


def _change_nothing(original: str) -> dict[str, str]:
    return {
        "GET": _diff(
            original,
            original.replace(
                '"""Return the document when the token is valid. Ownership is not checked."""',
                '"""Return the document when the token is valid. Ownership is not checked. Unchanged."""',
                1,
            ),
        ),
        "PUT": _diff(
            original,
            original.replace(
                '"""Replace title and content when the token is valid. Ownership is not checked."""',
                '"""Replace title and content when the token is valid. Ownership is not checked. Unchanged."""',
                1,
            ),
        ),
    }


def _startup_failure(original: str) -> dict[str, str]:
    broken = original.replace(
        "app = FastAPI(",
        'raise RuntimeError("startup failed")\napp = FastAPI(',
        1,
    )
    noted = original.replace(
        '"""Replace title and content when the token is valid. Ownership is not checked."""',
        '"""Replace title and content when the token is valid. Ownership is not checked. Unchanged."""',
        1,
    )
    return {"GET": _diff(original, broken), "PUT": _diff(original, noted)}


def _patch_dirs() -> set[str]:
    return {path.name for path in Path(tempfile.gettempdir()).glob("codeguard-patch-*")}


def _assert_original_unchanged(before: dict[str, bytes]) -> None:
    assert _snapshot(SOURCE) == before


def _assert_no_tokens(text: str, database: Path) -> None:
    stored = database.read_bytes()
    for token in (*_TOKENS, _KEY):
        assert token not in text
        assert token.encode() not in stored


@pytest.fixture
def mock_ai(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("USE_MOCK_AI", "true")


def test_only_y_approves(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("builtins.input", lambda _prompt: "y")
    assert _typed_approval(_proposal()) is True
    monkeypatch.setattr("builtins.input", lambda _prompt: "")
    assert _typed_approval(_proposal()) is False
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")
    assert _typed_approval(_proposal()) is False


def test_target_tests_directory_counts_as_regression(tmp_path: Path) -> None:
    assert _pytest_note(tmp_path) == "no target tests directory"
    tests = tmp_path / "tests"
    tests.mkdir()
    sample = tests / "test_sample.py"
    sample.write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    assert _pytest_note(tmp_path) == "passed"
    sample.write_text("def test_bad():\n    assert False\n", encoding="utf-8")
    assert _pytest_note(tmp_path) == "failed"


def test_fix_has_no_auto_approve_flag() -> None:
    assert main(["fix", "--config", "unused", "--yes"]) == 2


def test_details_flag_is_accepted(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["fix", "--config", "missing.yaml", "--details"])
    captured = capsys.readouterr()

    assert code == 2
    assert "unrecognized" not in captured.err


def test_compact_report_uses_counts_and_plain_text() -> None:
    owners = {"101": "alice", "202": "bob"}
    cases = [
        *_pair("get", "101", "alice", "bob"),
        *_pair("get", "202", "bob", "alice"),
        *_pair("put", "101", "alice", "bob"),
        *_pair("put", "202", "bob", "alice"),
        _case("get-101-unauthenticated", "GET", "101", "unauthenticated", "deny"),
        _case("get-202-unauthenticated", "GET", "202", "unauthenticated", "deny"),
        _case("put-101-unauthenticated", "PUT", "101", "unauthenticated", "deny"),
        _case("put-202-unauthenticated", "PUT", "202", "unauthenticated", "deny"),
    ]
    before = {case.id: _observed(case, 200 if case.identity != "unauthenticated" else 401) for case in cases}
    after = {
        case.id: _observed(case, 200 if case.identity == {"101": "alice", "202": "bob"}[case.resource_id] else 404)
        for case in cases
    }
    # Unauthenticated stays denied with 401, which is not an allowed non-owner.
    for case in cases:
        if case.identity == "unauthenticated":
            after[case.id] = _observed(case, 401)

    report = _report(
        _finding(),
        "Verified",
        "exploit blocked, owner access works, and regression passed",
        cases,
        before,
        after,
        owners,
        details=True,
    )

    assert "4 tests, 2 allowed (BAD)" in report
    assert "0 allowed (OK)" in report
    assert "4 tests, all allowed (OK)" in report
    assert "all allowed (OK)" in report
    assert "12 tests, 4 non-owner allowed" in report
    assert "0 non-owner allowed" in report
    assert "VERIFIED: exploit blocked, owner access works, regression clean" in report
    assert "401 denied" in report
    assert "401denied" not in report
    assert "\x1b[" not in report
    assert all(len(line) <= 100 for line in report.splitlines())
    hidden = _report(
        _finding(),
        "Verified",
        "ok",
        cases,
        before,
        after,
        owners,
        details=False,
    )
    assert "401 denied" not in hidden
    assert _detail_line(cases[-1], before[cases[-1].id]).endswith("401 denied")


def test_canned_patch_is_verified(mock_ai: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    before = _snapshot(SOURCE)
    temps = _patch_dirs()
    database = tmp_path / "codeguard.db"
    monkeypatch.setattr("builtins.input", lambda _prompt: "y")

    code = main(["fix", "--config", str(_config(tmp_path)), "--db", str(database), "--canned-patch"])
    captured = capsys.readouterr()

    assert code == 0
    assert "CannedPatch (tests and --canned-patch only)" in captured.out
    assert "2 verified, 0 verification failed, 0 inconclusive, 0 declined" in captured.out
    assert "Before" in captured.out and "After" in captured.out
    assert "owner control" in captured.out
    assert "0 allowed (OK)" in captured.out
    assert "all allowed (OK)" in captured.out
    assert "0 non-owner allowed" in captured.out
    assert "VERIFIED: exploit blocked, owner access works, regression clean" in captured.out
    assert " as bob:" not in captured.out
    assert all(len(line) <= 100 for line in captured.out.splitlines() if line.startswith(("Finding:", "exploit", "owner control", "regression", "VERIFIED", "check")))
    _assert_original_unchanged(before)
    assert _patch_dirs() == temps
    _assert_no_tokens(captured.out + captured.err, database)
    with sqlite3.connect(database) as connection:
        rows = connection.execute(
            "SELECT finding_id, final_status, patch_diff, check_results, created_at FROM verifications ORDER BY finding_id"
        ).fetchall()
        statuses = connection.execute("SELECT status FROM findings ORDER BY id").fetchall()
    assert [row[0] for row in rows] == ["get-documents-id", "put-documents-id"]
    assert {row[1] for row in rows} == {"Verified"}
    assert statuses == [("Verified",), ("Verified",)]
    for _finding_id, _status, diff, checks, created_at in rows:
        assert diff.strip()
        parsed = json.loads(checks)
        assert {item["check"] for item in parsed} == {"exploit", "owner", "regression"}
        assert all(item["result"] == "pass" for item in parsed)
        assert "200 allowed" in checks
        assert "404 denied" in checks
        assert "401 denied" in checks
        assert "401denied" not in checks
        assert "404denied" not in checks
        assert created_at


def test_patch_that_denies_everyone_fails_the_owner_check(
    mock_ai: None, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = _snapshot(SOURCE)
    database = tmp_path / "codeguard.db"
    original = _original()

    code = run_fix(
        str(_config(tmp_path)),
        db_path=database,
        approve=lambda _proposal: True,
        settings=_settings(),
        transport=_payloads(_deny_everyone(original)),
    )
    captured = capsys.readouterr()

    assert code == 1
    assert "VERIFICATION FAILED:" in captured.out
    assert "owner check failed" in captured.out
    assert "allowed (BAD)" in captured.out
    _assert_original_unchanged(before)
    _assert_no_tokens(captured.out + captured.err, database)
    with sqlite3.connect(database) as connection:
        statuses = {row[0] for row in connection.execute("SELECT final_status FROM verifications")}
        stored = " ".join(row[0] for row in connection.execute("SELECT check_results FROM verifications"))
    assert statuses == {"Verification failed"}
    assert "200 allowed" in stored
    assert "404 denied" in stored
    assert "404denied" not in stored


def test_patch_that_changes_nothing_leaves_the_exploit_working(
    mock_ai: None, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = _snapshot(SOURCE)
    database = tmp_path / "codeguard.db"

    code = run_fix(
        str(_config(tmp_path)),
        db_path=database,
        approve=lambda _proposal: True,
        settings=_settings(),
        transport=_payloads(_change_nothing(_original())),
        details=True,
    )
    captured = capsys.readouterr()

    assert code == 1
    assert "VERIFICATION FAILED:" in captured.out
    assert "the exploit still works" in captured.out
    assert "200 allowed" in captured.out
    assert "401 denied" in captured.out
    assert "401denied" not in captured.out
    assert all(len(line) <= 100 for line in captured.out.splitlines() if " as " in line)
    _assert_original_unchanged(before)
    _assert_no_tokens(captured.out + captured.err, database)


def test_declined_approval_applies_nothing(
    mock_ai: None, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = _snapshot(SOURCE)
    temps = _patch_dirs()
    database = tmp_path / "codeguard.db"

    code = run_fix(
        str(_config(tmp_path)),
        db_path=database,
        canned=True,
        approve=lambda _proposal: False,
    )
    captured = capsys.readouterr()

    assert code == 3
    assert "Fix proposed" in captured.out
    assert "the user declined the patch" in captured.out
    assert "0 verified, 0 verification failed, 0 inconclusive, 2 declined" in captured.out
    _assert_original_unchanged(before)
    assert _patch_dirs() == temps
    _assert_no_tokens(captured.out + captured.err, database)
    with sqlite3.connect(database) as connection:
        rows = connection.execute("SELECT final_status FROM verifications").fetchall()
        finding_status = connection.execute("SELECT status FROM findings").fetchall()
    assert rows == [("Fix proposed",), ("Fix proposed",)]
    assert finding_status == [("Fix proposed",), ("Fix proposed",)]


def test_patched_app_that_fails_to_start_is_inconclusive(
    mock_ai: None, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = _snapshot(SOURCE)
    temps = _patch_dirs()
    database = tmp_path / "codeguard.db"

    code = run_fix(
        str(_config(tmp_path)),
        db_path=database,
        approve=lambda _proposal: True,
        settings=_settings(),
        transport=_payloads(_startup_failure(_original())),
    )
    captured = capsys.readouterr()

    assert code == 1
    assert "INCONCLUSIVE:" in captured.out
    assert "patched app failed to start" in captured.out
    assert "not run" in captured.out
    assert "0 verified, 0 verification failed, 2 inconclusive, 0 declined" in captured.out
    _assert_original_unchanged(before)
    assert _patch_dirs() == temps
    _assert_no_tokens(captured.out + captured.err, database)
    with sqlite3.connect(database) as connection:
        statuses = {row[0] for row in connection.execute("SELECT final_status FROM verifications")}
    assert statuses == {"Inconclusive"}


def _finding() -> Finding:
    return Finding(
        id="get-documents-id",
        route="/documents/{id}",
        method="GET",
        status="Verified",
        reason="exploit blocked, owner access works, and regression passed",
        created_at=datetime.now(timezone.utc),
    )


def _case(case_id: str, method: str, resource_id: str, identity: str, expected: str) -> TestCase:
    return TestCase(
        id=case_id,
        route="/documents/{id}",
        method=method,  # type: ignore[arg-type]
        identity=identity,
        resource_id=resource_id,
        expected=expected,  # type: ignore[arg-type]
        reason="planned check",
    )


def _pair(method: str, resource_id: str, owner: str, other: str) -> list[TestCase]:
    verb = method.lower()
    return [
        _case(f"{verb}-{resource_id}-owner", method.upper(), resource_id, owner, "allow"),
        _case(f"{verb}-{resource_id}-other", method.upper(), resource_id, other, "deny"),
    ]


def _observed(case: TestCase, status_code: int) -> TestResult:
    access = "allowed" if 200 <= status_code < 300 else "denied"
    path = f"/documents/{case.resource_id}"
    return TestResult(
        test_id=case.id,
        status_code=status_code,
        access=access,  # type: ignore[arg-type]
        matches_expected=(access == "allowed") == (case.expected == "allow"),
        outcome="pass" if (access == "allowed") == (case.expected == "allow") else "fail",
        evidence=Evidence(
            method=case.method,
            path=path,
            identity=case.identity,
            status_code=status_code,
            body="",
        ),
    )


def _proposal():
    from app.remediation.patcher import PatchProposal

    return PatchProposal(
        finding_id="get-documents-id",
        file="app.py",
        diff="--- a/app.py\n+++ b/app.py\n",
        root_cause="missing owner check",
        side_effects="non-owners are denied",
        temp_copy_path=".",
    )
