"""Reliability measurement. The model transport is fake and stays on this machine."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from app.cli import _parser, main
from app.reliability import (
    AUTO_APPROVED,
    MEASURED,
    FindingOutcome,
    PatchStyle,
    ReliabilityReport,
    RunRecord,
    _format_error,
    _progress,
    _redact,
    _redact_tree,
    directory_hash,
    failure_label,
    render_markdown,
    report_json,
    run_reliability,
    style_flags,
    summarize,
)
from tests.conftest import use_server

_ROOT = Path(__file__).resolve().parents[1]
_SOURCE = _ROOT / "fixtures" / "vulnerable_api"
_KEY = "meta-secret-key-99"


def test_metric_arithmetic_on_a_hand_made_example() -> None:
    report = ReliabilityReport(
        commit="abc",
        date="2026-10-30",
        provider="meta",
        model="muse-spark-test",
        runs=2,
        source_hash="abc123",
        hash_unchanged=True,
        records=(
            RunRecord(
                tokens=100,
                latency_ms=10,
                source_hash_after="abc123",
                findings=(
                    FindingOutcome("GET /documents/{id}", "Verified and Hardened", 1, ()),
                    FindingOutcome("PUT /documents/{id}", "Verified and Hardened", 2, ("not JSON",)),
                ),
            ),
            RunRecord(
                tokens=300,
                latency_ms=40,
                source_hash_after="abc123",
                findings=(
                    FindingOutcome(
                        "GET /documents/{id}",
                        "Verification failed",
                        3,
                        ("exploit still works", "old text not found"),
                    ),
                    FindingOutcome("PUT /documents/{id}", "Inconclusive", 1, ("owner control failed",)),
                    FindingOutcome("DELETE /documents/{id}", "Verification failed", 2, ("bypass found",)),
                ),
            ),
        ),
    )

    stats = summarize(report)
    text = render_markdown(report)

    assert stats["findings"] == 5
    assert stats["first"] == 1
    assert stats["repaired"] == 1
    assert stats["missed"] == 3
    assert stats["first_share"] == "1/5 (20%)"
    assert stats["repaired_share"] == "1/5 (20%)"
    assert stats["missed_share"] == "3/5 (60%)"
    reasons = stats["reasons"]
    assert isinstance(reasons, dict)
    assert reasons["not JSON"] == 1
    assert reasons["exploit still works"] == 1
    assert reasons["owner control failed"] == 1
    assert reasons["bypass found"] == 1
    assert reasons["old text not found"] == 1
    assert stats["token_mean"] == "200"
    assert stats["token_max"] == "300"
    assert stats["latency_mean"] == "25"
    assert stats["latency_max"] == "40"
    assert "1 | 1/5 (20%)" in text
    assert "3 | 3/5 (60%)" in text
    assert "| Tokens | 200 | 300 |" in text
    assert "| Latency | 25 ms | 40 ms |" in text
    assert "old text not found" in text
    assert "Valid runs: 2" in text
    assert "Failed runs: 0" in text
    assert AUTO_APPROVED in text
    assert MEASURED in text
    assert failure_label("model fix was not JSON: leftover") == "not JSON"
    assert failure_label("exploit check failed: the exploit still works") == "exploit still works"
    assert failure_label("owner check failed: owner access no longer works") == "owner control failed"
    assert failure_label("bypass found via PUT /documents/101 as bob -> 200") == "bypass found"
    assert failure_label("old text not found", "rejected") == "old text not found"
    assert failure_label("", "VERIFIED") == ""


def test_mock_provider_is_refused(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("USE_MOCK_AI", "true")
    monkeypatch.setenv("META_API_KEY", _KEY)
    monkeypatch.setenv("META_MODEL", "muse-spark-test")
    monkeypatch.setenv("META_BASE_URL", "http://meta.test/v1")
    out = tmp_path / "reliability.md"

    code = run_reliability(
        config_path=str(_ROOT / "fixtures" / "codeguard.vulnerable.yaml"),
        provider="meta",
        runs=1,
        out_path=out,
    )
    captured = capsys.readouterr()

    assert code == 2
    assert "mock provider" in captured.out
    assert not out.exists()
    assert _KEY not in captured.out
    assert _KEY not in captured.err


def test_missing_key_is_refused(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("USE_MOCK_AI", "false")
    monkeypatch.setenv("META_API_KEY", "")
    monkeypatch.setenv("META_MODEL", "muse-spark-test")
    monkeypatch.setenv("META_BASE_URL", "http://meta.test/v1")
    monkeypatch.setenv("MODEL_API_KEY", "model-secret-key-99")
    monkeypatch.setenv("BASETEN_API_KEY", "baseten-secret-key-99")
    out = tmp_path / "reliability.md"

    code = run_reliability(
        config_path=str(_ROOT / "fixtures" / "codeguard.vulnerable.yaml"),
        provider="meta",
        runs=1,
        out_path=out,
    )
    captured = capsys.readouterr()

    assert code == 2
    assert captured.out.endswith("META_API_KEY is not set\n") or "META_API_KEY is not set" in captured.out
    assert "META_MODEL" not in captured.out
    assert "model-secret-key-99" not in captured.out
    assert "baseten-secret-key-99" not in captured.out
    assert not out.exists()


def test_original_directory_hash_is_unchanged(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    use_server("asgi", monkeypatch)
    monkeypatch.chdir(_ROOT)
    monkeypatch.setenv("USE_MOCK_AI", "false")
    monkeypatch.setenv("META_API_KEY", _KEY)
    monkeypatch.setenv("META_MODEL", "muse-spark-test")
    monkeypatch.setenv("META_BASE_URL", "http://meta.test/v1")
    monkeypatch.setenv("MODEL_API_KEY", "model-secret-key-99")
    before_hash = directory_hash(_SOURCE)
    before_files = _snapshot(_SOURCE)

    def handler(request: httpx.Request) -> httpx.Response:
        usage = {"prompt_tokens": 4, "completion_tokens": 6, "total_tokens": 10}
        body = request.content.decode("utf-8", errors="replace")
        if "submit_patch" in body:
            return httpx.Response(
                200,
                json={"usage": usage, "choices": [{"message": {"content": "not json"}}]},
            )
        return httpx.Response(
            200,
            json={
                "usage": usage,
                "choices": [
                    {
                        "message": {
                            "content": "",
                            "tool_calls": [
                                {
                                    "id": "call-1",
                                    "type": "function",
                                    "function": {
                                        "name": "submit_plan",
                                        "arguments": json.dumps({"cases": []}),
                                    },
                                }
                            ],
                        }
                    }
                ],
            },
        )

    out = tmp_path / "reports" / "reliability_meta.md"
    code = run_reliability(
        config_path=str(_ROOT / "fixtures" / "codeguard.vulnerable.yaml"),
        provider="meta",
        runs=1,
        out_path=out,
        transport=httpx.MockTransport(handler),
    )
    captured = capsys.readouterr()
    text = out.read_text(encoding="utf-8")
    json_text = out.with_suffix(".json").read_text(encoding="utf-8")

    assert code == 0
    assert directory_hash(_SOURCE) == before_hash
    assert _snapshot(_SOURCE) == before_files
    assert AUTO_APPROVED in captured.out
    assert AUTO_APPROVED in text.split("## Outcomes", 1)[0]
    assert "Provider: meta" in text
    assert "Model: muse-spark-test" in text
    assert "(unchanged)" in text
    assert "not JSON" in text
    assert MEASURED in text
    data = json.loads(json_text)
    assert data["provider"] == "meta"
    assert data["model"] == "muse-spark-test"
    assert data["source_hash_unchanged"] is True
    assert data["approval"] == AUTO_APPROVED
    for blob in (text, json_text, captured.out, captured.err):
        assert _KEY not in blob
        assert "model-secret-key-99" not in blob
        assert "alice-token" not in blob
        assert "bob-token" not in blob
        assert "sk-" not in blob


class _Once(httpx.SyncByteStream):
    def __init__(self, data: bytes) -> None:
        self._data = data

    def __iter__(self):
        yield self._data


def _streamed(status: int, payload: dict[str, object]) -> httpx.Response:
    return httpx.Response(
        status,
        headers={"Authorization": f"Bearer {_KEY}", "X-Api-Key": "sk-supersecretvalue"},
        stream=_Once(json.dumps(payload).encode()),
    )


def _model_payload(request: httpx.Request, *, leak: str) -> dict[str, object]:
    usage = {"prompt_tokens": 4, "completion_tokens": 6, "total_tokens": 10}
    body = request.content.decode("utf-8", errors="replace")
    if "submit_patch" in body:
        return {
            "usage": usage,
            "error": leak,
            "choices": [{"message": {"content": "not json"}}],
        }
    return {
        "usage": usage,
        "error": leak,
        "note": f"Authorization: Bearer {_KEY}",
        "choices": [
            {
                "message": {
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "call-1",
                            "type": "function",
                            "function": {
                                "name": "submit_plan",
                                "arguments": json.dumps({"cases": []}),
                            },
                        }
                    ],
                }
            }
        ],
    }


def test_streamed_model_response_does_not_raise(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    use_server("asgi", monkeypatch)
    monkeypatch.chdir(_ROOT)
    monkeypatch.setenv("USE_MOCK_AI", "false")
    monkeypatch.setenv("META_API_KEY", _KEY)
    monkeypatch.setenv("META_MODEL", "muse-spark-test")
    monkeypatch.setenv("META_BASE_URL", "http://meta.test/v1")
    before = directory_hash(_SOURCE)

    def handler(request: httpx.Request) -> httpx.Response:
        return _streamed(200, _model_payload(request, leak=f"{_KEY} sk-supersecretvalue"))

    out = tmp_path / "reliability.md"
    code = run_reliability(
        config_path=str(_ROOT / "fixtures" / "codeguard.vulnerable.yaml"),
        provider="meta",
        runs=1,
        out_path=out,
        transport=httpx.MockTransport(handler),
    )
    captured = capsys.readouterr()
    text = out.read_text(encoding="utf-8")

    assert code == 0
    assert directory_hash(_SOURCE) == before
    assert "Valid runs: 1" in text
    assert "Failed runs: 0" in text
    assert "ALL RUNS FAILED" not in text
    for blob in (text, captured.out, captured.err):
        assert "Attempted to access streaming response content" not in blob
        assert _KEY not in blob
        assert "sk-supersecretvalue" not in blob


def test_all_failed_runs_exit_1_and_are_labeled_as_errors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(_ROOT)
    monkeypatch.setenv("USE_MOCK_AI", "false")
    monkeypatch.setenv("META_API_KEY", _KEY)
    monkeypatch.setenv("META_MODEL", "muse-spark-test")
    monkeypatch.setenv("META_BASE_URL", "http://meta.test/v1")
    monkeypatch.setenv("MODEL_API_KEY", "model-secret-key-99")
    before = directory_hash(_SOURCE)
    leak = f"{_KEY} sk-supersecretvalue fw_livekeyvalue Authorization: Bearer {_KEY}"

    def handler(_request: httpx.Request) -> httpx.Response:
        return _streamed(500, {"error": leak, "usage": {"total_tokens": 3}})

    out = tmp_path / "reliability.md"
    code = run_reliability(
        config_path=str(_ROOT / "fixtures" / "codeguard.vulnerable.yaml"),
        provider="meta",
        runs=2,
        out_path=out,
        transport=httpx.MockTransport(handler),
    )
    captured = capsys.readouterr()
    text = out.read_text(encoding="utf-8")
    data = json.loads(out.with_suffix(".json").read_text(encoding="utf-8"))

    assert code == 1
    assert directory_hash(_SOURCE) == before
    output_lines = captured.out.splitlines()
    assert output_lines[0] == AUTO_APPROVED
    banner = output_lines.index("ALL RUNS FAILED")
    assert output_lines[banner + 1].startswith("RuntimeError:")
    assert [line.split(",", 1)[0] for line in output_lines if line.startswith("run ")] == [
        "run 1/2: error",
        "run 2/2: error",
    ]
    assert "RuntimeError:" in captured.out
    assert "status 500" in captured.out
    assert text.startswith("# CodeGuard reliability\n\nERROR\n\nALL RUNS FAILED\n")
    assert "Valid runs: 0" in text
    assert "Failed runs: 2" in text
    assert "Findings: 0" in text
    assert "| Verified and Hardened on the first attempt | 0 |" in text
    assert data["all_runs_failed"] is True
    assert data["valid_runs"] == 0
    assert data["failed_runs"] == 2
    assert data["verified_and_hardened_first_attempt"] == 0
    assert data["records"][0]["error"].startswith("RuntimeError:")
    assert data["records"][0]["findings"] == []
    for blob in (text, captured.out, captured.err, json.dumps(data)):
        assert "Attempted to access streaming response content" not in blob
        assert _KEY not in blob
        assert "model-secret-key-99" not in blob
        assert "sk-supersecretvalue" not in blob
        assert "fw_livekeyvalue" not in blob
        assert "Authorization:" not in blob
        assert "Bearer " not in blob


def test_error_text_never_contains_key_like_strings() -> None:
    secret = "Authorization: Bearer meta-secret-key-99 sk-supersecretvalue fw_livekeyvalue b10_examplekey99"
    text = _format_error(RuntimeError(secret))
    redacted = _redact(text, {"meta-secret-key-99"})

    assert text.startswith("RuntimeError:")
    assert "Authorization:" not in text
    assert "Bearer " not in text
    assert "sk-supersecretvalue" not in text
    assert "fw_livekeyvalue" not in text
    assert "b10_examplekey99" not in text
    assert "meta-secret-key-99" not in redacted


def test_fix_command_has_no_auto_approval(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen: dict[str, object] = {}

    def fake(*_args: object, **kwargs: object) -> int:
        seen["keys"] = set(kwargs)
        return 0

    monkeypatch.setattr("app.remediation.verifier.run_fix", fake)
    code = main(["fix", "--config", "fixtures/codeguard.vulnerable.yaml", "--provider", "meta", "--db", str(tmp_path / "x.db")])
    fix = _parser()._subparsers._group_actions[0].choices["fix"]  # type: ignore[attr-defined]
    help_text = fix.format_help().lower()

    assert code == 0
    assert isinstance(seen["keys"], set)
    assert "approve" not in seen["keys"]
    for flag in ("--yes", "--approve", "--auto-approve", "--no-approve", "--force"):
        assert flag not in help_text
    assert "auto-approved" not in help_text


def test_report_contains_no_key_like_strings(tmp_path: Path) -> None:
    secret = "Bearer alice-token sk-supersecretvalue fw_livekeyvalue b10_examplekey99"
    report = ReliabilityReport(
        commit="abc",
        date="2026-10-30",
        provider="fireworks",
        model="fireworks-model",
        runs=1,
        source_hash="abc123",
        hash_unchanged=True,
        records=(
            RunRecord(
                tokens=10,
                latency_ms=5,
                source_hash_after="abc123",
                error=secret,
                findings=(FindingOutcome("GET /documents/{id}", "Verification failed", 1, (secret,)),),
            ),
        ),
    )
    secrets = {"alice-token", "bob-token"}
    text = _redact(render_markdown(report), secrets)
    payload = json.dumps(_redact_tree(report_json(report), secrets))
    destination = tmp_path / "reliability.md"
    destination.write_text(text, encoding="utf-8")
    destination.with_suffix(".json").write_text(payload, encoding="utf-8")

    for blob in (text, payload):
        assert "alice-token" not in blob
        assert "bob-token" not in blob
        assert "sk-supersecretvalue" not in blob
        assert "fw_livekeyvalue" not in blob
        assert "b10_examplekey99" not in blob
        assert AUTO_APPROVED in blob
        assert MEASURED in blob
        assert "1/1 (100%)" in blob


def test_reliability_command_forwards_its_arguments(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen: dict[str, object] = {}

    def fake(**kwargs: object) -> int:
        seen.update(kwargs)
        return 0

    monkeypatch.setattr("app.reliability.run_reliability", fake)
    out = tmp_path / "reliability_baseten.md"
    code = main(
        [
            "reliability",
            "--config",
            "fixtures/codeguard.vulnerable.yaml",
            "--provider",
            "Baseten",
            "--runs",
            "10",
            "--out",
            str(out),
        ]
    )

    assert code == 0
    assert seen["provider"] == "baseten"
    assert seen["runs"] == 10
    assert seen["config_path"] == "fixtures/codeguard.vulnerable.yaml"
    assert Path(str(seen["out_path"])) == out
    assert seen["verbose"] is False


def test_module_help_lists_reliability() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "app.cli", "reliability", "--help"],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "--provider" in completed.stdout
    assert "--runs" in completed.stdout
    assert "--out" in completed.stdout
    assert "--verbose" in completed.stdout
    assert "AUTO-APPROVED" not in completed.stdout


_CLEAN_DIFF = """\
--- a/app.py
+++ b/app.py
@@ -87,2 +87,4 @@
     document = _existing_document(id)
+    if document.owner != user:
+        raise HTTPException(status_code=403, detail="Forbidden")
     updated = document.model_copy(update={"title": body.title})
"""

_IMPORT_DIFF = """\
--- a/app.py
+++ b/app.py
@@ -75,2 +75,3 @@
 def get_document(id: int, user: str) -> Document:
+    import hmac
     return _existing_document(id)
"""

_MODULE_IMPORT_DIFF = """\
--- a/app.py
+++ b/app.py
@@ -20,2 +20,3 @@
 import argparse
+import hmac
 from typing import Annotated
"""

_SINGLE_LOOKUP_DIFF = """\
--- a/app.py
+++ b/app.py
@@ -76,1 +76,4 @@
-    return _existing_document(id)
+    document = _existing_document(id)
+    if getattr(document, "owner", None) != user:
+        raise HTTPException(status_code=403, detail="Forbidden")
+    return document
"""

_FALLBACK_DIFF = """\
--- a/app.py
+++ b/app.py
@@ -76,1 +76,5 @@
-    return _existing_document(id)
+    owner = getattr(document, "owner", None) or document.model_dump().get("owner")
+    if owner is None and hasattr(document, "user_id"):
+        owner = getattr(document, "user_id", None)
+    if owner != user:
+        raise HTTPException(status_code=403, detail="Forbidden")
"""

_DOCSTRING_DIFF = '''\
--- a/app.py
+++ b/app.py
@@ -75,3 +75,6 @@
 def get_document(id: int, user: str) -> Document:
     """Return the document when the token is valid. Ownership is not checked."""
-    return _existing_document(id)
+    document = _existing_document(id)
+    if document.owner != user:
+        raise HTTPException(status_code=403, detail="Forbidden")
+    return document
'''

_REMOVED_DOCSTRING_DIFF = '''\
--- a/app.py
+++ b/app.py
@@ -75,3 +75,5 @@
 def get_document(id: int, user: str) -> Document:
-    """Return the document when the token is valid. Ownership is not checked."""
+    """Return the document only to its owner."""
+    document = _existing_document(id)
+    if document.owner != user:
+        raise HTTPException(status_code=403, detail="Forbidden")
+    return document
'''


def _changed(count: int) -> str:
    body = ["--- a/app.py", "+++ b/app.py", "@@ -1,1 +1,2 @@", "-    return _existing_document(id)"]
    body.extend(f"+    line_{index} = document.owner" for index in range(count - 1))
    return "\n".join(body) + "\n"


def test_style_flags_are_detected_on_hand_made_diffs() -> None:
    assert style_flags(_CLEAN_DIFF) == ()
    assert style_flags(_MODULE_IMPORT_DIFF) == ()
    assert style_flags(_SINGLE_LOOKUP_DIFF) == ()
    assert style_flags(_REMOVED_DOCSTRING_DIFF) == ()
    assert style_flags(_changed(8)) == ()
    assert style_flags(_IMPORT_DIFF) == ("import inside a function",)
    assert style_flags(_FALLBACK_DIFF) == ("owner lookup fallback chain",)
    assert style_flags(_DOCSTRING_DIFF) == ("docstring still says ownership is not checked",)
    assert style_flags(_changed(9)) == ("changes more than 8 lines",)


def test_style_flag_counts_add_up_and_hide_the_diff() -> None:
    secret_diff = _IMPORT_DIFF + "+    note = 'sk-supersecretvalue'\n"
    report = ReliabilityReport(
        commit="abc",
        date="2026-10-30",
        provider="meta",
        model="muse-spark-test",
        runs=2,
        source_hash="abc123",
        hash_unchanged=True,
        records=(
            RunRecord(
                tokens=10,
                latency_ms=5,
                findings=(),
                source_hash_after="abc123",
                patches=(
                    PatchStyle("GET /documents/{id}", style_flags(_CLEAN_DIFF)),
                    PatchStyle("PUT /documents/{id}", style_flags(secret_diff)),
                ),
            ),
            RunRecord(
                tokens=12,
                latency_ms=6,
                findings=(),
                source_hash_after="abc123",
                patches=(
                    PatchStyle("GET /documents/{id}", style_flags(_FALLBACK_DIFF + _changed(9))),
                    PatchStyle("DELETE /documents/{id}", style_flags(_DOCSTRING_DIFF)),
                ),
            ),
        ),
    )
    text = _redact(render_markdown(report), {"sk-supersecretvalue"})
    payload = _redact_tree(report_json(report), {"sk-supersecretvalue"})
    assert isinstance(payload, dict)
    counts = payload["style_flags"]
    assert isinstance(counts, dict)
    flagged = payload["flagged_patches"]
    assert isinstance(flagged, list)

    assert counts["import inside a function"] == 1
    assert counts["owner lookup fallback chain"] == 1
    assert counts["changes more than 8 lines"] == 1
    assert counts["docstring still says ownership is not checked"] == 1
    assert payload["patches_with_a_style_flag"] == 3
    assert payload["patches"] == 4
    assert "patches with at least one style flag: 3 of 4" in text
    assert sum(counts.values()) == sum(len(item["flags"]) for item in flagged)
    assert [(item["route"], item["run"]) for item in flagged] == [
        ("PUT /documents/{id}", 1),
        ("GET /documents/{id}", 2),
        ("DELETE /documents/{id}", 2),
    ]
    assert set(flagged[1]["flags"]) == {"owner lookup fallback chain", "changes more than 8 lines"}
    for item in flagged:
        assert set(item) == {"route", "run", "flags"}
    for blob in (text, json.dumps(payload)):
        assert "sk-supersecretvalue" not in blob
        assert "@@" not in blob
        assert "--- a/" not in blob
        assert AUTO_APPROVED in blob
        assert MEASURED in blob


def test_quiet_mode_prints_one_line_and_verbose_prints_the_run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(_ROOT)
    monkeypatch.setenv("USE_MOCK_AI", "false")
    monkeypatch.setenv("META_API_KEY", _KEY)
    monkeypatch.setenv("META_MODEL", "muse-spark-test")
    monkeypatch.setenv("META_BASE_URL", "http://meta.test/v1")

    def noisy(*_args: object, **_kwargs: object) -> int:
        print("Finding: GET /documents/{id}")
        print("--- a/app.py")
        print("@@ -1 +1 @@")
        print("+    import hmac")
        print("| Finding | Status |")
        return 0

    monkeypatch.setattr("app.reliability._run", noisy)
    quiet = run_reliability(
        config_path=str(_ROOT / "fixtures" / "codeguard.vulnerable.yaml"),
        provider="meta",
        runs=2,
        out_path=tmp_path / "quiet.md",
    )
    quiet_out = capsys.readouterr().out
    progress = [line for line in quiet_out.splitlines() if line.startswith("run ")]

    assert quiet == 0
    assert progress == [
        "run 1/2: no findings, 0.0 s, n/a tokens",
        "run 2/2: no findings, 0.0 s, n/a tokens",
    ]
    assert "Finding:" not in quiet_out
    assert "@@" not in quiet_out
    assert "| Finding | Status |" not in quiet_out

    verbose = run_reliability(
        config_path=str(_ROOT / "fixtures" / "codeguard.vulnerable.yaml"),
        provider="meta",
        runs=1,
        out_path=tmp_path / "verbose.md",
        verbose=True,
    )
    verbose_out = capsys.readouterr().out

    assert verbose == 0
    assert "Finding: GET /documents/{id}" in verbose_out
    assert "--- a/app.py" in verbose_out
    assert "@@ -1 +1 @@" in verbose_out
    assert "| Finding | Status |" in verbose_out
    assert "run 1/1: no findings, 0.0 s, n/a tokens" in verbose_out


def test_progress_line_matches_a_verified_run() -> None:
    record = RunRecord(
        tokens=9812,
        latency_ms=14200,
        source_hash_after="abc123",
        findings=(
            FindingOutcome("GET /documents/{id}", "Verified and Hardened", 1, ()),
            FindingOutcome("PUT /documents/{id}", "Verified and Hardened", 1, ()),
        ),
    )
    assert (
        _progress(3, 10, record)
        == "run 3/10: GET VERIFIED (attempt 1), PUT VERIFIED (attempt 1), 14.2 s, 9812 tokens"
    )


def test_verbose_flag_is_forwarded(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen: dict[str, object] = {}

    def fake(**kwargs: object) -> int:
        seen.update(kwargs)
        return 0

    monkeypatch.setattr("app.reliability.run_reliability", fake)
    code = main(
        [
            "reliability",
            "--config",
            "fixtures/codeguard.vulnerable.yaml",
            "--provider",
            "meta",
            "--runs",
            "2",
            "--out",
            str(tmp_path / "reliability_meta.md"),
            "--verbose",
        ]
    )

    assert code == 0
    assert seen["verbose"] is True


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
    }
