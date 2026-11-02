"""Benchmark harness metrics, with a fake provider and an in-process transport."""

from __future__ import annotations

import importlib
import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from app.benchmark_run import (
    AppBlock,
    BenchmarkReport,
    RouteRow,
    _redact,
    _redact_tree,
    consistency,
    describe_route,
    misses_for,
    rate,
    render_comparison,
    render_markdown,
    report_json,
    run_benchmark,
    run_benchmark_compare,
    score,
    working_tree_state,
)
from app.cli import main

_ROOT = Path(__file__).resolve().parents[1]
_INCONCLUSIVE = "A needed test was inconclusive, so this route is Inconclusive."
_MEASURED = "Measured on this benchmark only; not a claim of real-world coverage."


def _row(
    app_id: str,
    route: str,
    vulnerable: bool,
    statuses: list[str],
    reasons: list[str],
    flagged: list[str] | None = None,
) -> RouteRow:
    return RouteRow(
        app_id,
        route,
        vulnerable,
        tuple(statuses),
        tuple(reasons),
        tuple(flagged or ()),
    )


def _report(rows: list[RouteRow], *, provider: str = "mock", model: str = "") -> BenchmarkReport:
    grouped: dict[str, list[RouteRow]] = {}
    for row in rows:
        grouped.setdefault(row.app_id, []).append(row)
    apps = tuple(
        AppBlock(app_id, 1, len(items), tuple(items), ())
        for app_id, items in grouped.items()
    )
    return BenchmarkReport(
        commit="abc123",
        date="2026-10-29",
        provider=provider,
        model=model,
        runs=len(rows[0].statuses),
        apps=apps,
        totals=score(rows),
        plan_validity=rate(2, 4),
        plan_submissions=1,
        tool_calls=0,
        tokens=None,
        latency_ms=0,
        discovered=len(apps),
        labeled=len(rows),
        misses=misses_for(rows),
    )


def test_metric_arithmetic_including_zero_division() -> None:
    rows = [
        _row("vuln", "GET /a", True, ["Confirmed", "Confirmed", "Confirmed"], ["ok", "ok", "ok"]),
        _row("vuln", "GET /b", True, ["Inconclusive", "Suspected", "not discovered"], ["a", "b", ""]),
        _row("secure", "GET /c", False, ["Confirmed"], ["opened"]),
        _row("secure", "GET /d", False, ["Suspected"], ["static"]),
        _row("broken", "GET /e", True, ["error"], ["target app failed to start"]),
    ]
    totals = score(rows)
    assert totals.tp == 3
    assert totals.fp == 1
    assert totals.fn == 3
    assert totals.tn == 1
    assert totals.errors == 1
    assert totals.fn_inconclusive == 1
    assert totals.fn_suspected == 1
    assert totals.fn_not_discovered == 1
    assert totals.precision == "0.75"
    assert totals.recall == "0.50"
    assert rate(0, 0) == "n/a"
    only_secure = score([_row("secure", "GET /z", False, ["not discovered"], [""])])
    assert only_secure.tp == 0
    assert only_secure.fp == 0
    assert only_secure.fn == 0
    assert only_secure.tn == 1
    assert only_secure.precision == "n/a"
    assert only_secure.recall == "n/a"
    empty = _report([_row("secure", "GET /z", False, ["not discovered"], [""])])
    empty = BenchmarkReport(
        commit=empty.commit,
        date=empty.date,
        provider=empty.provider,
        model=empty.model,
        runs=1,
        apps=empty.apps,
        totals=only_secure,
        plan_validity=rate(0, 0),
        plan_submissions=0,
        tool_calls=0,
        tokens=None,
        latency_ms=0,
        discovered=0,
        labeled=1,
        misses=(),
    )
    text = render_markdown(empty)
    assert "Precision: n/a" in text
    assert "Recall: n/a" in text
    assert "Plan-validity rate: n/a" in text
    assert consistency(("Confirmed", "Confirmed", "Confirmed")) == "agreed"
    assert consistency(("Confirmed", "Suspected", "Confirmed")) == "disagreed"
    mixed = render_markdown(
        _report(
            [
                _row(
                    "vuln",
                    "GET /a",
                    True,
                    ["Confirmed", "Confirmed", "Suspected"],
                    ["ok", "ok", "static"],
                )
            ]
        )
    )
    assert "| Confirmed | Confirmed | Suspected | disagreed |" in mixed
    assert _MEASURED in mixed
    assert "A route counts as DETECTED when its status is Confirmed." in mixed


def test_each_discovery_case_keeps_the_same_confusion_counts() -> None:
    inventory = {("GET", "/documents/{id}"), ("PUT", "/documents/{id}")}
    flagged = {("PUT", "/documents/{id}")}
    missing = describe_route(
        "DELETE",
        "/absent",
        inventory=inventory,
        flagged_routes=flagged,
        finding_status=None,
    )
    quiet = describe_route(
        "GET",
        "/documents/{id}",
        inventory=inventory,
        flagged_routes=flagged,
        finding_status=None,
        static_reason="No issue observed",
    )
    suspected = describe_route(
        "PUT",
        "/documents/{id}",
        inventory=inventory,
        flagged_routes=flagged,
        finding_status="Suspected",
        finding_reason="Suspected, not reproduced",
    )
    assert missing == ("not discovered", "", "no")
    assert quiet == ("discovered, not flagged", "No issue observed", "no")
    assert suspected == ("Suspected", "Suspected, not reproduced", "yes")

    rows = [
        _row("vuln", "DELETE /absent", True, [missing[0]], [missing[1]], [missing[2]]),
        _row("vuln", "GET /documents/{id}", True, [quiet[0]], [quiet[1]], [quiet[2]]),
        _row("vuln", "PUT /documents/{id}", True, [suspected[0]], [suspected[1]], [suspected[2]]),
        _row("vuln", "PATCH /documents/{id}", True, ["Inconclusive"], [_INCONCLUSIVE], ["yes"]),
        _row("secure", "GET /documents/{id}", False, [quiet[0]], [quiet[1]], [quiet[2]]),
        _row(
            "secure",
            "PUT /documents/{id}",
            False,
            [suspected[0]],
            [suspected[1]],
            [suspected[2]],
        ),
        _row("vuln", "GET /open", True, ["Confirmed"], ["opened"], ["yes"]),
        _row("secure", "GET /open", False, ["Confirmed"], ["opened"], ["no"]),
    ]
    totals = score(rows)
    assert totals.tp == 1
    assert totals.fp == 1
    assert totals.fn == 4
    assert totals.tn == 2
    assert totals.fn_not_discovered == 1
    assert totals.fn_discovered_not_flagged == 1
    assert totals.fn_suspected == 1
    assert totals.fn_inconclusive == 1
    assert totals.tn_discovered_not_flagged == 1
    assert totals.tn_flagged_not_reproduced == 1
    text = render_markdown(_report(rows))
    assert "flagged by static analysis" in text
    assert "| DELETE /absent | no | not discovered | agreed |" in text
    assert "| GET /documents/{id} | no | discovered, not flagged | agreed |" in text
    assert "| PUT /documents/{id} | yes | Suspected | agreed |" in text
    false_negatives = text.split("False negatives:", 1)[1].split("True negatives:", 1)[0]
    true_negatives = text.split("True negatives:", 1)[1].split("Errors:", 1)[0]
    assert "- not discovered: 1" in false_negatives
    assert "- discovered, not flagged: 1" in false_negatives
    assert "- Suspected not reproduced: 1" in false_negatives
    assert "- Inconclusive: 1" in false_negatives
    assert "- discovered, not flagged: 1" in true_negatives
    assert "- flagged but not reproduced: 1" in true_negatives
    payload = report_json(_report(rows))
    totals_json = payload["totals"]
    assert isinstance(totals_json, dict)
    legacy = totals_json["legacy"]
    assert isinstance(legacy, dict)
    assert legacy["fn_not_discovered"] == 2
    assert legacy["not discovered"] == 2
    assert legacy["fn_suspected"] == 1
    assert legacy["Suspected-not-reproduced"] == 1
    assert legacy["fn_inconclusive"] == 1
    assert totals_json["tp"] == 1
    assert totals_json["fp"] == 1
    assert totals_json["fn"] == 4
    assert totals_json["tn"] == 2
    section = text.split("## Misses and false alarms", 1)[1]
    assert "vuln GET /documents/{id} run 1: discovered, not flagged: No issue observed" in section
    assert "vuln PUT /documents/{id} run 1: Suspected: Suspected, not reproduced" in section


def test_labeled_secure_confirmed_is_a_false_positive() -> None:
    reason = "A non-owner or unauthenticated caller received access the matrix denies, and the owner control test for this route passed."
    rows = [_row("secure-app", "GET /documents/{id}", False, ["Confirmed"], [reason])]
    totals = score(rows)
    assert totals.fp == 1
    assert totals.tp == 0
    assert totals.tn == 0
    assert totals.fn == 0
    text = render_markdown(_report(rows))
    section = text.split("## Misses and false alarms", 1)[1]
    assert f"secure-app GET /documents/{{id}} run 1: Confirmed: {reason}" in section


def test_inconclusive_vulnerable_route_is_a_false_negative() -> None:
    rows = [_row("vuln-app", "PUT /documents/{id}", True, ["Inconclusive"], [_INCONCLUSIVE])]
    totals = score(rows)
    assert totals.fn == 1
    assert totals.tp == 0
    assert totals.fn_inconclusive == 1
    assert totals.fn_suspected == 0
    assert totals.fn_not_discovered == 0
    text = render_markdown(_report(rows))
    section = text.split("## Misses and false alarms", 1)[1]
    assert f"vuln-app PUT /documents/{{id}} run 1: Inconclusive: {_INCONCLUSIVE}" in section


def test_report_contains_no_key_like_strings() -> None:
    reason = "Bearer alice-token sk-supersecretvalue fw_livekeyvalue b10_examplekey99 bob-token"
    rows = [_row("app", "GET /documents/{id}", True, ["Inconclusive"], [reason])]
    report = _report(rows)
    tokens = {"alice-token", "bob-token"}
    text = _redact(render_markdown(report), tokens)
    payload = json.dumps(_redact_tree(report_json(report), tokens))
    for blob in (text, payload):
        assert "alice-token" not in blob
        assert "bob-token" not in blob
        assert "sk-supersecretvalue" not in blob
        assert "fw_livekeyvalue" not in blob
        assert "b10_examplekey99" not in blob
        assert "real model" not in blob
    assert "Provider: mock (development only)" in text
    assert _MEASURED in text


def test_benchmark_command_passes_runs_and_out(monkeypatch, tmp_path: Path) -> None:
    seen: dict[str, object] = {}

    def fake(*, runs: int, out_path: object, labels_path: object, provider: str | None = None) -> int:
        seen["runs"] = runs
        seen["out"] = Path(str(out_path))
        seen["labels"] = Path(str(labels_path))
        seen["provider"] = provider
        return 0

    monkeypatch.setattr("app.benchmark_run.run_benchmark", fake)
    out = tmp_path / "benchmark.md"
    code = main(["benchmark", "--runs", "3", "--out", str(out)])
    assert code == 0
    assert seen["runs"] == 3
    assert seen["out"] == out
    assert seen["labels"] == Path("benchmarks/labels.yaml")
    assert seen["provider"] is None


def test_start_failure_is_reported_and_the_run_continues(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("USE_MOCK_AI", "true")
    monkeypatch.chdir(_ROOT)
    labels = tmp_path / "labels.yaml"
    labels.write_text(
        "\n".join(
            (
                "apps:",
                "  - id: helper-check-vulnerable",
                "    config: benchmarks/helper_check/vulnerable/codeguard.yaml",
                "    routes:",
                "      - method: GET",
                "        path: /documents/{id}",
                "        vulnerable: true",
                "      - method: PUT",
                "        path: /documents/{id}",
                "        vulnerable: true",
                "  - id: helper-check-secure",
                "    config: benchmarks/helper_check/secure/codeguard.yaml",
                "    routes:",
                "      - method: GET",
                "        path: /documents/{id}",
                "        vulnerable: false",
                "      - method: PUT",
                "        path: /documents/{id}",
                "        vulnerable: false",
                "",
            )
        ),
        encoding="utf-8",
    )

    class _Dummy:
        def stop(self) -> None:
            return None

    def start(config: object, source_dir: Path, tokens: object) -> _Dummy:
        del config, tokens
        if source_dir.name == "secure":
            raise RuntimeError("target app failed to start")
        return _Dummy()

    def transport_for(config: object) -> httpx.ASGITransport:
        target = getattr(config, "target_app")
        module_name, _, attr = str(target).partition(":")
        module = importlib.import_module(module_name)
        module.reset()
        return httpx.ASGITransport(app=getattr(module, attr or "app"))

    monkeypatch.setattr("app.cli._start_target", start)
    out = tmp_path / "reports" / "benchmark.md"
    code = run_benchmark(
        runs=2,
        out_path=out,
        labels_path=labels,
        transport_for=transport_for,
    )
    assert code == 0
    text = out.read_text(encoding="utf-8")
    json_text = out.with_suffix(".json").read_text(encoding="utf-8")
    vulnerable = text.split("## helper-check-vulnerable", 1)[1].split("## ", 1)[0]
    secure = text.split("## helper-check-secure", 1)[1].split("## ", 1)[0]
    assert "| error |" not in vulnerable
    assert "target app failed to start" in secure
    assert "| error | error | agreed |" in secure
    assert "helper-check-vulnerable" in text
    for blob in (text, json_text):
        assert "alice-token" not in blob
        assert "bob-token" not in blob
        assert "sk-" not in blob
        assert "real model" not in blob
        assert _MEASURED in blob
    assert "Provider: mock (development only)" in text
    data = json.loads(json_text)
    assert data["provider"] == "mock"
    assert data["runs"] == 2
    assert data["totals"]["errors"] == 4


def test_commands_forward_provider_and_hide_a_bad_value(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    seen: dict[str, object] = {}

    def benchmark(**kwargs: object) -> int:
        seen["benchmark"] = kwargs.get("provider")
        return 0

    def scan(*_args: object, **kwargs: object) -> int:
        seen["scan"] = kwargs.get("provider_name")
        return 0

    def fix(*_args: object, **kwargs: object) -> int:
        seen["fix"] = kwargs.get("provider")
        return 0

    monkeypatch.setattr("app.benchmark_run.run_benchmark", benchmark)
    monkeypatch.setattr("app.cli._scan", scan)
    monkeypatch.setattr("app.remediation.verifier.run_fix", fix)

    assert main(["benchmark", "--provider", "Fireworks", "--out", str(tmp_path / "benchmark.md")]) == 0
    assert main(["scan", "--config", "x", "--provider", "meta"]) == 0
    assert main(["fix", "--config", "x", "--provider", "baseten"]) == 0
    assert seen == {"benchmark": "fireworks", "scan": "meta", "fix": "baseten"}

    secret = "provider-secret-key-99"
    code = main(["benchmark", "--provider", secret, "--out", str(tmp_path / "hidden.md")])
    captured = capsys.readouterr()
    assert code == 2
    assert "Invalid PROVIDER" in captured.err
    assert secret not in captured.out
    assert secret not in captured.err


def test_benchmark_header_names_the_provider_and_model(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    key = "meta-secret-key-99"
    monkeypatch.setenv("USE_MOCK_AI", "false")
    monkeypatch.setenv("META_API_KEY", key)
    monkeypatch.setenv("META_MODEL", "muse-spark-test")
    monkeypatch.setenv("META_BASE_URL", "http://meta.test/v1")
    monkeypatch.setenv("BASETEN_API_KEY", "baseten-secret-key-99")
    monkeypatch.chdir(_ROOT)
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        payload = {
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            "choices": [
                {
                    "message": {
                        "role": "assistant",
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
        return httpx.Response(200, json=payload)

    real_client = httpx.Client

    def client(*args: object, **kwargs: object) -> httpx.Client:
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr("app.ai.llm_provider.httpx.Client", client)

    class _Dummy:
        def stop(self) -> None:
            return None

    def start(config: object, source_dir: Path, tokens: object) -> _Dummy:
        del config, source_dir, tokens
        return _Dummy()

    def transport_for(config: object) -> httpx.ASGITransport:
        target = getattr(config, "target_app")
        module_name, _, attr = str(target).partition(":")
        module = importlib.import_module(module_name)
        module.reset()
        return httpx.ASGITransport(app=getattr(module, attr or "app"))

    monkeypatch.setattr("app.cli._start_target", start)
    out = tmp_path / "reports" / "benchmark.md"

    code = run_benchmark(
        runs=1,
        out_path=out,
        labels_path=_pair_labels(tmp_path),
        transport_for=transport_for,
        provider="meta",
    )

    text = out.read_text(encoding="utf-8")
    json_text = out.with_suffix(".json").read_text(encoding="utf-8")
    header = text.split("## Definitions", 1)[0]
    assert code == 0
    assert "Provider: meta" in header
    assert "Model: muse-spark-test" in header
    assert seen
    assert all(str(item.url) == "http://meta.test/v1/chat/completions" for item in seen)
    assert all(item.headers["authorization"] == f"Bearer {key}" for item in seen)
    assert all(json.loads(item.content)["model"] == "muse-spark-test" for item in seen)
    data = json.loads(json_text)
    assert data["provider"] == "meta"
    assert data["model"] == "muse-spark-test"
    for blob in (text, json_text):
        assert key not in blob
        assert "baseten-secret-key-99" not in blob
        assert "alice-token" not in blob
        assert "bob-token" not in blob


def test_benchmark_refuses_a_provider_whose_key_is_missing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("USE_MOCK_AI", "false")
    monkeypatch.setenv("META_API_KEY", "")
    monkeypatch.setenv("META_MODEL", "muse-spark-test")
    monkeypatch.setenv("META_BASE_URL", "http://meta.test/v1")
    monkeypatch.setenv("BASETEN_API_KEY", "baseten-secret-key-99")
    monkeypatch.setenv("MODEL_API_KEY", "model-secret-key-99")
    out = tmp_path / "reports" / "benchmark.md"

    code = run_benchmark(runs=1, out_path=out, labels_path=_pair_labels(tmp_path), provider="meta")
    captured = capsys.readouterr()

    assert code == 2
    assert not out.exists()
    assert "META_API_KEY" in captured.out
    assert "Provider: meta" not in captured.out
    assert "muse-spark-test" not in captured.out
    assert "baseten-secret-key-99" not in captured.out
    assert "model-secret-key-99" not in captured.out
    assert "baseten-secret-key-99" not in captured.err
    assert "model-secret-key-99" not in captured.err


def test_provider_and_ablation_use_separate_default_files(monkeypatch, tmp_path: Path) -> None:
    seen: dict[str, object] = {}

    def fake(**kwargs: object) -> int:
        seen.update(kwargs)
        return 0

    monkeypatch.setattr("app.benchmark_run.run_benchmark", fake)
    assert main(["benchmark", "--provider", "meta", "--runs", "2"]) == 0
    assert seen["provider"] == "meta"
    assert seen["out_path"] == "reports/benchmark_meta.md"
    assert "no_model_tests" not in seen

    assert main(["benchmark", "--no-model-tests", "--runs", "2"]) == 0
    assert seen["out_path"] == "reports/benchmark_no_model.md"
    assert seen["no_model_tests"] is True


def test_no_model_ablation_makes_no_model_calls_and_warns_when_dirty(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("USE_MOCK_AI", "false")
    monkeypatch.setenv("META_API_KEY", "")
    monkeypatch.setenv("MODEL_API_KEY", "")
    monkeypatch.chdir(_ROOT)
    calls = {"n": 0}

    def fail_provider(*_args: object, **_kwargs: object) -> object:
        calls["n"] += 1
        raise RuntimeError("model was called sk-supersecretvalue")

    monkeypatch.setattr("app.benchmark_run.get_provider", fail_provider)
    monkeypatch.setattr("app.benchmark_run.working_tree_state", lambda: "dirty")

    class _Dummy:
        def stop(self) -> None:
            return None

    def start(config: object, source_dir: Path, tokens: object) -> _Dummy:
        del config, source_dir, tokens
        return _Dummy()

    def transport_for(config: object) -> httpx.ASGITransport:
        target = getattr(config, "target_app")
        module_name, _, attr = str(target).partition(":")
        module = importlib.import_module(module_name)
        module.reset()
        return httpx.ASGITransport(app=getattr(module, attr or "app"))

    monkeypatch.setattr("app.cli._start_target", start)
    out = tmp_path / "reports" / "benchmark_no_model.md"
    code = run_benchmark(
        runs=1,
        out_path=out,
        labels_path=_pair_labels(tmp_path),
        transport_for=transport_for,
        no_model_tests=True,
    )
    captured = capsys.readouterr()
    text = out.read_text(encoding="utf-8")
    data = json.loads(out.with_suffix(".json").read_text(encoding="utf-8"))
    header = text.split("## Definitions", 1)[0]

    assert code == 0
    assert calls["n"] == 0
    assert "model was called" not in text
    assert "required tests only (no model)" in header
    assert "WARNING: THE WORKING TREE IS DIRTY" in header
    assert "Working tree: dirty" in header
    assert "Commit:" in header
    assert "Date:" in header
    assert _MEASURED in header
    assert "WARNING: THE WORKING TREE IS DIRTY" in captured.out
    assert data["provider"] == "required tests only (no model)"
    assert data["mode"] == "required tests only (no model)"
    assert data["working_tree"] == "dirty"
    assert data["totals"]["tool_calls"] == 0
    assert data["totals"]["plan_proposed"] == 0
    for blob in (text, captured.out, captured.err, json.dumps(data)):
        assert "alice-token" not in blob
        assert "bob-token" not in blob
        assert "sk-" not in blob
        assert "fw_" not in blob
        assert "b10_" not in blob


def test_comparison_arithmetic_lists_differing_routes_and_hides_keys(tmp_path: Path) -> None:
    meta = {
        "provider": "meta",
        "model": "muse-spark-test",
        "runs": 2,
        "apps": [
            {
                "id": "helper",
                "routes": [
                    {"route": "GET /a", "statuses": ["Confirmed", "Confirmed"]},
                    {"route": "GET /b", "statuses": ["Suspected", "Suspected"]},
                    {"route": "GET /sk-supersecretvalue", "statuses": ["Confirmed fw_livekeyvalue", "Confirmed"]},
                ],
            }
        ],
        "totals": {
            "tp": 3,
            "fp": 1,
            "fn": 1,
            "tn": 1,
            "plan_validity": "0.50",
            "plan_accepted": 2,
            "plan_proposed": 4,
            "tokens": 100,
            "latency_ms": 40,
            "scans": 2,
        },
    }
    baseten = {
        "provider": "baseten",
        "model": "other-model",
        "runs": 2,
        "apps": [
            {
                "id": "helper",
                "routes": [
                    {"route": "GET /a", "statuses": ["Confirmed", "Confirmed"]},
                    {"route": "GET /b", "statuses": ["Confirmed", "Confirmed"]},
                    {"route": "GET /sk-supersecretvalue", "statuses": ["Suspected", "Suspected"]},
                ],
            }
        ],
        "totals": {
            "tp": 2,
            "fp": 0,
            "fn": 2,
            "tn": 2,
            "plan_validity": "1.00",
            "plan_accepted": 1,
            "plan_proposed": 1,
            "tokens": 20,
            "latency_ms": 10,
            "scans": 2,
        },
    }
    ablation = {
        "provider": "required tests only (no model)",
        "mode": "required tests only (no model)",
        "model": "",
        "runs": 2,
        "apps": [
            {
                "id": "helper",
                "routes": [
                    {"route": "GET /a", "statuses": ["Confirmed", "Confirmed"]},
                    {"route": "GET /b", "statuses": ["Suspected", "Suspected"]},
                    {"route": "GET /sk-supersecretvalue", "statuses": ["Confirmed", "Confirmed"]},
                ],
            }
        ],
        "totals": {
            "tp": 1,
            "fp": 0,
            "fn": 1,
            "tn": 2,
            "plan_validity": "n/a",
            "plan_accepted": 0,
            "plan_proposed": 0,
            "tokens": None,
            "latency_ms": 0,
            "scans": 2,
        },
    }
    paths = []
    for name, payload in (("benchmark_meta", meta), ("benchmark_baseten", baseten), ("benchmark_no_model", ablation)):
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        paths.append(path.with_suffix(".md"))
    # The command is given markdown paths and reads the JSON beside them.
    for name in ("benchmark_meta", "benchmark_baseten", "benchmark_no_model"):
        (tmp_path / f"{name}.md").write_text("# placeholder\n", encoding="utf-8")
    out = tmp_path / "benchmark_comparison.md"
    code = run_benchmark_compare(files=[str(item) for item in paths], out_path=out)
    text = out.read_text(encoding="utf-8")
    differed = text.split("## Routes that differ", 1)[1]

    assert code == 0
    assert "| meta | 3 | 1 | 1 | 1 | 0.75 (3/4) | 0.75 (3/4) | 0.50 (2/4) | 50 (100/2) | 20 ms (40/2) |" in text
    assert "| baseten | 2 | 0 | 2 | 2 | 1.00 (2/2) | 0.50 (2/4) | 1.00 (1/1) | 10 (20/2) | 5 ms (10/2) |" in text
    assert "| required tests only (no model) | 1 | 0 | 1 | 2 | 1.00 (1/1) | 0.50 (1/2) | n/a (0/0) | n/a | 0 ms (0/2) |" in text
    assert "helper GET /a:" not in differed
    assert "helper GET /b: meta=Suspected, Suspected; baseten=Confirmed, Confirmed; required tests only (no model)=Suspected, Suspected" in differed
    assert _MEASURED in text
    assert "sk-supersecretvalue" not in text
    assert "fw_livekeyvalue" not in text
    assert "Bearer " not in text


def _pair_labels(tmp_path: Path) -> Path:
    labels = tmp_path / "labels.yaml"
    labels.write_text(
        "\n".join(
            (
                "apps:",
                "  - id: helper-check-vulnerable",
                "    config: benchmarks/helper_check/vulnerable/codeguard.yaml",
                "    routes:",
                "      - method: GET",
                "        path: /documents/{id}",
                "        vulnerable: true",
                "      - method: PUT",
                "        path: /documents/{id}",
                "        vulnerable: true",
                "  - id: helper-check-secure",
                "    config: benchmarks/helper_check/secure/codeguard.yaml",
                "    routes:",
                "      - method: GET",
                "        path: /documents/{id}",
                "        vulnerable: false",
                "      - method: PUT",
                "        path: /documents/{id}",
                "        vulnerable: false",
                "",
            )
        ),
        encoding="utf-8",
    )
    return labels


def _git(repo: Path, *args: str, env: dict[str, str]) -> None:
    subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True, text=True)


def _seed_repo(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    """A tiny git repo. Author identity is passed in the environment, not git config."""
    repo = tmp_path / "repo"
    repo.mkdir()
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = "CodeGuard Test"
    env["GIT_AUTHOR_EMAIL"] = "test@example.com"
    env["GIT_COMMITTER_NAME"] = "CodeGuard Test"
    env["GIT_COMMITTER_EMAIL"] = "test@example.com"
    _git(repo, "init", env=env)
    (repo / "README").write_text("seed\n", encoding="utf-8")
    _git(repo, "add", "README", env=env)
    _git(repo, "commit", "-m", "seed", env=env)
    return repo, env


def test_output_files_alone_leave_the_tree_clean(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo, _env = _seed_repo(tmp_path)
    (repo / "reports").mkdir()
    (repo / "reports" / "benchmark.md").write_text("generated report\n", encoding="utf-8")
    (repo / "regression_tests").mkdir()
    (repo / "regression_tests" / "get_documents.py").write_text("def test_owner():\n    assert True\n", encoding="utf-8")
    (repo / "data").mkdir()
    (repo / "data" / "codeguard.db").write_bytes(b"sqlite")
    monkeypatch.chdir(repo)

    assert working_tree_state() == "clean"
    assert tuple(getattr(working_tree_state, "paths", ())) == ()


def test_app_change_is_dirty_and_the_header_lists_paths_not_contents(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, _env = _seed_repo(tmp_path)
    secret = "file-body-SECRET-should-not-be-in-the-header"
    app = repo / "app"
    app.mkdir()
    for index in range(6):
        (app / f"extra_{index}.py").write_text(f"{secret} {index}\n", encoding="utf-8")
    monkeypatch.chdir(repo)

    assert working_tree_state() == "dirty"
    paths = tuple(getattr(working_tree_state, "paths", ()))
    commit = str(getattr(working_tree_state, "commit", ""))
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    assert commit == head
    assert len(commit) == 40
    assert len(paths) == 6
    assert paths[5] not in paths[:5]
    report = replace(
        _report([_row("secure", "GET /z", False, ["not discovered"], [""])]),
        working_tree="dirty",
        commit=commit,
        dirty_paths=paths[:5],
    )
    header = render_markdown(report).split("## Definitions", 1)[0]
    comparison = render_comparison(
        [{"provider": "meta", "totals": {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "scans": 1}}],
        working_tree="dirty",
        commit=commit,
        dirty_paths=paths[:5],
    )

    assert "WARNING: THE WORKING TREE IS DIRTY" in header
    assert f"Commit: {commit}" in header
    for path in paths[:5]:
        assert path in header
        assert path in comparison
    assert paths[5] not in header
    assert secret not in header
    assert secret not in comparison
    assert f"Commit: {commit}" in comparison

