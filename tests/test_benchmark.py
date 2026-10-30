"""Benchmark harness metrics, with a fake provider and an in-process transport."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import httpx

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
    render_markdown,
    report_json,
    run_benchmark,
    score,
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

    def fake(*, runs: int, out_path: object, labels_path: object) -> int:
        seen["runs"] = runs
        seen["out"] = Path(str(out_path))
        seen["labels"] = Path(str(labels_path))
        return 0

    monkeypatch.setattr("app.benchmark_run.run_benchmark", fake)
    out = tmp_path / "benchmark.md"
    code = main(["benchmark", "--runs", "3", "--out", str(out)])
    assert code == 0
    assert seen["runs"] == 3
    assert seen["out"] == out
    assert seen["labels"] == Path("benchmarks/labels.yaml")


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
