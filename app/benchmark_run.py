"""Measure the existing scan pipeline against hand-written benchmark labels.

This module does not change analysis, planning, execution, or verification.
It runs those steps and records what they returned.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml
from pydantic import ValidationError

from app import cli as cli_module
from app.ai.factory import get_provider
from app.ai.model_run import ModelRun
from app.ai.required_plan import supplement_plan
from app.ai.validator import validate_plan
from app.analyzer.auth_checks import assess_routes
from app.analyzer.routes import discover_routes
from app.findings.classifier import classify, git_revision
from app.runner.executor import execute_plan
from app.target_config import TargetConfig, load_target_config

_BEARER = re.compile(r"Bearer\s+\S+", re.IGNORECASE)
_KEY = re.compile(r"\b(?:sk-|sk_|fw_|b10_)[A-Za-z0-9_-]{4,}\b")
_MEASURED = "Measured on this benchmark only; not a claim of real-world coverage."
_DEFINITIONS = (
    "A route counts as DETECTED when its status is Confirmed.",
    "True positive: labeled vulnerable and Confirmed.",
    "False negative: labeled vulnerable and not Confirmed.",
    "False negatives are counted separately as not discovered, discovered not flagged, Suspected not reproduced, or Inconclusive.",
    "True negatives are counted separately as discovered not flagged, or flagged but not reproduced.",
    "not discovered: static route discovery did not find the route.",
    "discovered, not flagged: static route discovery found the route and the static heuristics did not mark it Suspected.",
    "Suspected not reproduced: the static heuristics marked the route Suspected and the scan did not Confirm it.",
    "flagged by static analysis is yes when the static heuristics marked the route Suspected, and no otherwise.",
    "False positive: labeled secure and Confirmed.",
    "True negative: labeled secure and not Confirmed.",
    "Each run of a labeled route counts once.",
    "An error is recorded in the table and is not a true positive, false positive, false negative, or true negative.",
    "Plan-validity rate: accepted tests divided by proposed tests.",
)
_NOT_DISCOVERED = "not discovered"
_NOT_FLAGGED = "discovered, not flagged"


@dataclass(frozen=True)
class LabelRoute:
    method: str
    path: str
    vulnerable: bool

    @property
    def route(self) -> str:
        return f"{self.method.upper()} {self.path}"


@dataclass(frozen=True)
class LabelApp:
    app_id: str
    config: str
    routes: tuple[LabelRoute, ...]


@dataclass(frozen=True)
class RouteRow:
    """Statuses for one labeled route across every run."""

    app_id: str
    route: str
    vulnerable: bool
    statuses: tuple[str, ...]
    reasons: tuple[str, ...]
    flagged: tuple[str, ...] = ()


@dataclass(frozen=True)
class Totals:
    tp: int
    fp: int
    fn: int
    tn: int
    errors: int
    fn_inconclusive: int
    fn_suspected: int
    fn_not_discovered: int
    fn_discovered_not_flagged: int
    tn_discovered_not_flagged: int
    tn_flagged_not_reproduced: int
    tn_not_discovered: int
    precision: str
    recall: str


@dataclass(frozen=True)
class Miss:
    app_id: str
    route: str
    run: int
    status: str
    reason: str


@dataclass(frozen=True)
class AppBlock:
    app_id: str
    discovered: int
    labeled: int
    routes: tuple[RouteRow, ...]
    errors: tuple[str, ...]


@dataclass(frozen=True)
class BenchmarkReport:
    commit: str
    date: str
    provider: str
    model: str
    runs: int
    apps: tuple[AppBlock, ...]
    totals: Totals
    plan_validity: str
    plan_submissions: int
    tool_calls: int
    tokens: int | None
    latency_ms: int
    discovered: int
    labeled: int
    misses: tuple[Miss, ...]


def rate(numerator: int, denominator: int) -> str:
    """Return a two-decimal rate, or n/a when the denominator is zero."""
    if denominator == 0:
        return "n/a"
    return f"{numerator / denominator:.2f}"


def trial_kind(vulnerable: bool, status: str) -> str:
    """Classify one route-run. ``error`` is kept out of the confusion matrix."""
    if status == "error":
        return "error"
    if vulnerable and status == "Confirmed":
        return "TP"
    if vulnerable:
        return "FN"
    if status == "Confirmed":
        return "FP"
    return "TN"


def describe_route(
    method: str,
    path: str,
    *,
    inventory: set[tuple[str, str]],
    flagged_routes: set[tuple[str, str]],
    finding_status: str | None,
    finding_reason: str = "",
    static_reason: str = "",
) -> tuple[str, str, str]:
    """Return status, the tool's reason, and whether static analysis flagged the route.

    ``inventory`` is the scan's discovered routes. ``flagged_routes`` is the subset
    whose static heuristic status is Suspected. ``finding_status`` is the classified
    finding, when the scan stored one.
    """
    key = (method.upper(), path)
    flagged = "yes" if key in flagged_routes else "no"
    if finding_status:
        return finding_status, finding_reason, flagged
    if key not in inventory:
        return _NOT_DISCOVERED, "", "no"
    if flagged == "no":
        return _NOT_FLAGGED, static_reason, "no"
    return "Suspected", static_reason or "Suspected, not reproduced", "yes"


def fn_bucket(status: str) -> str | None:
    """Bucket a false negative. Other non-Confirmed statuses stay in the FN total only."""
    if status == "Inconclusive":
        return "Inconclusive"
    if status == "Suspected":
        return "Suspected not reproduced"
    if status == _NOT_DISCOVERED:
        return "not discovered"
    if status == _NOT_FLAGGED:
        return "discovered, not flagged"
    return None


def consistency(statuses: Sequence[str]) -> str:
    if statuses and len(set(statuses)) == 1:
        return "agreed"
    return "disagreed"


def _flagged_values(row: RouteRow) -> tuple[str, ...]:
    if row.flagged:
        return row.flagged
    return tuple(_infer_flag(status) for status in row.statuses)


def _flagged_cell(row: RouteRow) -> str:
    values = _flagged_values(row)
    if not values:
        return "no"
    if len(set(values)) == 1:
        return values[0]
    return ", ".join(values)


def _infer_flag(status: str) -> str:
    if status == "error":
        return "-"
    if status in {_NOT_DISCOVERED, _NOT_FLAGGED}:
        return "no"
    if status == "Suspected":
        return "yes"
    return "yes"


def score(rows: Sequence[RouteRow]) -> Totals:
    """Count every run of every labeled route."""
    tp = fp = fn = tn = errors = 0
    inconclusive = suspected = missing = quiet = 0
    tn_quiet = tn_flagged = tn_missing = 0
    for row in rows:
        for status in row.statuses:
            kind = trial_kind(row.vulnerable, status)
            if kind == "TP":
                tp += 1
            elif kind == "FP":
                fp += 1
            elif kind == "FN":
                fn += 1
                bucket = fn_bucket(status)
                if bucket == "Inconclusive":
                    inconclusive += 1
                elif bucket == "Suspected not reproduced":
                    suspected += 1
                elif bucket == "not discovered":
                    missing += 1
                elif bucket == "discovered, not flagged":
                    quiet += 1
            elif kind == "TN":
                tn += 1
                if status == _NOT_FLAGGED:
                    tn_quiet += 1
                elif status == "Suspected":
                    tn_flagged += 1
                elif status == _NOT_DISCOVERED:
                    tn_missing += 1
            else:
                errors += 1
    return Totals(
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        errors=errors,
        fn_inconclusive=inconclusive,
        fn_suspected=suspected,
        fn_not_discovered=missing,
        fn_discovered_not_flagged=quiet,
        tn_discovered_not_flagged=tn_quiet,
        tn_flagged_not_reproduced=tn_flagged,
        tn_not_discovered=tn_missing,
        precision=rate(tp, tp + fp),
        recall=rate(tp, tp + fn),
    )


def misses_for(rows: Sequence[RouteRow]) -> tuple[Miss, ...]:
    """Wrong route-runs only: false positives and false negatives, with the tool's reason."""
    found: list[Miss] = []
    for row in rows:
        for index, status in enumerate(row.statuses, start=1):
            if trial_kind(row.vulnerable, status) not in {"FP", "FN"}:
                continue
            reason = row.reasons[index - 1] if index - 1 < len(row.reasons) else ""
            found.append(Miss(row.app_id, row.route, index, status, reason))
    return tuple(found)


def render_markdown(report: BenchmarkReport) -> str:
    lines = [
        "# CodeGuard benchmark",
        "",
        f"Commit: {report.commit}",
        f"Date: {report.date}",
        _provider_line(report.provider),
        f"Model: {report.model or '-'}",
        _MEASURED,
        "",
        "## Definitions",
        "",
    ]
    lines.extend(f"- {item}" for item in _DEFINITIONS)
    lines.append("")
    for app in report.apps:
        lines.extend(
            (
                f"## {app.app_id}",
                "",
                f"Routes the static analyzer discovered: {app.discovered}. Routes labeled: {app.labeled}.",
                "",
            )
        )
        for index, message in enumerate(app.errors, start=1):
            if message:
                lines.append(f"Run {index}: error: {message}")
        if any(app.errors):
            lines.append("")
        header = [
            "Route",
            "flagged by static analysis",
            *[f"Run {index}" for index in range(1, report.runs + 1)],
            "Consistent",
        ]
        lines.append("| " + " | ".join(header) + " |")
        lines.append("| " + " | ".join("---" for _ in header) + " |")
        for row in app.routes:
            cells = [row.route, _flagged_cell(row), *row.statuses, consistency(row.statuses)]
            lines.append("| " + " | ".join(cells) + " |")
        lines.append("")
    totals = report.totals
    tokens = "-" if report.tokens is None else str(report.tokens)
    lines.extend(
        (
            "## Totals",
            "",
            f"Runs: {report.runs}",
            f"True positives: {totals.tp}",
            f"False positives: {totals.fp}",
            f"False negatives: {totals.fn}",
            f"- not discovered: {totals.fn_not_discovered}",
            f"- discovered, not flagged: {totals.fn_discovered_not_flagged}",
            f"- Suspected not reproduced: {totals.fn_suspected}",
            f"- Inconclusive: {totals.fn_inconclusive}",
            f"True negatives: {totals.tn}",
            f"- discovered, not flagged: {totals.tn_discovered_not_flagged}",
            f"- flagged but not reproduced: {totals.tn_flagged_not_reproduced}",
            f"- not discovered: {totals.tn_not_discovered}",
            f"Errors: {totals.errors}",
            f"Precision: {totals.precision}",
            f"Recall: {totals.recall}",
            f"Plan-validity rate: {report.plan_validity}",
            f"Plan submissions: {report.plan_submissions}",
            f"Tool calls: {report.tool_calls}",
            f"Tokens: {tokens}",
            f"Latency: {report.latency_ms} ms",
            f"Routes the static analyzer discovered: {report.discovered}",
            f"Routes labeled: {report.labeled}",
            "",
            "## Misses and false alarms",
            "",
        )
    )
    if not report.misses:
        lines.append("(none)")
    for miss in report.misses:
        reason = miss.reason.strip()
        detail = f"{miss.status}: {reason}" if reason else miss.status
        lines.append(f"{miss.app_id} {miss.route} run {miss.run}: {detail}")
    lines.append("")
    return "\n".join(lines)


def report_json(report: BenchmarkReport) -> dict[str, object]:
    """Machine-readable copy of the same counts the markdown prints."""
    return {
        "commit": report.commit,
        "date": report.date,
        "provider": report.provider,
        "model": report.model,
        "note": _MEASURED,
        "definitions": list(_DEFINITIONS),
        "runs": report.runs,
        "apps": [
            {
                "id": app.app_id,
                "discovered": app.discovered,
                "labeled": app.labeled,
                "errors": list(app.errors),
                "routes": [
                    {
                        "route": row.route,
                        "vulnerable": row.vulnerable,
                        "statuses": list(row.statuses),
                        "reasons": list(row.reasons),
                        "flagged_by_static_analysis": _flagged_cell(row),
                        "flagged_by_static_analysis_runs": list(_flagged_values(row)),
                        "consistent": consistency(row.statuses),
                    }
                    for row in app.routes
                ],
            }
            for app in report.apps
        ],
        "totals": {
            "tp": report.totals.tp,
            "fp": report.totals.fp,
            "fn": report.totals.fn,
            "tn": report.totals.tn,
            "errors": report.totals.errors,
            "fn_inconclusive": report.totals.fn_inconclusive,
            "fn_suspected": report.totals.fn_suspected,
            "fn_not_discovered": report.totals.fn_not_discovered,
            "fn_discovered_not_flagged": report.totals.fn_discovered_not_flagged,
            "tn_discovered_not_flagged": report.totals.tn_discovered_not_flagged,
            "tn_flagged_not_reproduced": report.totals.tn_flagged_not_reproduced,
            "tn_not_discovered": report.totals.tn_not_discovered,
            "legacy": {
                "fn_inconclusive": report.totals.fn_inconclusive,
                "fn_suspected": report.totals.fn_suspected,
                "fn_not_discovered": (
                    report.totals.fn_not_discovered + report.totals.fn_discovered_not_flagged
                ),
                "Inconclusive": report.totals.fn_inconclusive,
                "Suspected-not-reproduced": report.totals.fn_suspected,
                "not discovered": (
                    report.totals.fn_not_discovered + report.totals.fn_discovered_not_flagged
                ),
            },
            "precision": report.totals.precision,
            "recall": report.totals.recall,
            "plan_validity": report.plan_validity,
            "plan_submissions": report.plan_submissions,
            "tool_calls": report.tool_calls,
            "tokens": report.tokens,
            "latency_ms": report.latency_ms,
            "discovered": report.discovered,
            "labeled": report.labeled,
        },
        "misses": [
            {
                "app": miss.app_id,
                "route": miss.route,
                "run": miss.run,
                "status": miss.status,
                "reason": miss.reason,
            }
            for miss in report.misses
        ],
    }


def run_benchmark(
    *,
    runs: int = 3,
    out_path: str | Path = "reports/benchmark.md",
    labels_path: str | Path = "benchmarks/labels.yaml",
    transport_for: Callable[[TargetConfig], object] | None = None,
) -> int:
    """Scan every labeled app ``runs`` times and write markdown plus JSON."""
    if runs < 1:
        print("benchmark error: runs must be at least 1")
        return 2
    try:
        apps = load_labels(labels_path)
    except (OSError, ValueError, yaml.YAMLError, ValidationError) as exc:
        print(f"benchmark error: {exc}")
        return 2
    provider_name, model_name = _provider_identity()
    tokens: set[str] = set()
    measured = [_measure_app(app, runs, tokens, transport_for) for app in apps]
    report = _assemble(measured, runs, provider_name, model_name)
    payload = _redact_tree(report_json(report), tokens)
    text = _redact(render_markdown(report), tokens)
    destination = Path(out_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    json_path = destination.with_suffix(".json")
    destination.write_text(text, encoding="utf-8")
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(destination.as_posix())
    print(json_path.as_posix())
    return 0


def load_labels(path: str | Path) -> tuple[LabelApp, ...]:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("apps"), list):
        raise ValueError("labels file has no apps list")
    apps: list[LabelApp] = []
    for item in raw["apps"]:
        if not isinstance(item, dict):
            raise ValueError("label app must be a mapping")
        app_id = item.get("id")
        config = item.get("config")
        routes = item.get("routes")
        if not isinstance(app_id, str) or not app_id:
            raise ValueError("label app id is missing")
        if not isinstance(config, str) or not config:
            raise ValueError(f"label config is missing for {app_id}")
        if not isinstance(routes, list) or not routes:
            raise ValueError(f"label routes are missing for {app_id}")
        parsed: list[LabelRoute] = []
        for route in routes:
            if not isinstance(route, dict):
                raise ValueError(f"label route must be a mapping for {app_id}")
            method = route.get("method")
            route_path = route.get("path")
            vulnerable = route.get("vulnerable")
            if not isinstance(method, str) or not isinstance(route_path, str):
                raise ValueError(f"label route method or path is missing for {app_id}")
            if not isinstance(vulnerable, bool):
                raise ValueError(f"label vulnerable must be true or false for {app_id}")
            parsed.append(LabelRoute(method, route_path, vulnerable))
        apps.append(LabelApp(app_id, config, tuple(parsed)))
    if not apps:
        raise ValueError("labels file has no apps")
    return tuple(apps)


@dataclass
class _Measured:
    app: LabelApp
    discovered: int
    rows: list[RouteRow]
    errors: list[str]
    proposed: int = 0
    accepted: int = 0
    plan_submissions: int = 0
    tool_calls: int = 0
    tokens: int | None = None
    latency_ms: int = 0


def _measure_app(
    app: LabelApp,
    runs: int,
    tokens: set[str],
    transport_for: Callable[[TargetConfig], object] | None,
) -> _Measured:
    per_run: list[tuple[str, list[tuple[str, str, str]], int, ModelRun | None]] = []
    discovered_counts: list[int] = []
    measured = _Measured(app, 0, [], [])
    for _run in range(runs):
        outcome = _measure_once(app, tokens, transport_for)
        per_run.append(outcome)
        discovered_counts.append(outcome[2])
        _add_model(measured, outcome[3])
    measured.discovered = max(discovered_counts) if discovered_counts else 0
    measured.errors = [item[0] for item in per_run]
    measured.rows = _rows_from_runs(app, per_run)
    return measured


def _rows_from_runs(
    app: LabelApp,
    per_run: Sequence[tuple[str, list[tuple[str, str, str]], int, ModelRun | None]],
) -> list[RouteRow]:
    rows: list[RouteRow] = []
    for index, label in enumerate(app.routes):
        statuses: list[str] = []
        reasons: list[str] = []
        flagged: list[str] = []
        for error, route_results, _discovered, _model in per_run:
            if error:
                statuses.append("error")
                reasons.append(error)
                flagged.append("-")
                continue
            status, reason, flag = route_results[index]
            statuses.append(status)
            reasons.append(reason)
            flagged.append(flag)
        rows.append(
            RouteRow(
                app.app_id,
                label.route,
                label.vulnerable,
                tuple(statuses),
                tuple(reasons),
                tuple(flagged),
            )
        )
    return rows


def _measure_once(
    app: LabelApp,
    tokens: set[str],
    transport_for: Callable[[TargetConfig], object] | None,
) -> tuple[str, list[tuple[str, str, str]], int, ModelRun | None]:
    """Return (error, per-route status/reason/flag, discovered count, model run)."""
    started: object | None = None
    provider: object | None = None
    model_run: ModelRun | None = None
    discovered = 0
    try:
        config = load_target_config(app.config)
        tokens.update(user.token for user in config.users if user.token)
        source_dir = cli_module._source_directory(config, Path(app.config))
        routes = discover_routes(source_dir)
        discovered = len(routes)
        route_findings = assess_routes(source_dir)
        provider = get_provider()
        plan = provider.plan_tests(route_findings, config.matrix(), routes=routes, config=config)
        validated = validate_plan(plan, routes, config.matrix(), config)
        model_cases, model_tests, required_tests = supplement_plan(
            validated.accepted,
            route_findings,
            config.matrix(),
            config,
        )
        model_run = provider.model_run().with_counts(
            proposed=cli_module._proposed_count(plan),
            accepted=len(validated.accepted),
            rejected=len(validated.rejected),
        ).with_sources(model_tests=model_tests, required_tests=required_tests)
        if validated.rejected:
            detail = "; ".join(
                f"{item.id}: {', '.join(item.reasons)}" for item in validated.rejected
            )
            raise RuntimeError(f"validation error: {detail}")
        started = cli_module._start_target(config, source_dir, sorted(tokens))
        transport = transport_for(config) if transport_for is not None else None
        results = asyncio.run(execute_plan(model_cases, config, transport=transport))
        findings = classify(route_findings, results, config.matrix())
        inventory = {(item.method.upper(), item.path) for item in routes}
        flagged_routes = {
            (item.method.upper(), item.path)
            for item in route_findings
            if item.status == "Suspected"
        }
        static_reasons: dict[tuple[str, str], str] = {}
        for item in route_findings:
            key = (item.method.upper(), item.path)
            if key not in static_reasons or item.status == "Suspected":
                static_reasons[key] = item.reason
        by_route = {(item.method.upper(), item.route): item for item in findings}
        matched: list[tuple[str, str, str]] = []
        for label in app.routes:
            found = by_route.get((label.method.upper(), label.path))
            status, reason, flag = describe_route(
                label.method,
                label.path,
                inventory=inventory,
                flagged_routes=flagged_routes,
                finding_status=None if found is None else found.status,
                finding_reason="" if found is None else found.reason,
                static_reason=static_reasons.get((label.method.upper(), label.path), ""),
            )
            matched.append((status, reason, flag))
        return "", matched, discovered, model_run
    except Exception as exc:
        if model_run is None and provider is not None:
            model_run = getattr(provider, "model_run", lambda: None)()
        message = " ".join(str(exc).split())
        return message, [], discovered, model_run if isinstance(model_run, ModelRun) else None
    finally:
        if started is not None:
            stop = getattr(started, "stop", None)
            if stop is not None:
                stop()


def _add_model(measured: _Measured, model_run: ModelRun | None) -> None:
    if model_run is None:
        return
    measured.proposed += model_run.proposed
    measured.accepted += model_run.accepted
    measured.plan_submissions += model_run.plan_submissions
    measured.tool_calls += len(model_run.tool_trace)
    measured.latency_ms += model_run.latency_ms
    if model_run.total_tokens is not None:
        measured.tokens = (measured.tokens or 0) + model_run.total_tokens


def _assemble(
    measured: Sequence[_Measured],
    runs: int,
    provider_name: str,
    model_name: str,
) -> BenchmarkReport:
    apps = tuple(
        AppBlock(
            item.app.app_id,
            item.discovered,
            len(item.app.routes),
            tuple(item.rows),
            tuple(item.errors),
        )
        for item in measured
    )
    rows = [row for item in measured for row in item.rows]
    proposed = sum(item.proposed for item in measured)
    accepted = sum(item.accepted for item in measured)
    tokens: int | None = None
    for item in measured:
        if item.tokens is not None:
            tokens = (tokens or 0) + item.tokens
    return BenchmarkReport(
        commit=git_revision() or "unknown",
        date=datetime.now(timezone.utc).date().isoformat(),
        provider=provider_name,
        model=model_name,
        runs=runs,
        apps=apps,
        totals=score(rows),
        plan_validity=rate(accepted, proposed),
        plan_submissions=sum(item.plan_submissions for item in measured),
        tool_calls=sum(item.tool_calls for item in measured),
        tokens=tokens,
        latency_ms=sum(item.latency_ms for item in measured),
        discovered=sum(item.discovered for item in measured),
        labeled=sum(len(item.app.routes) for item in measured),
        misses=misses_for(rows),
    )


def _provider_identity() -> tuple[str, str]:
    try:
        probe = get_provider().model_run()
    except Exception:
        return "unknown", ""
    return probe.provider, probe.model_name


def _provider_line(provider: str) -> str:
    if provider == "mock":
        return "Provider: mock (development only)"
    if provider == "unknown" or not provider:
        return "Provider: unknown"
    return f"Provider: {provider}"


def _redact(text: str, tokens: set[str]) -> str:
    redacted = _BEARER.sub("Bearer [redacted]", text)
    for token in sorted((item for item in tokens if item), key=len, reverse=True):
        redacted = redacted.replace(token, "[redacted]")
    return _KEY.sub("[redacted]", redacted)


def _redact_tree(value: object, tokens: set[str]) -> object:
    if isinstance(value, str):
        return _redact(value, tokens)
    if isinstance(value, list):
        return [_redact_tree(item, tokens) for item in value]
    if isinstance(value, dict):
        return {key: _redact_tree(item, tokens) for key, item in value.items()}
    return value
