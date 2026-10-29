"""Re-test an approved patch on a temporary copy and record the fix gate.

The original source tree is never modified. A patch is started only after an
explicit approval, and only from a temporary copy on 127.0.0.1.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import yaml

from app.ai.factory import get_provider
from app.ai.required_plan import supplement_plan
from app.ai.validator import validate_plan
from app.analyzer.auth_checks import assess_routes
from app.analyzer.routes import discover_routes
from app.config import Settings
from app.findings.classifier import Finding, classify
from app.findings.store import FindingStore
from app.remediation.patcher import PatchProposal, PatchRejected, materialize, propose_patch, route_for
from app.runner.executor import TestResult, execute_plan
from app.runner.variants import VariantReport, build_variants, execute_variants, summarize
from app.schemas import TestCase
from app.target_config import TargetConfig, load_target_config

_ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost"})
_BEARER = re.compile(r"Bearer\s+\S+", re.IGNORECASE)
_READY_TIMEOUT_SECONDS = 30.0
_STOP_TIMEOUT_SECONDS = 5.0
_PYTEST_TIMEOUT_SECONDS = 60.0
_REPORT_WIDTH = 100
_MAX_REPAIR_ATTEMPTS = 2


class FixUsageError(Exception):
    """A config or validation problem. The fix command exits 2."""


@dataclass
class _Tracked:
    finding: Finding
    route_file: str
    handler_source: str
    line_numbers: tuple[int, ...]
    labels: list[str] = field(default_factory=list)
    proposal: PatchProposal | None = None
    feedback: str | None = None
    done: bool = False
    declined: bool = False
    attempts: int = 0
    final_status: str = ""
    final_reason: str = ""
    checks: list[_GateCheck] = field(default_factory=list)
    observed: dict[str, TestResult] = field(default_factory=dict)
    variant_history: list[str] = field(default_factory=list)


@dataclass
class _GateCheck:
    name: str
    outcome: str
    before: str
    after: str
    detail: str


@dataclass
class _Running:
    process: subprocess.Popen[bytes]
    log_path: Path

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=_STOP_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=_STOP_TIMEOUT_SECONDS)
        try:
            self.log_path.unlink(missing_ok=True)
        except OSError:
            return


def run_fix(
    config_path: str,
    *,
    db_path: str | Path,
    canned: bool = False,
    approve: Callable[[PatchProposal], bool] | None = None,
    settings: Settings | None = None,
    transport: httpx.BaseTransport | None = None,
    details: bool = False,
) -> int:
    """Scan, propose a fix for each Confirmed finding, and run the fix gate."""
    try:
        return _run(
            config_path,
            db_path=db_path,
            canned=canned,
            approve=approve if approve is not None else _typed_approval,
            settings=settings,
            transport=transport,
            details=details,
        )
    except FixUsageError as exc:
        print(_redact(str(exc), ()), file=sys.stderr)
        return 2


def _run(
    config_path: str,
    *,
    db_path: str | Path,
    canned: bool,
    approve: Callable[[PatchProposal], bool],
    settings: Settings | None,
    transport: httpx.BaseTransport | None,
    details: bool = False,
) -> int:
    config = _load_config(config_path)
    tokens = [user.token for user in config.users]
    source_dir = _source_directory(config, Path(config_path))
    routes = discover_routes(source_dir)
    route_findings = assess_routes(source_dir)
    provider = get_provider()
    try:
        plan = provider.plan_tests(route_findings, config.matrix(), routes=routes, config=config)
    except RuntimeError as exc:
        raise FixUsageError(_redact(str(exc), tokens)) from exc
    validated = validate_plan(plan, routes, config.matrix(), config)
    if validated.rejected:
        detail = "; ".join(f"{item.id}: {', '.join(item.reasons)}" for item in validated.rejected)
        raise FixUsageError(_redact(f"validation error: {detail}", tokens))
    cases, _model_tests, _required_tests = supplement_plan(
        validated.accepted,
        route_findings,
        config.matrix(),
        config,
    )
    if not config.target_app:
        raise FixUsageError("config error: target_app is required")

    started = _start(
        config.target_app,
        _import_root(source_dir, config.target_app),
        config.base_url,
        tokens,
        label="target app",
    )
    try:
        before = asyncio.run(execute_plan(cases, config))
    finally:
        started.stop()
    findings = classify(route_findings, before, config.matrix())
    store = FindingStore(db_path)
    store.save_scan(findings, before, provider.model_run())
    confirmed = [finding for finding in findings if finding.status == "Confirmed"]
    if not confirmed:
        print(_redact("0 verified, 0 verification failed, 0 inconclusive, 0 declined", tokens))
        return 0

    tracked = _track(confirmed, route_findings)
    owners = {resource.id: resource.owner for resource in config.resources}
    before_by_id = {result.test_id: result for result in before}
    _repair(
        tracked,
        source_dir=source_dir,
        cases=cases,
        before=before,
        before_by_id=before_by_id,
        config=config,
        tokens=tokens,
        store=store,
        approve=approve,
        settings=settings,
        transport=transport,
        canned=canned,
        details=details,
        owners=owners,
    )
    verified = sum(item.final_status == "Verified" for item in tracked)
    failed = sum(item.final_status == "Verification failed" for item in tracked)
    inconclusive = sum(item.final_status == "Inconclusive" for item in tracked)
    declined = sum(item.declined for item in tracked)
    summary = (
        f"{verified} verified, {failed} verification failed, {inconclusive} inconclusive, {declined} declined"
    )
    print(_redact(summary, tokens))
    if failed or inconclusive:
        return 1
    if declined:
        return 3
    return 0


def _track(confirmed: Sequence[Finding], route_findings: Sequence[object]) -> list[_Tracked]:
    tracked: list[_Tracked] = []
    for finding in confirmed:
        route = route_for(finding, route_findings)  # type: ignore[arg-type]
        if route is None:
            raise FixUsageError(f"validation error: no handler for {finding.method} {finding.route}")
        tracked.append(
            _Tracked(
                finding=finding,
                route_file=route.file,
                handler_source=route.source,
                line_numbers=tuple(route.line_numbers),
            )
        )
    return tracked


def _repair(
    tracked: list[_Tracked],
    *,
    source_dir: Path,
    cases: Sequence[TestCase],
    before: Sequence[TestResult],
    before_by_id: dict[str, TestResult],
    config: TargetConfig,
    tokens: Sequence[str],
    store: FindingStore,
    approve: Callable[[PatchProposal], bool],
    settings: Settings | None,
    transport: httpx.BaseTransport | None,
    canned: bool,
    details: bool,
    owners: dict[str, str],
) -> None:
    """Propose, gate, and repair each finding. A finding gets at most two repairs."""
    limit = 1 + _MAX_REPAIR_ATTEMPTS
    for _round in range(limit):
        if all(item.done for item in tracked):
            break
        fresh: list[_Tracked] = []
        proposal_dirs: list[Path] = []
        try:
            for item in tracked:
                if item.done:
                    continue
                item.attempts += 1
                try:
                    proposal = propose_patch(
                        item.finding,
                        source_dir=source_dir,
                        route_file=item.route_file,
                        handler_source=item.handler_source,
                        line_numbers=item.line_numbers,
                        matrix=config.matrix(),
                        settings=settings,
                        transport=transport,
                        canned=canned and item.attempts == 1,
                        feedback=None if canned else item.feedback,
                    )
                except PatchRejected as exc:
                    if canned:
                        raise FixUsageError(f"validation error: {_redact(str(exc), tokens)}") from exc
                    reason = _redact(str(exc), tokens)
                    item.labels.append(f"Attempt {item.attempts}: rejected ({reason})")
                    terminal = item.attempts >= limit
                    _record(
                        store,
                        item.finding,
                        None,
                        [],
                        "Verification failed" if terminal else "rejected",
                        reason,
                        tokens,
                        attempt=item.attempts,
                        failure_reason=reason,
                        verdict="rejected",
                    )
                    if terminal:
                        item.done = True
                        item.final_status = "Verification failed"
                        item.final_reason = reason
                    else:
                        item.feedback = reason
                    continue
                except RuntimeError as exc:
                    raise FixUsageError(f"validation error: {_redact(str(exc), tokens)}") from exc
                proposal_dirs.append(Path(proposal.temp_copy_path))
                _print_proposal(item.finding, proposal, tokens)
                if approve(proposal):
                    item.proposal = proposal
                    fresh.append(item)
                    continue
                item.declined = True
                item.done = True
                item.final_status = "Fix proposed"
                item.final_reason = "The user declined the patch."
                _record(
                    store,
                    item.finding,
                    proposal,
                    [],
                    "Fix proposed",
                    item.final_reason,
                    tokens,
                    attempt=item.attempts,
                    failure_reason="",
                    verdict="declined",
                )
                print(
                    _redact(
                        f"{item.finding.method} {item.finding.route}: Fix proposed: the user declined the patch",
                        tokens,
                    )
                )
        finally:
            for path in proposal_dirs:
                _remove_tree(path, source_dir)
        if not fresh:
            continue
        after, regression_note, start_error, reports = _run_patched(
            source_dir,
            tracked,
            config,
            tokens,
            cases,
            fresh=fresh,
            before=before,
        )
        for item in fresh:
            checks, status, reason = _gate(
                item.finding,
                cases,
                before,
                after,
                config,
                start_error,
                regression_note,
            )
            report = reports.get(item.finding.id)
            status, reason, variant_feedback = _with_variants(status, reason, report)
            reason_text = _redact(reason, tokens)
            verdict = _verdict_name(status)
            item.labels.append(_attempt_label(item.attempts, verdict, reason_text))
            item.checks = list(checks)
            item.observed = after
            if report is not None and _show_variant_line(status, report):
                item.variant_history.append(report.line)
            stored_variants = "[]" if report is None else _redact(report.to_json(), tokens)
            _record(
                store,
                item.finding,
                item.proposal,
                checks,
                status,
                reason_text,
                tokens,
                attempt=item.attempts,
                failure_reason="" if status == "Verified" else reason_text,
                verdict=verdict,
                variant_results=stored_variants,
            )
            if status == "Verification failed" and not canned and item.attempts < limit:
                item.feedback = (
                    _redact(variant_feedback, tokens) if variant_feedback else _gate_feedback(reason_text, checks)
                )
                continue
            item.done = True
            item.final_status = status
            item.final_reason = reason_text
            if status == "Verified":
                _export_verified_test(item, config, store, tokens)
    for item in tracked:
        if item.labels:
            print(_redact(" -> ".join(item.labels), tokens))
        if item.declined:
            print(
                _redact(
                    _wrap(
                        f"Finding: {item.finding.method} {item.finding.route}\nDECLINED: the user declined the patch"
                    ),
                    tokens,
                )
            )
        elif item.checks and item.proposal is not None:
            report_text = _report(
                item.finding,
                item.final_status,
                item.final_reason,
                cases,
                before_by_id,
                item.observed,
                owners,
                details,
            )
            if item.variant_history:
                report_text = report_text + "\n" + "\n".join(item.variant_history)
            print(_redact(_wrap(report_text), tokens))
        elif item.final_status == "Verification failed":
            print(_redact(f"VERIFICATION FAILED: {item.final_reason}", tokens))


def _export_verified_test(
    item: _Tracked,
    config: TargetConfig,
    store: FindingStore,
    tokens: Sequence[str],
) -> None:
    if item.proposal is None:
        return
    from app.findings.regression import export_verified

    path = export_verified(
        item.finding.model_copy(update={"status": "Verified"}),
        config,
        root_cause=_redact(item.proposal.root_cause, tokens),
        db_path=store.path,
    )
    if path is not None:
        print(_redact(f"Regression test: {path.name}", tokens))


def _run_patched(
    source_dir: Path,
    tracked: Sequence[_Tracked],
    config: TargetConfig,
    tokens: Sequence[str],
    cases: Sequence[TestCase],
    *,
    fresh: Sequence[_Tracked],
    before: Sequence[TestResult],
) -> tuple[dict[str, TestResult], str, str, dict[str, VariantReport]]:
    chosen = [
        (item.proposal.file, item.proposal.diff)
        for item in tracked
        if item.proposal is not None and not item.declined
    ]
    copied: Path | None = None
    patched: _Running | None = None
    try:
        try:
            copied = materialize(source_dir, chosen)
        except PatchRejected as exc:
            raise FixUsageError(f"validation error: {exc}") from exc
        base_url, patched, start_error = _start_copy(copied, config, tokens)
        if start_error:
            return {}, "", start_error, {}
        patched_config = config.model_copy(update={"base_url": base_url})
        note = _pytest_note(copied)
        after, reports = asyncio.run(
            _recheck(fresh, cases, before, config, patched_config, note)
        )
        return after, note, "", reports
    finally:
        if patched is not None:
            patched.stop()
        if copied is not None:
            _remove_tree(copied, source_dir)


async def _recheck(
    fresh: Sequence[_Tracked],
    cases: Sequence[TestCase],
    before: Sequence[TestResult],
    config: TargetConfig,
    patched_config: TargetConfig,
    regression_note: str,
) -> tuple[dict[str, TestResult], dict[str, VariantReport]]:
    """Re-run the plan, then the fixed variant set, while the patched app is up."""
    rerun = await execute_plan(cases, patched_config)
    after = {result.test_id: result for result in rerun}
    reports: dict[str, VariantReport] = {}
    for item in fresh:
        checks, _status, _reason = _gate(item.finding, cases, before, after, config, "", regression_note)
        if not _variants_ready(checks):
            continue
        built = build_variants(item.finding.method, item.finding.route, patched_config)
        observed = await execute_variants(built, patched_config)
        reports[item.finding.id] = summarize(observed)
    return after, reports


def _variants_ready(checks: Sequence[_GateCheck]) -> bool:
    """The route's own exploit and owner checks passed, so the bypass set can run."""
    by_name = {check.name: check for check in checks}
    exploit = by_name.get("exploit")
    owner = by_name.get("owner")
    return (
        exploit is not None
        and owner is not None
        and exploit.outcome == "pass"
        and owner.outcome == "pass"
    )


def _with_variants(status: str, reason: str, report: VariantReport | None) -> tuple[str, str, str]:
    """Apply the bypass stage. A bypass fails the gate. A 5xx does not start a repair."""
    if report is None:
        return status, reason, ""
    if report.outcome == "bypass":
        return "Verification failed", report.reason, report.model_feedback
    if report.outcome == "inconclusive" and status == "Verified":
        return "Inconclusive", report.reason, ""
    return status, reason, ""


def _show_variant_line(status: str, report: VariantReport) -> bool:
    if report.outcome == "bypass":
        return True
    if report.outcome == "inconclusive":
        return status == "Inconclusive"
    return status == "Verified"


def _attempt_label(number: int, verdict: str, reason: str) -> str:
    if verdict == "VERIFIED":
        return f"Attempt {number}: VERIFIED"
    return f"Attempt {number}: {verdict} ({reason})"


def _verdict_name(status: str) -> str:
    if status == "Verified":
        return "VERIFIED"
    if status == "Verification failed":
        return "VERIFICATION FAILED"
    if status == "Inconclusive":
        return "INCONCLUSIVE"
    return status


def _gate_feedback(reason: str, checks: Sequence[_GateCheck]) -> str:
    lines = [reason]
    for check in checks:
        if check.outcome == "pass":
            continue
        lines.append(
            f"check {check.name} failed ({check.detail}); before: {check.before}; after: {check.after}"
        )
    return "\n".join(lines)


def _gate(
    finding: Finding,
    cases: Sequence[TestCase],
    before: Sequence[TestResult],
    after: dict[str, TestResult],
    config: TargetConfig,
    start_error: str,
    regression_note: str,
) -> tuple[list[_GateCheck], str, str]:
    by_id = {result.test_id: result for result in before}
    owners = {resource.id: resource.owner for resource in config.resources}
    grouped = dict(_case_groups(finding, cases, owners))
    exploit_cases = grouped["exploit"]
    owner_cases = grouped["owner"]
    if start_error:
        checks = [
            _GateCheck(name, "inconclusive", _brief(by_id, group), "not run", start_error)
            for name, group in _case_groups(finding, cases, owners)
        ]
        return checks, "Inconclusive", start_error
    checks = [
        _compare("exploit", exploit_cases, by_id, after, want="denied"),
        _compare("owner", owner_cases, by_id, after, want="allowed"),
        _regression(grouped["regression"], by_id, after, regression_note),
    ]
    if any(check.outcome == "inconclusive" for check in checks):
        failed = next(check for check in checks if check.outcome == "inconclusive")
        return checks, "Inconclusive", failed.detail
    failed_checks = [check for check in checks if check.outcome == "fail"]
    if failed_checks:
        detail = "; ".join(f"{check.name} check failed: {check.detail}" for check in failed_checks)
        return checks, "Verification failed", detail
    return checks, "Verified", "exploit blocked, owner access works, and regression passed"


def _compare(
    name: str,
    cases: Sequence[TestCase],
    before: dict[str, TestResult],
    after: dict[str, TestResult],
    *,
    want: str,
) -> _GateCheck:
    if not cases:
        return _GateCheck(name, "fail", "-", "-", f"{name} check has no tests")
    before_text = _brief(before, cases)
    if any(case.id not in after for case in cases):
        return _GateCheck(name, "inconclusive", before_text, "not run", f"{name} check did not run")
    later = [after[case.id] for case in cases]
    after_text = _brief(after, cases)
    if any(_is_inconclusive(result) for result in later):
        return _GateCheck(name, "inconclusive", before_text, after_text, f"{name} check timed out or returned 5xx")
    if want == "denied" and any(result.access == "allowed" for result in later):
        return _GateCheck(name, "fail", before_text, after_text, "the exploit still works")
    if want == "allowed" and any(result.access != "allowed" for result in later):
        return _GateCheck(name, "fail", before_text, after_text, "owner access no longer works")
    if any(result.outcome != "pass" for result in later):
        return _GateCheck(name, "fail", before_text, after_text, f"{name} check did not match the matrix")
    return _GateCheck(name, "pass", before_text, after_text, f"{name} check passed")


def _regression(
    cases: Sequence[TestCase],
    before: dict[str, TestResult],
    after: dict[str, TestResult],
    pytest_note: str,
) -> _GateCheck:
    before_text = _brief(before, cases)
    if any(case.id not in after for case in cases):
        return _GateCheck("regression", "inconclusive", before_text, "not run", "regression check did not run")
    later = [after[case.id] for case in cases]
    after_text = _brief(after, cases)
    if any(_is_inconclusive(result) for result in later):
        return _GateCheck(
            "regression",
            "inconclusive",
            before_text,
            after_text,
            "regression check timed out or returned 5xx",
        )
    if any(result.outcome != "pass" for result in later):
        return _GateCheck("regression", "fail", before_text, after_text, "the validated plan no longer matches")
    if pytest_note == "passed" or pytest_note == "no target tests directory":
        return _GateCheck("regression", "pass", before_text, after_text, pytest_note)
    if pytest_note == "timed out":
        return _GateCheck("regression", "inconclusive", before_text, after_text, "target tests timed out")
    return _GateCheck("regression", "fail", before_text, after_text, "target tests failed")


def _pytest_note(source_dir: Path) -> str:
    tests = source_dir / "tests"
    if not tests.is_dir():
        return "no target tests directory"
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "tests",
                "-q",
                "--tb=no",
                "--noconftest",
                "--rootdir",
                str(source_dir),
            ],
            cwd=source_dir,
            capture_output=True,
            text=True,
            timeout=_PYTEST_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "timed out"
    except OSError:
        return "failed"
    return "passed" if completed.returncode == 0 else "failed"


def _record(
    store: FindingStore,
    finding: Finding,
    proposal: PatchProposal | None,
    checks: Sequence[_GateCheck],
    status: str,
    reason: str,
    tokens: Sequence[str],
    *,
    attempt: int,
    failure_reason: str,
    verdict: str,
    variant_results: str = "[]",
) -> None:
    created_at = datetime.now(timezone.utc)
    payload = [
        {
            "attempt": attempt,
            "verdict": verdict,
            "failure_reason": failure_reason,
            "check": check.name,
            "result": check.outcome,
            "before": check.before,
            "after": check.after,
            "detail": check.detail,
        }
        for check in checks
    ]
    if not payload:
        payload = [{"attempt": attempt, "verdict": verdict, "failure_reason": failure_reason}]
    diff = "" if proposal is None else proposal.diff
    store.save_verification(
        finding.id,
        _redact(diff, tokens),
        _redact(json.dumps(payload), tokens),
        status,
        created_at,
        attempt=attempt,
        failure_reason=_redact(failure_reason, tokens),
        verdict=verdict,
        variant_results=variant_results,
    )
    store.update_finding_status(finding.id, status, _redact(reason, tokens))


def _print_proposal(finding: Finding, proposal: PatchProposal, tokens: Sequence[str]) -> None:
    print(
        _redact(
            "\n".join(
                (
                    f"Finding: {finding.method} {finding.route} ({finding.id})",
                    f"Root cause: {proposal.root_cause}",
                    f"Side effects: {proposal.side_effects}",
                    proposal.diff.rstrip(),
                )
            ),
            tokens,
        )
    )


def _typed_approval(proposal: PatchProposal) -> bool:
    typed = input(f"Apply this fix for {proposal.finding_id}? Type y to approve: ")
    return typed.strip() == "y"


def _start_copy(source_dir: Path, config: TargetConfig, tokens: Sequence[str]) -> tuple[str, _Running | None, str]:
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    attribute = config.target_app.split(":")[-1] if config.target_app and ":" in config.target_app else "app"
    module = "app"
    try:
        running = _start(f"{module}:{attribute}", source_dir, base_url, tokens)
    except FixUsageError as exc:
        return base_url, None, f"patched app failed to start: {exc}"
    return base_url, running, ""


def _start(target_app: str, cwd: Path, base_url: str, tokens: Sequence[str], *, label: str = "patched app") -> _Running:
    parsed = urlsplit(base_url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "http" or host not in _ALLOWED_HOSTS or parsed.username or parsed.password:
        raise FixUsageError("config error: base_url must be http://127.0.0.1 or http://localhost")
    port = parsed.port or 8000
    log_path = Path(tempfile.gettempdir()) / f"codeguard-fix-{port}.log"
    handle = log_path.open("wb")
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                target_app,
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--log-level",
                "warning",
            ],
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=handle,
            stderr=handle,
        )
    except OSError as exc:
        handle.close()
        log_path.unlink(missing_ok=True)
        raise FixUsageError(f"{label} failed to start") from exc
    handle.close()
    running = _Running(process, log_path)
    deadline = time.monotonic() + _READY_TIMEOUT_SECONDS
    probe = f"http://127.0.0.1:{port}/openapi.json"
    while time.monotonic() < deadline:
        if running.process.poll() is not None:
            running.stop()
            raise FixUsageError(f"{label} failed to start")
        try:
            response = httpx.get(probe, timeout=0.5, trust_env=False, follow_redirects=False)
        except httpx.HTTPError:
            time.sleep(0.2)
            continue
        if response.status_code == 200:
            return running
        time.sleep(0.2)
    running.stop()
    raise FixUsageError(_redact(f"{label} failed to start", tokens))


def _brief(results: dict[str, TestResult], cases: Sequence[TestCase]) -> str:
    parts = [_detail_line(case, results.get(case.id)) for case in cases]
    return "; ".join(parts) if parts else "-"


def _detail_line(case: TestCase, result: TestResult | None) -> str:
    """One request. Status and access stay separated, as in ``401 denied``."""
    if result is None:
        return f"{case.method} {case.route} {case.resource_id} as {case.identity}: missing"
    status = "-" if result.status_code is None else str(result.status_code)
    access = result.access if result.access is not None else result.outcome
    path = result.evidence.path or case.route
    method = result.evidence.method or case.method
    return f"{method} {path} as {case.identity}: {status} {access}"


def _is_inconclusive(result: TestResult) -> bool:
    if result.outcome == "inconclusive":
        return True
    return result.status_code is not None and result.status_code >= 500


def _case_groups(
    finding: Finding,
    cases: Sequence[TestCase],
    owners: dict[str, str],
) -> tuple[tuple[str, list[TestCase]], ...]:
    exploit = [
        case
        for case in cases
        if case.method.upper() == finding.method.upper()
        and case.route == finding.route
        and case.expected == "deny"
        and case.identity != owners.get(case.resource_id)
    ]
    owner = [
        case
        for case in cases
        if case.expected == "allow" and case.identity == owners.get(case.resource_id)
    ]
    return (("exploit", exploit), ("owner", owner), ("regression", list(cases)))


def _report(
    finding: Finding,
    status: str,
    reason: str,
    cases: Sequence[TestCase],
    before: dict[str, TestResult],
    after: dict[str, TestResult],
    owners: dict[str, str],
    details: bool,
) -> str:
    """Compact before/after counts. Full request lines are printed only with details."""
    rows: list[tuple[str, str, str]] = []
    detail_lines: list[str] = []
    for name, group in _case_groups(finding, cases, owners):
        ran = bool(group) and all(case.id in after for case in group)
        rows.append(
            (
                _CHECK_LABEL[name],
                _summary(name, group, before, owners, lead=True),
                _summary(name, group, after, owners, lead=False) if ran else "not run",
            )
        )
        if details:
            detail_lines.append(f"Details: {_CHECK_LABEL[name]} before")
            detail_lines.extend(f"  {_detail_line(case, before.get(case.id))}" for case in group)
            detail_lines.append(f"Details: {_CHECK_LABEL[name]} after")
            if ran:
                detail_lines.extend(f"  {_detail_line(case, after.get(case.id))}" for case in group)
            else:
                detail_lines.append("  not run")
    lines = [f"Finding: {finding.method} {finding.route}", _count_table(rows), _verdict(status, reason)]
    if detail_lines:
        lines.append("\n".join(detail_lines))
    return _wrap("\n".join(lines))


_CHECK_LABEL = {"exploit": "exploit", "owner": "owner control", "regression": "regression"}


def _summary(
    name: str,
    cases: Sequence[TestCase],
    results: dict[str, TestResult],
    owners: dict[str, str],
    *,
    lead: bool,
) -> str:
    if name == "exploit":
        return _exploit_summary(cases, results, lead=lead)
    if name == "owner":
        return _owner_summary(cases, results, lead=lead)
    return _regression_summary(cases, results, owners, lead=lead)


def _exploit_summary(cases: Sequence[TestCase], results: dict[str, TestResult], *, lead: bool) -> str:
    total, allowed, incomplete = _allowed_count(cases, results)
    if total == 0:
        return "0 tests"
    mark = "inconclusive" if incomplete and allowed == 0 else ("BAD" if allowed else "OK")
    tail = f"{allowed} allowed ({mark})"
    if lead:
        return f"{total} tests, {tail}"
    return tail


def _owner_summary(cases: Sequence[TestCase], results: dict[str, TestResult], *, lead: bool) -> str:
    total, allowed, incomplete = _allowed_count(cases, results)
    if total == 0:
        return "0 tests"
    if not incomplete and allowed == total:
        phrase = "all allowed (OK)"
    elif incomplete and allowed == 0:
        phrase = "inconclusive"
    else:
        phrase = f"{allowed} allowed (BAD)"
    if lead:
        return f"{total} tests, {phrase}"
    return phrase


def _regression_summary(
    cases: Sequence[TestCase],
    results: dict[str, TestResult],
    owners: dict[str, str],
    *,
    lead: bool,
) -> str:
    if not cases:
        return "0 tests"
    bad = 0
    for case in cases:
        result = results.get(case.id)
        if result is None or result.access != "allowed":
            continue
        if case.identity != owners.get(case.resource_id):
            bad += 1
    tail = f"{bad} non-owner allowed"
    if lead:
        return f"{len(cases)} tests, {tail}"
    return tail


def _allowed_count(cases: Sequence[TestCase], results: dict[str, TestResult]) -> tuple[int, int, bool]:
    allowed = 0
    incomplete = False
    for case in cases:
        result = results.get(case.id)
        if result is None or _is_inconclusive(result):
            incomplete = True
            continue
        if result.access == "allowed":
            allowed += 1
    return len(cases), allowed, incomplete


def _verdict(status: str, reason: str) -> str:
    if status == "Verified":
        return "VERIFIED: exploit blocked, owner access works, regression clean"
    if status == "Verification failed":
        return f"VERIFICATION FAILED: {reason}"
    if status == "Inconclusive":
        return f"INCONCLUSIVE: {reason}"
    return f"{status}: {reason}"


def _count_table(rows: Sequence[tuple[str, str, str]]) -> str:
    headers = ("check", "Before", "After")
    rendered = [headers, *rows]
    widths = [max(len(row[index]) for row in rendered) for index in range(3)]
    gap = 2
    while sum(widths) + gap * 2 > _REPORT_WIDTH and widths[1] > 16:
        widths[1] -= 1
    while sum(widths) + gap * 2 > _REPORT_WIDTH and widths[2] > 12:
        widths[2] -= 1

    def cells(row: Sequence[str]) -> list[list[str]]:
        wrapped: list[list[str]] = []
        for index, cell in enumerate(row):
            wrapped.append(textwrap.wrap(cell, width=widths[index], break_long_words=False) or [""])
        return wrapped

    lines: list[str] = []
    for row in rendered:
        wrapped = cells(row)
        height = max(len(item) for item in wrapped)
        for line_index in range(height):
            parts = [
                (wrapped[index][line_index] if line_index < len(wrapped[index]) else "").ljust(widths[index])
                for index in range(3)
            ]
            lines.append("  ".join(parts).rstrip())
    return "\n".join(lines)


def _wrap(text: str) -> str:
    lines: list[str] = []
    for line in text.splitlines():
        if len(line) <= _REPORT_WIDTH:
            lines.append(line)
            continue
        lines.extend(
            textwrap.wrap(
                line,
                width=_REPORT_WIDTH,
                break_long_words=False,
                break_on_hyphens=False,
                replace_whitespace=False,
            )
            or [""]
        )
    return "\n".join(lines)


def _load_config(config_path: str) -> TargetConfig:
    try:
        return load_target_config(config_path)
    except FileNotFoundError as exc:
        raise FixUsageError("config error: config file was not found") from exc
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise FixUsageError("config error: invalid config") from exc


def _source_directory(config: TargetConfig, config_path: Path) -> Path:
    if not config.source_dir:
        raise FixUsageError("config error: source_dir is required")
    raw = Path(config.source_dir)
    if raw.is_absolute() and raw.is_dir():
        return raw
    candidates = [Path.cwd() / raw, config_path.parent / raw]
    if config_path.exists():
        candidates.extend(parent / raw for parent in config_path.resolve().parents)
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    raise FixUsageError("config error: source_dir is not a directory")


def _import_root(source_dir: Path, target_app: str) -> Path:
    top = target_app.split(":", 1)[0].split(".", 1)[0]
    for candidate in (source_dir, *source_dir.resolve().parents):
        if (candidate / top / "__init__.py").is_file() or (candidate / f"{top}.py").is_file():
            return candidate
    return Path.cwd()


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _remove_tree(path: Path, source_dir: Path) -> None:
    if path.resolve() == source_dir.resolve():
        return
    for _attempt in range(5):
        try:
            shutil.rmtree(path)
            return
        except OSError:
            time.sleep(0.2)
    shutil.rmtree(path, ignore_errors=True)


def _redact(text: str, tokens: Sequence[str]) -> str:
    redacted = _BEARER.sub("Bearer [redacted]", text)
    for token in sorted({item for item in tokens if item}, key=len, reverse=True):
        redacted = redacted.replace(token, "[redacted]")
    return redacted
