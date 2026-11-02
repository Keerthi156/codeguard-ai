"""Measure scan and fix outcomes on temporary copies of a target.

The original source directory is never modified. Approval is an automatic
callback used only by this command, and only for those temporary copies.
The fix command still asks for a typed y.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import time
from collections.abc import Sequence
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path

import httpx
import yaml
from pydantic import ValidationError

from app.cli import _UsageError, _source_directory
from app.config import credential_names, load_settings
from app.benchmark_run import working_tree_state
from app.findings.classifier import git_revision
from app.findings.store import FindingStore
from app.remediation.patcher import PatchProposal
from app.remediation.verifier import FixUsageError, _run
from app.target_config import load_target_config

AUTO_APPROVED = "AUTO-APPROVED (measurement mode, temporary copies only)"
MEASURED = "Measured on the benchmark fixtures only; not a claim of real-world reliability."
_PROVIDERS = frozenset({"meta", "baseten", "fireworks"})
_CANONICAL = (
    "not JSON",
    "exploit still works",
    "owner control failed",
    "bypass found",
)
_BEARER = re.compile(r"Bearer\s+\S+", re.IGNORECASE)
_KEY = re.compile(r"\b(?:sk-|sk_|fw_|b10_)[A-Za-z0-9_-]{4,}\b")
_HEADER = re.compile(
    r"(?i)\b(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*[:=]\s*\S+"
)
_HARDENED = "Verified and Hardened"
_FAILED = "Verification failed"
_INCONCLUSIVE = "Inconclusive"
_STYLE_IMPORT = "import inside a function"
_STYLE_FALLBACK = "owner lookup fallback chain"
_STYLE_LONG = "changes more than 8 lines"
_STYLE_DOCSTRING = "docstring still says ownership is not checked"
_STYLE_ORDER = (_STYLE_IMPORT, _STYLE_FALLBACK, _STYLE_LONG, _STYLE_DOCSTRING)
_ADDED_IMPORT = re.compile(r"^\s+(?:import\s+[A-Za-z_][\w.]*|from\s+\S+\s+import\s+)")
_FALLBACK_CALL = re.compile(r"\b(?:getattr|hasattr)\s*\(|\.model_dump\s*\(")
_OWNER_WORD = re.compile(r"\bowner\b", re.IGNORECASE)
_OWNERSHIP_DOC = re.compile(r"ownership is not checked", re.IGNORECASE)


@dataclass(frozen=True)
class FindingOutcome:
    """One finding after a measurement run."""

    route: str
    status: str
    attempts: int
    failures: tuple[str, ...]


@dataclass(frozen=True)
class PatchStyle:
    """Informational notes about one applied patch. They do not change the result."""

    route: str
    flags: tuple[str, ...]


@dataclass(frozen=True)
class RunRecord:
    """Tokens, latency, and finding outcomes for one run."""

    tokens: int | None
    latency_ms: int
    findings: tuple[FindingOutcome, ...]
    source_hash_after: str
    error: str = ""
    patches: tuple[PatchStyle, ...] = ()


@dataclass(frozen=True)
class ReliabilityReport:
    """The measurement summary. It contains no API keys and no reasoning text."""

    commit: str
    date: str
    provider: str
    model: str
    runs: int
    source_hash: str
    hash_unchanged: bool
    records: tuple[RunRecord, ...]
    working_tree: str = "clean"
    dirty_paths: tuple[str, ...] = ()


def failure_label(reason: str, verdict: str = "", variant_results: str = "[]") -> str:
    """Map one stored attempt onto a failure reason. An empty string is not a failure."""
    text = " ".join(reason.split())
    lowered = text.lower()
    if "not json" in lowered:
        return "not JSON"
    if "bypass found" in lowered or _variant_outcome(variant_results) == "bypass":
        return "bypass found"
    if "exploit still works" in lowered:
        return "exploit still works"
    if "owner access no longer works" in lowered or "owner check failed" in lowered:
        return "owner control failed"
    if not text:
        return ""
    if verdict == "rejected":
        return text
    return text


def summarize(report: ReliabilityReport) -> dict[str, object]:
    """Count hardened outcomes, failure reasons, and token and latency stats."""
    findings = [item for record in report.records for item in record.findings]
    total = len(findings)
    first = sum(1 for item in findings if item.status == _HARDENED and item.attempts == 1)
    repaired = sum(1 for item in findings if item.status == _HARDENED and item.attempts > 1)
    missed = total - first - repaired
    reasons: dict[str, int] = {name: 0 for name in _CANONICAL}
    for item in findings:
        for reason in item.failures:
            reasons[reason] = reasons.get(reason, 0) + 1
    token_values = [record.tokens for record in report.records if record.tokens is not None]
    latency_values = [record.latency_ms for record in report.records]
    return {
        "findings": total,
        "first": first,
        "repaired": repaired,
        "missed": missed,
        "first_share": _share(first, total),
        "repaired_share": _share(repaired, total),
        "missed_share": _share(missed, total),
        "reasons": reasons,
        "token_mean": _mean(token_values),
        "token_max": "-" if not token_values else str(max(token_values)),
        "latency_mean": _mean(latency_values),
        "latency_max": "-" if not latency_values else str(max(latency_values)),
    }


def render_markdown(report: ReliabilityReport) -> str:
    """Render the measurement report. Counts are printed beside every share."""
    stats = summarize(report)
    valid, failed = _run_split(report)
    hash_line = report.source_hash + (" (unchanged)" if report.hash_unchanged else " (CHANGED)")
    lines = ["# CodeGuard reliability", ""]
    if report.records and failed == len(report.records):
        lines.extend(["ERROR", "", "ALL RUNS FAILED", ""])
        lines.append(report.records[0].error or "the run failed")
        lines.append("")
    if report.working_tree == "dirty":
        lines.append("WARNING: THE WORKING TREE IS DIRTY")
        lines.extend(report.dirty_paths[:5])
        lines.append("")
    lines.extend(
        [
        AUTO_APPROVED,
        "",
        f"Commit: {report.commit}",
        f"Date: {report.date}",
        f"Provider: {report.provider}",
        f"Model: {report.model or '-'}",
        f"Runs: {report.runs}",
        f"Valid runs: {valid}",
        f"Failed runs: {failed}",
        f"Source hash: {hash_line}",
        "",
        MEASURED,
        "",
        "## Outcomes",
        "",
        f"Findings: {stats['findings']}",
        "",
        "| Outcome | Count | Share |",
        "| --- | --- | --- |",
        _outcome_row("Verified and Hardened on the first attempt", stats["first"], stats["first_share"]),
        _outcome_row("Verified and Hardened after repair", stats["repaired"], stats["repaired_share"]),
        _outcome_row("Not verified and hardened", stats["missed"], stats["missed_share"]),
        "",
        "## Failure reasons",
        "",
        "| Reason | Count |",
        "| --- | --- |",
        ]
    )
    reasons = stats["reasons"]
    assert isinstance(reasons, dict)
    for name in _CANONICAL:
        lines.append(f"| {name} | {reasons.get(name, 0)} |")
    for name, count in reasons.items():
        if name in _CANONICAL or count == 0:
            continue
        lines.append(f"| {name} | {count} |")
    lines.extend(
        (
            "",
            "## Tokens and latency",
            "",
            "| Measure | Mean | Max |",
            "| --- | --- | --- |",
            f"| Tokens | {stats['token_mean']} | {stats['token_max']} |",
            f"| Latency | {stats['latency_mean']} ms | {stats['latency_max']} ms |",
            "",
            "## Patch style",
            "",
            "| Flag | Patches |",
            "| --- | --- |",
        )
    )
    style_counts, flagged_patches, patch_total = _style_totals(report)
    for name in _STYLE_ORDER:
        lines.append(f"| {name} | {style_counts[name]} |")
    lines.extend(
        (
            "",
            f"patches with at least one style flag: {flagged_patches} of {patch_total}",
            "",
            "## Runs",
            "",
        )
    )
    if not report.records:
        lines.append("No runs completed.")
        lines.append("")
    for index, record in enumerate(report.records, start=1):
        tokens = "-" if record.tokens is None else str(record.tokens)
        lines.extend(
            (
                f"### Run {index}",
                "",
                f"Tokens: {tokens}",
                f"Latency: {record.latency_ms} ms",
                f"Source hash after: {record.source_hash_after}",
                "",
            )
        )
        if record.error:
            lines.append(f"Error: {record.error}")
            lines.append("")
        lines.extend(
            (
                "| Finding | Status | Attempts | Failed attempts |",
                "| --- | --- | --- | --- |",
            )
        )
        if not record.findings:
            lines.append("| - | - | - | - |")
        for finding in record.findings:
            failed = "; ".join(finding.failures) if finding.failures else "-"
            lines.append(
                f"| {finding.route} | {finding.status} | {finding.attempts} | {failed} |"
            )
        lines.append("")
    return "\n".join(lines)


def report_json(report: ReliabilityReport) -> dict[str, object]:
    """Machine-readable copy of the same counts the markdown prints."""
    stats = summarize(report)
    reasons = stats["reasons"]
    assert isinstance(reasons, dict)
    style_counts, flagged_patches, patch_total = _style_totals(report)
    return {
        "approval": AUTO_APPROVED,
        "commit": report.commit,
        "date": report.date,
        "provider": report.provider,
        "model": report.model,
        "runs": report.runs,
        "source_hash": report.source_hash,
        "source_hash_unchanged": report.hash_unchanged,
        "note": MEASURED,
        "findings": stats["findings"],
        "verified_and_hardened_first_attempt": stats["first"],
        "verified_and_hardened_first_attempt_share": stats["first_share"],
        "verified_and_hardened_after_repair": stats["repaired"],
        "verified_and_hardened_after_repair_share": stats["repaired_share"],
        "not_verified_and_hardened": stats["missed"],
        "not_verified_and_hardened_share": stats["missed_share"],
        "failure_reasons": reasons,
        "tokens_mean": stats["token_mean"],
        "tokens_max": stats["token_max"],
        "latency_mean_ms": stats["latency_mean"],
        "valid_runs": _run_split(report)[0],
        "failed_runs": _run_split(report)[1],
        "all_runs_failed": bool(report.records) and _run_split(report)[1] == len(report.records),
        "latency_max_ms": stats["latency_max"],
        "style_flags": style_counts,
        "patches_with_a_style_flag": flagged_patches,
        "patches": patch_total,
        "flagged_patches": _flagged_patches(report),
        "records": [
            {
                "tokens": record.tokens,
                "latency_ms": record.latency_ms,
                "source_hash_after": record.source_hash_after,
                "error": record.error,
                "findings": [
                    {
                        "route": finding.route,
                        "status": finding.status,
                        "attempts": finding.attempts,
                        "failures": list(finding.failures),
                    }
                    for finding in record.findings
                ],
            }
            for record in report.records
        ],
    }


def run_reliability(
    *,
    config_path: str,
    provider: str,
    runs: int = 10,
    out_path: str | Path = "reports/reliability.md",
    transport: httpx.BaseTransport | None = None,
    verbose: bool = False,
) -> int:
    """Run the scan and fix pipeline ``runs`` times against fresh copies.

    Returns 0 when at least one run finishes and the original directory is unchanged,
    1 when every run failed or the directory hash changes, and 2 when measurement
    cannot start.
    """
    if runs < 1:
        print("reliability error: runs must be at least 1")
        return 2
    if provider not in _PROVIDERS:
        print("reliability error: Invalid PROVIDER. Use meta, baseten, or fireworks.")
        return 2
    try:
        settings = load_settings(provider=provider)
        config = load_target_config(config_path)
        source = _source_directory(config, Path(config_path))
    except (OSError, ValueError, yaml.YAMLError, ValidationError, _UsageError) as exc:
        print(f"reliability error: {' '.join(str(exc).split())}")
        return 2
    if settings.use_mock_ai:
        print("reliability error: the mock provider cannot be used for measurement")
        return 2
    missing = [
        name
        for name, value in zip(
            credential_names(settings.provider),
            (settings.model_api_key, settings.model_name, settings.model_base_url),
            strict=True,
        )
        if not value.strip()
    ]
    if missing:
        print("reliability error: " + ", ".join(missing) + " is not set")
        return 2

    source_hash = directory_hash(source)
    secrets = _secrets(config, settings.model_api_key)
    print(AUTO_APPROVED)
    inner = transport if transport is not None else httpx.HTTPTransport()
    records: list[RunRecord] = []
    unchanged = True
    try:
        for index in range(runs):
            record = _one_run(
                Path(config_path),
                source,
                provider=provider,
                transport=inner,
                verbose=verbose,
            )
            records.append(record)
            print(_progress(index + 1, runs, record), flush=True)
            if record.source_hash_after != source_hash:
                unchanged = False
                break
    finally:
        if transport is None:
            inner.close()

    tree = working_tree_state()
    commit = str(getattr(working_tree_state, "commit", "") or git_revision() or "unknown")
    report = ReliabilityReport(
        commit=commit,
        date=datetime.now(timezone.utc).date().isoformat(),
        provider=provider,
        model=settings.model_name,
        runs=len(records),
        source_hash=source_hash,
        hash_unchanged=unchanged,
        records=tuple(records),
        working_tree=tree,
        dirty_paths=tuple(getattr(working_tree_state, "paths", ())[:5]),
    )
    text = _redact(render_markdown(report), secrets)
    payload = _redact_tree(report_json(report), secrets)
    destination = Path(out_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    json_path = destination.with_suffix(".json")
    destination.write_text(text, encoding="utf-8")
    json_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    failed = sum(1 for record in records if record.error)
    if records and failed == len(records):
        print("ALL RUNS FAILED")
        print(_redact(records[0].error, secrets))
    print(destination.as_posix())
    print(json_path.as_posix())
    if tree == "dirty":
        print("WARNING: THE WORKING TREE IS DIRTY")
    if not unchanged:
        print("reliability error: the original source directory changed")
        return 1
    if records and failed == len(records):
        return 1
    return 0


def directory_hash(path: Path) -> str:
    """Hash file paths and bytes. Caches and bytecode are not part of the source."""
    digest = hashlib.sha256()
    root = path.resolve()
    files = [
        item
        for item in root.rglob("*")
        if item.is_file() and "__pycache__" not in item.parts and item.suffix != ".pyc"
    ]
    for item in sorted(files, key=lambda current: current.relative_to(root).as_posix()):
        relative = item.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(item.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


class _Meter(httpx.BaseTransport):
    """Count tokens and latency for model calls. The body is not stored."""

    def __init__(self, inner: httpx.BaseTransport) -> None:
        self._inner = inner
        self.tokens = 0
        self.latency_ms = 0
        self.saw_tokens = False

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        started = time.perf_counter()
        try:
            response = self._inner.handle_request(request)
        finally:
            self.latency_ms += max(0, int((time.perf_counter() - started) * 1000))
        self._record_tokens(response)
        return response

    def close(self) -> None:
        """Leave the shared inner transport open for the next model call."""
        return

    def _record_tokens(self, response: httpx.Response) -> None:
        try:
            response.read()
            payload = json.loads(response.content)
        except (json.JSONDecodeError, UnicodeError, ValueError, httpx.StreamError):
            return
        usage = payload.get("usage") if isinstance(payload, dict) else None
        if not isinstance(usage, dict):
            return
        total = usage.get("total_tokens")
        if isinstance(total, bool) or not isinstance(total, int):
            return
        self.tokens += total
        self.saw_tokens = True


def _one_run(
    config_path: Path,
    source: Path,
    *,
    provider: str,
    transport: httpx.BaseTransport,
    verbose: bool,
) -> RunRecord:
    before = directory_hash(source)
    work = Path(tempfile.mkdtemp(prefix="codeguard-reliability-"))
    meter = _Meter(transport)
    previous_regression = os.environ.get("CODEGUARD_REGRESSION_DIR")
    error = ""
    findings: tuple[FindingOutcome, ...] = ()
    patches: tuple[PatchStyle, ...] = ()
    try:
        copy = work / "source"
        shutil.copytree(
            source,
            copy,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        generated = work / "codeguard.yaml"
        _write_config(config_path, copy, generated)
        os.environ["CODEGUARD_REGRESSION_DIR"] = str(work / "regression")
        with contextlib.redirect_stdout(sys.stdout if verbose else io.StringIO()):
            try:
                _run(
                    str(generated),
                    db_path=work / "findings.db",
                    canned=False,
                    approve=_auto_approve,
                    settings=None,
                    transport=meter,
                    provider=provider,
                )
            except FixUsageError as exc:
                error = _format_error(exc.__cause__ or exc)
            else:
                findings = _outcomes(work / "findings.db")
                patches = _applied_patches(work / "findings.db")
    except Exception as exc:
        error = _format_error(exc)
    finally:
        if previous_regression is None:
            os.environ.pop("CODEGUARD_REGRESSION_DIR", None)
        else:
            os.environ["CODEGUARD_REGRESSION_DIR"] = previous_regression
        shutil.rmtree(work, ignore_errors=True)
    after = directory_hash(source)
    if after != before and not error:
        error = "RuntimeError: the original source directory changed"
    return RunRecord(
        tokens=meter.tokens if meter.saw_tokens else None,
        latency_ms=meter.latency_ms,
        findings=() if error else findings,
        source_hash_after=after,
        error=error,
        patches=() if error else patches,
    )


def _auto_approve(_proposal: PatchProposal) -> bool:
    """Approve a patch only for this measurement. The fix command does not use it."""
    return True


def _write_config(original: Path, copy: Path, destination: Path) -> None:
    raw = yaml.safe_load(original.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("config error: invalid config")
    raw["source_dir"] = str(copy)
    target = raw.get("target_app")
    attribute = "app"
    if isinstance(target, str) and ":" in target:
        attribute = target.split(":")[-1] or "app"
    if (copy / "app.py").is_file():
        raw["target_app"] = f"app:{attribute}"
    raw["base_url"] = f"http://127.0.0.1:{_free_port()}"
    destination.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")


def _outcomes(database: Path) -> tuple[FindingOutcome, ...]:
    if not database.is_file():
        return ()
    store = FindingStore(database)
    scan = store.latest_scan()
    if scan is None:
        return ()
    outcomes: list[FindingOutcome] = []
    for finding in store.findings_for_scan(int(scan["id"])):
        rows = store.load_verifications(finding.id)
        if not rows:
            continue
        ordered = sorted(rows, key=lambda row: (int(row["attempt"]), str(row["created_at"])))
        last = ordered[-1]
        failures = tuple(
            label
            for row in ordered
            if (
                label := failure_label(
                    str(row.get("failure_reason") or ""),
                    str(row.get("verdict") or ""),
                    str(row.get("variant_results") or "[]"),
                )
            )
            and str(row.get("final_status") or "") != "Verified"
        )
        outcomes.append(
            FindingOutcome(
                route=f"{finding.method} {finding.route}",
                status=_display_status(str(last.get("final_status") or ""), str(last.get("variant_results") or "[]")),
                attempts=int(last["attempt"]),
                failures=failures,
            )
        )
    return tuple(outcomes)


def _display_status(status: str, variant_results: str) -> str:
    outcome = _variant_outcome(variant_results)
    if status == "Verified" and outcome not in {"bypass", "inconclusive"}:
        return _HARDENED
    if status == "Inconclusive" or outcome == "inconclusive":
        return _INCONCLUSIVE
    return _FAILED


def _variant_outcome(variant_results: str) -> str:
    try:
        payload = json.loads(variant_results)
    except json.JSONDecodeError:
        return ""
    if isinstance(payload, dict):
        outcome = payload.get("outcome")
        return outcome if isinstance(outcome, str) else ""
    return ""


def _secrets(config: object, api_key: str) -> set[str]:
    users = getattr(config, "users", ())
    secrets = {user.token for user in users if getattr(user, "token", "")}
    if api_key.strip():
        secrets.add(api_key)
    return secrets


def _share(count: object, total: object) -> str:
    if not isinstance(count, int) or not isinstance(total, int) or total == 0:
        return f"{count}/{total} (n/a)"
    percent = f"{(count / total) * 100:.1f}".rstrip("0").rstrip(".")
    return f"{count}/{total} ({percent}%)"


def _mean(values: Sequence[int]) -> str:
    if not values:
        return "n/a"
    rendered = f"{sum(values) / len(values):.1f}"
    if rendered.endswith(".0"):
        return rendered[:-2]
    return rendered


def _outcome_row(label: str, count: object, share: object) -> str:
    return f"| {label} | {count} | {share} |"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def style_flags(diff: str) -> tuple[str, ...]:
    """Informational notes from one unified diff. Nothing here rejects a patch."""
    added: list[str] = []
    surviving: list[str] = []
    changed = 0
    for line in diff.splitlines():
        if line.startswith(("+++", "---", "@@", "diff ", "index ")):
            continue
        if line.startswith("+"):
            changed += 1
            text = line[1:]
            added.append(text)
            surviving.append(text)
        elif line.startswith("-"):
            changed += 1
        elif line.startswith(" "):
            surviving.append(line[1:])
    flags: list[str] = []
    if any(_ADDED_IMPORT.match(line) for line in added):
        flags.append(_STYLE_IMPORT)
    added_text = "\n".join(added)
    if _OWNER_WORD.search(added_text) and len(_FALLBACK_CALL.findall(added_text)) >= 2:
        flags.append(_STYLE_FALLBACK)
    if changed > 8:
        flags.append(_STYLE_LONG)
    if _docstring_left(surviving):
        flags.append(_STYLE_DOCSTRING)
    return tuple(flags)


def _docstring_left(surviving: Sequence[str]) -> bool:
    """True when a remaining docstring line still says ownership is not checked."""
    if not any(_OWNERSHIP_DOC.search(line) for line in surviving):
        return False
    blob = "\n".join(surviving)
    return '"""' in blob or "'''" in blob


def _style_totals(report: ReliabilityReport) -> tuple[dict[str, int], int, int]:
    counts = {name: 0 for name in _STYLE_ORDER}
    total = 0
    flagged = 0
    for record in report.records:
        for patch in record.patches:
            total += 1
            if not patch.flags:
                continue
            flagged += 1
            for flag in patch.flags:
                if flag in counts:
                    counts[flag] += 1
    return counts, flagged, total


def _flagged_patches(report: ReliabilityReport) -> list[dict[str, object]]:
    listed: list[dict[str, object]] = []
    for run_number, record in enumerate(report.records, start=1):
        for patch in record.patches:
            if not patch.flags:
                continue
            listed.append({"route": patch.route, "run": run_number, "flags": list(patch.flags)})
    return listed


def _progress(index: int, total: int, record: RunRecord) -> str:
    """One quiet-mode line. It names each route, the time, and the token count."""
    if record.error:
        body = "error"
    elif not record.findings:
        body = "no findings"
    else:
        body = ", ".join(
            f"{finding.route.split()[0]} {_short_status(finding.status)} (attempt {finding.attempts})"
            for finding in record.findings
        )
    tokens = "n/a" if record.tokens is None else str(record.tokens)
    return f"run {index}/{total}: {body}, {record.latency_ms / 1000:.1f} s, {tokens} tokens"


def _short_status(status: str) -> str:
    if status == _HARDENED:
        return "VERIFIED"
    if status == _INCONCLUSIVE:
        return "INCONCLUSIVE"
    return "FAILED"


def _applied_patches(database: Path) -> tuple[PatchStyle, ...]:
    if not database.is_file():
        return ()
    store = FindingStore(database)
    scan = store.latest_scan()
    if scan is None:
        return ()
    notes: list[PatchStyle] = []
    for finding in store.findings_for_scan(int(scan["id"])):
        route = f"{finding.method} {finding.route}"
        for row in store.load_verifications(finding.id):
            diff = str(row.get("patch_diff") or "")
            verdict = str(row.get("verdict") or "")
            if not diff.strip() or verdict in {"rejected", "declined"}:
                continue
            notes.append(PatchStyle(route, style_flags(diff)))
    return tuple(notes)


def _run_split(report: ReliabilityReport) -> tuple[int, int]:
    failed = sum(1 for record in report.records if record.error)
    return len(report.records) - failed, failed


def _format_error(exc: BaseException) -> str:
    """Type plus a short message. Headers and key-like text are not included."""
    text = " ".join(str(exc).split())
    text = _HEADER.sub("[redacted]", text)
    text = _BEARER.sub("Bearer [redacted]", text)
    text = _KEY.sub("[redacted]", text)
    if len(text) > 180:
        text = text[:180].rstrip()
    return f"{type(exc).__name__}: {text}"


def _redact(text: str, secrets: set[str]) -> str:
    redacted = _HEADER.sub("[redacted]", text)
    redacted = _BEARER.sub("Bearer [redacted]", redacted)
    for secret in sorted((item for item in secrets if item), key=len, reverse=True):
        redacted = redacted.replace(secret, "[redacted]")
    return _KEY.sub("[redacted]", redacted)


def _redact_tree(value: object, secrets: set[str]) -> object:
    if isinstance(value, str):
        return _redact(value, secrets)
    if isinstance(value, list):
        return [_redact_tree(item, secrets) for item in value]
    if isinstance(value, dict):
        return {_redact(str(key), secrets): _redact_tree(item, secrets) for key, item in value.items()}
    return value
