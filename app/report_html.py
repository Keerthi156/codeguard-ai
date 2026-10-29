"""Write a one-page HTML report from the SQLite scan store.

The command reads saved rows only. It does not call the model and it does not
start a server.
"""

from __future__ import annotations

import html
import json
import re
import sys
from datetime import datetime
from pathlib import Path

from app.findings.classifier import Finding, evidence_line
from app.findings.store import FindingStore
from app.runner.executor import Evidence

_BEARER = re.compile(r"Bearer\s+\S+", re.IGNORECASE)
_KEY = re.compile(r"\b(?:sk-|sk_|fw_|b10_)[A-Za-z0-9_-]{4,}\b")
_REQUEST = re.compile(
    r"^(?P<method>[A-Za-z]+)\s+(?P<path>\S+)\s+as\s+(?P<identity>\S+):\s+"
    r"(?P<status>\d+|-)\s+(?P<access>\S+)$"
)
_MISSING = re.compile(
    r"^(?P<method>[A-Za-z]+)\s+\S+\s+(?P<resource>\S+)\s+as\s+(?P<identity>\S+):\s+missing$"
)
_CONFIRMED = frozenset({"Confirmed", "Verified", "Fix proposed", "Verification failed"})
_UNAUTHENTICATED = frozenset({"", "anonymous", "unauthenticated"})
_CHECK_LABEL = {"exploit": "exploit", "owner": "owner control", "regression": "regression"}
_EVIDENCE_RANK = {"EXPLOIT": 0, "CONTROL": 1, "DENIED": 2, "FAILED": 3, "INCONCLUSIVE": 4, "CHECK": 5}
_FOOTER = (
    "Built during the Meta Global AI Developer Hackathon (Oct 27 to Nov 4, 2026). "
    "Fixtures are intentionally vulnerable and for local use only."
)


class ReportUsage(Exception):
    """The report could not be written because the config path is unusable."""


def run_report(config_path: str, *, db_path: str | Path, out_path: str | Path) -> int:
    """Write the HTML report. Returns 0, or 2 when the config file is missing."""
    try:
        page = build_report(config_path, db_path)
    except ReportUsage as exc:
        print(str(exc), file=sys.stderr)
        return 2
    destination = Path(out_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(page, encoding="utf-8")
    print(destination.as_posix())
    return 0


def build_report(config_path: str, db_path: str | Path) -> str:
    """Render the report for the latest stored scan."""
    config = Path(config_path)
    if not config.is_file():
        raise ReportUsage("config error: config file was not found")
    store = FindingStore(db_path)
    scan = store.latest_scan()
    findings = [] if scan is None else store.findings_for_scan(int(scan["id"]))
    scan_at = "" if scan is None else str(scan.get("created_at") or "")
    finding_ids = {finding.id for finding in findings}
    regressions = {
        str(row["finding_id"]): dict(row)
        for row in store.load_regression_tests()
        if str(row["finding_id"]) in finding_ids and _at_or_after(row["created_at"], scan_at)
    }
    attempts = {
        finding.id: _latest_fix_run(
            [row for row in store.load_verifications(finding.id) if _at_or_after(row.get("created_at"), scan_at)]
        )
        for finding in findings
    }
    return _page(config, scan, findings, attempts, regressions)


def _page(
    config: Path,
    scan: dict[str, object] | None,
    findings: list[Finding],
    attempts: dict[str, list[dict[str, object]]],
    regressions: dict[str, object],
) -> str:
    confirmed = sum(1 for finding in findings if finding.status in _CONFIRMED)
    hardened = sum(1 for finding in findings if _is_hardened(finding, attempts.get(finding.id, [])))
    saved = sum(1 for finding in findings if finding.id in regressions)
    summary = (
        f"{len(findings)} routes scanned, {confirmed} confirmed, "
        f"{hardened} verified and hardened, {saved} regression tests saved"
    )
    finding_cards = "".join(
        _card(finding, attempts.get(finding.id, []), regressions.get(finding.id)) for finding in findings
    )
    notice = _empty() if confirmed == 0 and hardened == 0 else ""
    cards = notice + finding_cards
    revision = "-" if scan is None or not scan.get("target_revision") else str(scan["target_revision"])
    scanned_at = "-" if scan is None else str(scan.get("created_at") or "-")
    body = "\n".join(
        (
            _header(scanned_at, config.name, revision),
            f"<p class=\"summary\">{_text(summary)}</p>",
            _shows(len(findings), confirmed, hardened),
            cards,
            _model_section(scan),
            _reproduce(config),
            _limits(),
            _footer(),
        )
    )
    return (
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "<meta charset=\"utf-8\">\n"
        "<title>CodeGuard AI report</title>\n"
        f"<style>\n{_CSS}\n</style>\n"
        "</head>\n"
        "<body>\n"
        "<main>\n"
        f"{body}\n"
        "</main>\n"
        "</body>\n"
        "</html>\n"
    )


def _header(scanned_at: str, config_name: str, revision: str) -> str:
    return (
        "<header>\n"
        "<h1>CodeGuard AI</h1>\n"
        "<p>"
        f"Scan time {_text(scanned_at)}. "
        f"Target {_text(config_name)}. "
        f"Revision {_text(revision)}."
        "</p>\n"
        "</header>"
    )


def _empty() -> str:
    return "<section class=\"card\"><h2>No Confirmed findings</h2></section>"


def _shows(routes: int, confirmed: int, hardened: int) -> str:
    if routes == 0 or confirmed == 0:
        text = "This scan did not confirm that a non-owner can open another user's record."
    elif hardened == confirmed:
        text = (
            "A non-owner could open another user's record. "
            "The saved fix blocks that access, and the owner can still open their own."
        )
    elif hardened:
        text = (
            "A non-owner could open another user's record. "
            "Some saved fixes are verified, and the others are not."
        )
    else:
        text = "A non-owner could open another user's record. The saved fix is not verified for every route."
    return f"<p class=\"shows\">What this shows: {_text(text)}</p>"


def _footer() -> str:
    return f"<footer>\n<p>{_text(_FOOTER)}</p>\n</footer>"


def _card(finding: Finding, rows: list[dict[str, object]], regression: object) -> str:
    final = rows[-1] if rows else None
    diff = _latest_diff(rows)
    root = _root_cause(regression, finding.reason)
    file_name = "not saved" if regression is None else Path(str(regression["file_path"])).name
    history = " | ".join(_history_item(row) for row in rows) or "No attempts stored"
    label, badge = _badge(finding, rows)
    return (
        "<section class=\"card\">\n"
        f"<h2>{_text(finding.method)} {_text(finding.route)} "
        f"<span class=\"badge {badge}\">{_text(label)}</span></h2>\n"
        f"<h3>Root cause</h3>\n<p>{_text(root)}</p>\n"
        "<h3>Evidence</h3>\n"
        f"<ul class=\"evidence\">\n{_evidence_items(finding.evidence)}</ul>\n"
        "<h3>Patch diff</h3>\n"
        f"<div class=\"diff\">\n{_diff_html(diff)}</div>\n"
        "<h3>Before and after</h3>\n"
        f"{_check_table(final)}\n"
        f"<p class=\"history\">{_text(history)}</p>\n"
        f"<p class=\"bypass\">{_text(_bypass_line(final))}</p>\n"
        f"<p>Regression test {_text(file_name)}</p>\n"
        "</section>"
    )


def _evidence_items(evidence: list[Evidence]) -> str:
    ordered = sorted(enumerate(evidence), key=lambda item: (_EVIDENCE_RANK.get(item[1].label, 9), item[0]))
    if not ordered:
        return "<li>No evidence stored</li>"
    return "\n".join(f"<li>{_text(_role_line(item))}</li>" for _index, item in ordered)


def _role_line(item: Evidence) -> str:
    line = evidence_line(item)
    role = _caller_role(item)
    prefix = f"{item.label}:"
    if item.label and role and line.startswith(prefix):
        return f"{item.label} ({role}):{line[len(prefix):]}"
    return line


def _caller_role(item: Evidence) -> str:
    identity = item.identity.strip()
    if identity.lower() in _UNAUTHENTICATED:
        return "unauthenticated"
    if item.label in {"CONTROL", "FAILED"}:
        return f"owner {identity}"
    if item.label in {"EXPLOIT", "DENIED"}:
        return f"non-owner {identity}"
    return identity


def _diff_html(diff: str) -> str:
    if not diff.strip():
        return "<div>No patch diff stored</div>"
    rendered: list[str] = []
    for line in diff.splitlines():
        safe = _text(line if line else " ")
        if line.startswith("+") and not line.startswith("+++"):
            rendered.append(f"<div class=\"add\">{safe}</div>")
        elif line.startswith("-") and not line.startswith("---"):
            rendered.append(f"<div class=\"del\">{safe}</div>")
        else:
            rendered.append(f"<div>{safe}</div>")
    return "\n".join(rendered)


def _check_table(row: dict[str, object] | None) -> str:
    checks = _checks(row)
    if not checks:
        return "<p>Before and after were not stored.</p>"
    owners = _owner_map(checks)
    body = "\n".join(
        "<tr>"
        f"<td>{_text(_CHECK_LABEL.get(str(item.get('check')), str(item.get('check') or '')))}</td>"
        f"<td>{_text(_compact_cell(str(item.get('check') or ''), str(item.get('before') or ''), owners, lead=True))}</td>"
        f"<td>{_text(_compact_cell(str(item.get('check') or ''), str(item.get('after') or ''), owners, lead=False))}</td>"
        "</tr>"
        for item in checks
    )
    return (
        "<table>\n"
        "<thead><tr><th>check</th><th>Before</th><th>After</th></tr></thead>\n"
        f"<tbody>\n{body}\n</tbody>\n"
        "</table>\n"
        f"{_request_details(checks)}"
    )


def _model_section(scan: dict[str, object] | None) -> str:
    summary = "" if scan is None else str(scan.get("model_summary") or "")
    tools = _tool_names(str(scan.get("tool_trace") or "[]") if scan else "[]")
    tokens = "-" if scan is None or scan.get("total_tokens") is None else str(scan.get("total_tokens"))
    calls = "-" if scan is None else str(scan.get("model_calls") or 0)
    latency = "-" if scan is None else str(scan.get("latency_ms") or 0)
    rows = (
        ("Provider", "-" if scan is None else scan.get("provider") or "-"),
        ("Model", "-" if scan is None else scan.get("model_name") or "-"),
        ("Tool mode", _summary_field(summary, "Tool mode")),
        ("Tools called", ", ".join(tools) if tools else "-"),
        ("Calls", calls),
        ("Tokens", tokens),
        ("Latency", f"{latency} ms"),
    )
    body = "\n".join(f"<tr><th>{_text(label)}</th><td>{_text(value)}</td></tr>" for label, value in rows)
    return (
        "<section class=\"card\">\n"
        "<h2>Model run</h2>\n"
        "<table>\n"
        f"<tbody>\n{body}\n</tbody>\n"
        "</table>\n"
        "</section>"
    )


def _reproduce(config: Path) -> str:
    shown = config.as_posix()
    commands = "\n".join(
        (
            f"python -m app.cli scan --config {shown}",
            f"python -m app.cli fix --config {shown}",
            f"python -m app.cli regress --config {shown}",
        )
    )
    return (
        "<section class=\"card\">\n"
        "<h2>How to reproduce</h2>\n"
        f"<pre>{_text(commands)}</pre>\n"
        "</section>"
    )


def _limits() -> str:
    return (
        "<section class=\"card\">\n"
        "<h2>Limits</h2>\n"
        "<p>Single localhost fixture. Static heuristics. Results vary by run.</p>\n"
        "</section>"
    )


def _history_item(row: dict[str, object]) -> str:
    number = int(row.get("attempt") or 1)
    verdict = str(row.get("verdict") or "")
    reason = str(row.get("failure_reason") or "")
    variant = _variant(row)
    outcome = str(variant.get("outcome") or "")
    if outcome == "bypass":
        return f"Attempt {number}: {reason or 'bypass found'}"
    if verdict == "VERIFIED" and outcome == "hardened":
        return f"Attempt {number}: VERIFIED and HARDENED"
    if verdict == "VERIFIED":
        return f"Attempt {number}: VERIFIED"
    if "not JSON" in reason:
        return f"Attempt {number}: model reply was not JSON"
    if verdict == "rejected":
        return f"Attempt {number}: rejected ({reason})"
    if verdict == "INCONCLUSIVE" or str(row.get("final_status") or "") == "Inconclusive":
        return f"Attempt {number}: INCONCLUSIVE ({reason})"
    if verdict == "declined":
        return f"Attempt {number}: declined"
    if verdict:
        return f"Attempt {number}: {verdict} ({reason})" if reason else f"Attempt {number}: {verdict}"
    return f"Attempt {number}: {reason or 'recorded'}"


def _bypass_line(row: dict[str, object] | None) -> str:
    if row is None:
        return "Bypass check: not run"
    variant = _variant(row)
    line = variant.get("line")
    if isinstance(line, str) and line.strip():
        return line
    outcome = str(variant.get("outcome") or "")
    count = len(variant.get("variants") or []) if isinstance(variant.get("variants"), list) else 0
    if outcome == "hardened":
        return f"Bypass check: {count} variants, 0 bypasses (HARDENED)"
    if outcome == "inconclusive":
        return f"Bypass check: {count} variants, inconclusive"
    if outcome == "bypass":
        return "Bypass check: BYPASS FOUND"
    return "Bypass check: not run"


def _latest_fix_run(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    """Keep the newest attempt sequence, one row per attempt number."""
    ordered = sorted(rows, key=lambda row: (str(row.get("created_at") or ""), int(row.get("attempt") or 0)))
    runs: list[list[dict[str, object]]] = []
    current: list[dict[str, object]] = []
    previous = 0
    for row in ordered:
        attempt = int(row.get("attempt") or 1)
        if current and attempt < previous:
            runs.append(current)
            current = []
        current.append(row)
        previous = attempt
    if current:
        runs.append(current)
    if not runs:
        return []
    latest: dict[int, dict[str, object]] = {}
    for row in runs[-1]:
        latest[int(row.get("attempt") or 1)] = row
    return [latest[number] for number in sorted(latest)]


def _at_or_after(value: object, start: str) -> bool:
    if not start:
        return False
    left = _parsed_time(value)
    right = _parsed_time(start)
    if left is None or right is None:
        return str(value or "") >= start
    if left.tzinfo is None and right.tzinfo is not None:
        left = left.replace(tzinfo=right.tzinfo)
    if right.tzinfo is None and left.tzinfo is not None:
        right = right.replace(tzinfo=left.tzinfo)
    return left >= right


def _parsed_time(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _is_hardened(finding: Finding, rows: list[dict[str, object]]) -> bool:
    status = str(rows[-1].get("final_status") or finding.status) if rows else finding.status
    if status != "Verified":
        return False
    if not rows:
        return True
    outcome = str(_variant(rows[-1]).get("outcome") or "")
    return outcome in {"", "hardened"}


def _root_cause(regression: object, fallback: str) -> str:
    if regression is None:
        return fallback
    cause = str(regression["root_cause"] or "").strip()
    return cause or fallback


def _latest_diff(rows: list[dict[str, object]]) -> str:
    for row in reversed(rows):
        diff = str(row.get("patch_diff") or "")
        if diff.strip():
            return diff
    return ""


def _checks(row: dict[str, object] | None) -> list[dict[str, object]]:
    if row is None:
        return []
    try:
        parsed = json.loads(str(row.get("check_results") or "[]"))
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, dict) and item.get("check")]


def _variant(row: dict[str, object]) -> dict[str, object]:
    try:
        parsed = json.loads(str(row.get("variant_results") or "{}"))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _tool_names(raw: str) -> list[str]:
    try:
        parsed = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    names: list[str] = []
    for item in parsed:
        if isinstance(item, dict) and isinstance(item.get("tool"), str) and item["tool"]:
            names.append(item["tool"])
    return names


def _summary_field(summary: str, label: str) -> str:
    prefix = f"{label}: "
    for line in summary.splitlines():
        if line.startswith(prefix):
            value = line[len(prefix) :].strip()
            return value or "-"
    return "-"


def _badge(finding: Finding, rows: list[dict[str, object]]) -> tuple[str, str]:
    status = finding.status
    outcome = ""
    if rows:
        status = str(rows[-1].get("final_status") or finding.status)
        outcome = str(_variant(rows[-1]).get("outcome") or "")
    if status == "Verified" and outcome == "hardened":
        return "Verified and Hardened", "ok"
    if status == "Verified":
        return "Verified", "ok"
    if status == "Verification failed":
        return "Verification failed", "bad"
    if status == "Inconclusive":
        return "Inconclusive", "wait"
    if status == "Confirmed":
        return status, "bad"
    return status, "plain"


def _compact_cell(name: str, text: str, owners: dict[str, str], *, lead: bool) -> str:
    requests = _parse_requests(text)
    if requests is None:
        return text.strip() or "-"
    if name == "exploit":
        return _exploit_phrase(requests, lead=lead)
    if name == "owner":
        return _owner_phrase(requests, lead=lead)
    return _regression_phrase(requests, owners, lead=lead)


def _request_details(checks: list[dict[str, object]]) -> str:
    lines: list[str] = []
    for item in checks:
        name = _CHECK_LABEL.get(str(item.get("check")), str(item.get("check") or "check"))
        before = str(item.get("before") or "")
        after = str(item.get("after") or "")
        if _parse_requests(before) is None and _parse_requests(after) is None:
            continue
        lines.append(f"{name} before")
        lines.extend(f"  {part}" for part in _request_parts(before))
        lines.append(f"{name} after")
        lines.extend(f"  {part}" for part in _request_parts(after))
    if not lines:
        return ""
    return (
        "<details>\n"
        "<summary>Full request details</summary>\n"
        f"<pre>{_text(chr(10).join(lines))}</pre>\n"
        "</details>\n"
    )


def _owner_map(checks: list[dict[str, object]]) -> dict[str, str]:
    owners: dict[str, str] = {}
    for item in checks:
        if str(item.get("check") or "") != "owner":
            continue
        for field in ("before", "after"):
            parsed = _parse_requests(str(item.get(field) or ""))
            if parsed is None:
                continue
            for request in parsed:
                if request["missing"]:
                    continue
                owners[str(request["resource"])] = str(request["identity"])
    return owners


def _exploit_phrase(requests: list[dict[str, object]], *, lead: bool) -> str:
    total, allowed, incomplete = _allowed_count(requests)
    if total == 0:
        return "0 tests"
    mark = "inconclusive" if incomplete and allowed == 0 else ("BAD" if allowed else "OK")
    tail = f"{allowed} allowed ({mark})"
    return f"{total} tests, {tail}" if lead else tail


def _owner_phrase(requests: list[dict[str, object]], *, lead: bool) -> str:
    total, allowed, incomplete = _allowed_count(requests)
    if total == 0:
        return "0 tests"
    if not incomplete and allowed == total:
        phrase = "all allowed (OK)"
    elif incomplete and allowed == 0:
        phrase = "inconclusive"
    else:
        phrase = f"{allowed} allowed (BAD)"
    return f"{total} tests, {phrase}" if lead else phrase


def _regression_phrase(requests: list[dict[str, object]], owners: dict[str, str], *, lead: bool) -> str:
    if not requests:
        return "0 tests"
    bad = 0
    for request in requests:
        if request["access"] != "allowed":
            continue
        owner = owners.get(str(request["resource"]))
        if owner is None or request["identity"] != owner:
            bad += 1
    tail = f"{bad} non-owner allowed"
    return f"{len(requests)} tests, {tail}" if lead else tail


def _allowed_count(requests: list[dict[str, object]]) -> tuple[int, int, bool]:
    allowed = 0
    incomplete = False
    for request in requests:
        if bool(request["missing"]) or request["access"] == "inconclusive" or _server_error(request["status"]):
            incomplete = True
            continue
        if request["access"] == "allowed":
            allowed += 1
    return len(requests), allowed, incomplete


def _server_error(status: object) -> bool:
    return isinstance(status, int) and status >= 500


def _parse_requests(text: str) -> list[dict[str, object]] | None:
    raw = text.strip()
    if not raw or raw in {"-", "not run"} or " as " not in raw:
        return None
    parsed: list[dict[str, object]] = []
    for part in _request_parts(raw):
        request = _parse_request(part)
        if request is None:
            return None
        parsed.append(request)
    return parsed


def _request_parts(text: str) -> list[str]:
    return [part.strip() for part in text.split("; ") if part.strip()]


def _parse_request(part: str) -> dict[str, object] | None:
    matched = _REQUEST.match(part)
    if matched is not None:
        status_text = matched.group("status")
        status = None if status_text == "-" else int(status_text)
        return {
            "identity": matched.group("identity"),
            "status": status,
            "access": matched.group("access"),
            "resource": _resource_key(matched.group("path")),
            "missing": False,
        }
    missing = _MISSING.match(part)
    if missing is None:
        return None
    return {
        "identity": missing.group("identity"),
        "status": None,
        "access": "missing",
        "resource": missing.group("resource"),
        "missing": True,
    }


def _resource_key(path: str) -> str:
    clean = path.split("?", 1)[0].rstrip("/")
    if not clean or "{" in clean:
        return clean
    return clean.rsplit("/", 1)[-1]


def _text(value: object) -> str:
    return html.escape(_redact("" if value is None else str(value)), quote=True)


def _redact(value: str) -> str:
    redacted = _BEARER.sub("Bearer [redacted]", value)
    return _KEY.sub("[redacted]", redacted)


_CSS = """
body {
  margin: 0;
  background: #f4f5f7;
  color: #1c1c1c;
  font-family: "Segoe UI", sans-serif;
  font-size: 16px;
  line-height: 1.45;
}
main {
  max-width: 60rem;
  margin: 0 auto;
  padding: 1.5rem 1.25rem 3rem;
}
h1, h2, h3 { line-height: 1.25; }
h1 { margin: 0 0 0.25rem; font-size: 1.75rem; }
h2 { margin: 0 0 0.75rem; font-size: 1.25rem; }
h3 { margin: 1rem 0 0.35rem; font-size: 1rem; }
header p, .summary { margin: 0.35rem 0 1rem; }
.card {
  background: #fff;
  border: 1px solid #d0d4dc;
  border-radius: 6px;
  padding: 1rem 1.1rem;
  margin: 0 0 1rem;
}
.badge {
  display: inline-block;
  margin-left: 0.4rem;
  padding: 0.1rem 0.45rem;
  border-radius: 4px;
  font-size: 0.85rem;
  vertical-align: middle;
}
.ok { background: #e5f6e8; color: #146c2e; }
.bad { background: #fde8e8; color: #9b1c1c; }
.wait { background: #fff4d6; color: #7a4e00; }
.plain { background: #eceff3; color: #333; }
.evidence { margin: 0.25rem 0 0; padding-left: 1.2rem; }
.diff {
  overflow-x: auto;
  background: #fafafa;
  border: 1px solid #e2e5eb;
  padding: 0.5rem 0.7rem;
  font-family: Consolas, "Courier New", monospace;
  font-size: 0.85rem;
  line-height: 1.35;
  white-space: pre;
}
.diff .add { background: #e5f6e8; color: #146c2e; }
.diff .del { background: #fde8e8; color: #9b1c1c; }
table { width: 100%; border-collapse: collapse; margin-top: 0.35rem; }
th, td {
  border: 1px solid #d0d4dc;
  padding: 0.35rem 0.5rem;
  text-align: left;
  vertical-align: top;
  overflow-wrap: anywhere;
}
th { background: #f4f5f7; }
.history, .bypass { margin: 0.75rem 0 0; }
.shows { margin: -0.25rem 0 1rem; }
footer { margin-top: 1.5rem; font-size: 0.95rem; }
details { margin-top: 0.75rem; }
summary { cursor: pointer; }
pre {
  overflow-x: auto;
  background: #fafafa;
  border: 1px solid #e2e5eb;
  padding: 0.7rem 0.8rem;
  font-family: Consolas, "Courier New", monospace;
  font-size: 0.9rem;
  white-space: pre-wrap;
}
@media print {
  body { background: #fff; }
  main { max-width: none; padding: 0; }
  .card, footer { break-inside: avoid; border-color: #bbb; }
  details > * { display: block !important; }
}
"""
