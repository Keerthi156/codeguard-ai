"""Command line for a local authorization scan.

Analysis never imports or executes the target. The target app is started only
as a localhost uvicorn process, and only after the config and test plan pass
validation.

    python -m app.cli scan --config fixtures/codeguard.vulnerable.yaml
    python -m app.cli fix --config fixtures/codeguard.vulnerable.yaml
"""

from __future__ import annotations

import argparse
import asyncio
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import yaml
from pydantic import ValidationError

from app.ai.factory import get_provider
from app.ai.required_plan import supplement_plan
from app.ai.model_run import ModelRun
from app.ai.validator import validate_plan
from app.analyzer.auth_checks import assess_routes
from app.analyzer.routes import discover_routes
from app.findings.classifier import Finding, classify, evidence_line
from app.findings.store import DEFAULT_DB_PATH, FindingStore
from app.runner.executor import execute_plan
from app.target_config import TargetConfig, load_target_config

_ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost"})
_BEARER = re.compile(r"Bearer\s+\S+", re.IGNORECASE)
_READY_TIMEOUT_SECONDS = 30.0
_STOP_TIMEOUT_SECONDS = 5.0


class _UsageError(Exception):
    """A config or validation problem. The process exits 2."""


class _StartedTarget:
    """A localhost uvicorn process started for one scan."""

    def __init__(self, process: subprocess.Popen[bytes], log_path: Path) -> None:
        self.process = process
        self.log_path = log_path

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

    def failure_text(self) -> str:
        try:
            text = self.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return "target app exited before it was ready"
        line = next((item.strip() for item in reversed(text.splitlines()) if item.strip()), "")
        if not line:
            return "target app exited before it was ready"
        return f"target app exited before it was ready: {line[:200]}"


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI.

    ``scan`` returns 0, 1, or 2. ``fix`` returns 0 when every approved finding
    is Verified, 1 when a check fails or is inconclusive, 2 on config or
    validation errors, and 3 when the user declines a patch.
    """
    parser = _parser()
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        code = exc.code
        return code if isinstance(code, int) else 2
    try:
        if args.command == "fix":
            from app.remediation.verifier import run_fix

            return run_fix(
                args.config,
                db_path=args.db,
                canned=bool(args.canned_patch),
                details=bool(args.details),
            )
        return _scan(
            args.config,
            start_server=not args.no_start,
            db_path=args.db,
            canned_patch=bool(getattr(args, "canned_patch", False)),
        )
    except _UsageError as exc:
        print(_redact(str(exc), ()), file=sys.stderr)
        return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.cli",
        description="Scan a local FastAPI app for broken object-level authorization.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    scan = subcommands.add_parser("scan", help="discover, test, and classify a local target")
    scan.add_argument("--config", required=True, help="path to a codeguard YAML file")
    scan.add_argument(
        "--no-start",
        action="store_true",
        help="use the server already listening on the configured localhost base_url",
    )
    scan.add_argument("--db", default=str(DEFAULT_DB_PATH), help="SQLite database path")
    scan.add_argument(
        "--canned-patch",
        action="store_true",
        help="propose a labeled CannedPatch owner check for the document fixtures; does not call the model",
    )
    fix = subcommands.add_parser("fix", help="propose a patch and verify it on a temporary copy")
    fix.add_argument("--config", required=True, help="path to a codeguard YAML file")
    fix.add_argument("--db", default=str(DEFAULT_DB_PATH), help="SQLite database path")
    fix.add_argument(
        "--canned-patch",
        action="store_true",
        help="use the labeled CannedPatch owner check; does not call the model",
    )
    fix.add_argument(
        "--details",
        action="store_true",
        help="print each request in the fix gate; the saved record always has them",
    )
    return parser


def _scan(config_path: str, *, start_server: bool, db_path: str, canned_patch: bool = False) -> int:
    config = _load_config(config_path)
    tokens = [user.token for user in config.users]
    _assert_localhost(config.base_url)
    source_dir = _source_directory(config, Path(config_path))
    routes = discover_routes(source_dir)
    route_findings = assess_routes(source_dir)
    provider = get_provider()
    try:
        plan = provider.plan_tests(route_findings, config.matrix(), routes=routes, config=config)
    except RuntimeError as exc:
        _print_model_run(provider.model_run(), tokens)
        raise _UsageError(_redact(str(exc), tokens)) from exc
    validated = validate_plan(plan, routes, config.matrix(), config)
    model_cases, model_tests, required_tests = supplement_plan(
        validated.accepted,
        route_findings,
        config.matrix(),
        config,
    )
    model_run = provider.model_run().with_counts(
        proposed=_proposed_count(plan),
        accepted=len(validated.accepted),
        rejected=len(validated.rejected),
    ).with_sources(model_tests=model_tests, required_tests=required_tests)
    if validated.rejected:
        detail = "; ".join(f"{item.id}: {', '.join(item.reasons)}" for item in validated.rejected)
        _print_model_run(model_run, tokens)
        raise _UsageError(_redact(f"validation error: {detail}", tokens))

    started: _StartedTarget | None = None
    try:
        if start_server:
            started = _start_target(config, source_dir, tokens)
        results = asyncio.run(execute_plan(model_cases, config))
        findings = classify(route_findings, results, config.matrix())
        FindingStore(db_path).save_scan(findings, results, model_run)
    except _UsageError:
        raise
    except ValueError as exc:
        raise _UsageError(_redact(str(exc), tokens)) from exc
    finally:
        if started is not None:
            started.stop()

    _print_report(findings, tokens, model_run)
    if canned_patch:
        _print_canned_patches(findings, route_findings, source_dir, config.matrix(), tokens)
    confirmed = sum(1 for finding in findings if finding.status == "Confirmed")
    return 1 if confirmed else 0


def _print_canned_patches(
    findings: Sequence[Finding],
    route_findings: Sequence[object],
    source_dir: Path,
    matrix: object,
    tokens: Sequence[str],
) -> None:
    from app.analyzer.auth_checks import RouteFinding
    from app.remediation.patcher import PatchRejected, propose_patch, route_for
    from app.schemas import AuthorizationMatrix

    if not isinstance(matrix, AuthorizationMatrix):
        raise _UsageError("canned patch: authorization matrix is missing")
    routes = [item for item in route_findings if isinstance(item, RouteFinding)]
    for finding in findings:
        if finding.status != "Confirmed":
            continue
        route = route_for(finding, routes)
        if route is None:
            raise _UsageError(f"canned patch: no handler for {finding.method} {finding.route}")
        try:
            proposal = propose_patch(
                finding,
                source_dir=source_dir,
                route_file=route.file,
                handler_source=route.source,
                line_numbers=route.line_numbers,
                matrix=matrix,
                canned=True,
            )
        except PatchRejected as exc:
            raise _UsageError(f"canned patch: {exc}") from exc
        print(
            _redact(
                "\n".join(
                    (
                        f"{proposal.status} [{proposal.root_cause.split(':', 1)[0]}]",
                        f"finding: {proposal.finding_id}",
                        f"file: {proposal.file}",
                        f"temp copy: {proposal.temp_copy_path}",
                        proposal.root_cause,
                    )
                ),
                tokens,
            )
        )


def _load_config(config_path: str) -> TargetConfig:
    try:
        return load_target_config(config_path)
    except ValidationError as exc:
        parts = [
            f"{'.'.join(str(item) for item in error.get('loc', ())) or 'config'}: {error.get('msg', 'invalid')}"
            for error in exc.errors()
        ]
        raise _UsageError("config error: " + "; ".join(parts)) from exc
    except FileNotFoundError as exc:
        raise _UsageError("config error: config file was not found") from exc
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise _UsageError("config error: invalid config") from exc


def _assert_localhost(base_url: str) -> None:
    parsed = urlsplit(base_url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "http" or host not in _ALLOWED_HOSTS or parsed.username or parsed.password:
        raise _UsageError("config error: base_url must be http://127.0.0.1 or http://localhost")


def _source_directory(config: TargetConfig, config_path: Path) -> Path:
    if not config.source_dir:
        raise _UsageError("config error: source_dir is required")
    raw = Path(config.source_dir)
    if raw.is_absolute():
        if raw.is_dir():
            return raw
        raise _UsageError("config error: source_dir is not a directory")
    candidates = [Path.cwd() / raw, config_path.parent / raw]
    if config_path.exists():
        candidates.extend(parent / raw for parent in config_path.resolve().parents)
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    raise _UsageError("config error: source_dir is not a directory")


def _start_target(config: TargetConfig, source_dir: Path, tokens: Sequence[str]) -> _StartedTarget:
    if not config.target_app:
        raise _UsageError("config error: target_app is required unless --no-start is set")
    parsed = urlsplit(config.base_url)
    host = (parsed.hostname or "").lower()
    if host not in _ALLOWED_HOSTS:
        raise _UsageError("config error: base_url must be http://127.0.0.1 or http://localhost")
    port = parsed.port or 8000
    log_path = Path(tempfile.gettempdir()) / f"codeguard-target-{port}.log"
    handle = log_path.open("wb")
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                config.target_app,
                "--host",
                host,
                "--port",
                str(port),
                "--log-level",
                "warning",
            ],
            cwd=_import_root(source_dir, config.target_app),
            stdin=subprocess.DEVNULL,
            stdout=handle,
            stderr=handle,
        )
    except OSError as exc:
        handle.close()
        log_path.unlink(missing_ok=True)
        raise _UsageError("target app failed to start") from exc
    handle.close()
    started = _StartedTarget(process, log_path)
    try:
        _wait_until_ready(config.base_url, started)
    except _UsageError:
        detail = _redact(started.failure_text(), tokens)
        started.stop()
        raise _UsageError(detail) from None
    except BaseException:
        started.stop()
        raise
    return started


def _import_root(source_dir: Path, target_app: str) -> Path:
    top = target_app.split(":", 1)[0].split(".", 1)[0]
    for candidate in (source_dir, *source_dir.resolve().parents):
        if (candidate / top / "__init__.py").is_file() or (candidate / f"{top}.py").is_file():
            return candidate
    return Path.cwd()


def _wait_until_ready(base_url: str, started: _StartedTarget) -> None:
    deadline = time.monotonic() + _READY_TIMEOUT_SECONDS
    probe = f"{base_url.rstrip('/')}/openapi.json"
    while time.monotonic() < deadline:
        if started.process.poll() is not None:
            raise _UsageError("target app exited before it was ready")
        try:
            response = httpx.get(probe, timeout=0.5, trust_env=False, follow_redirects=False)
        except httpx.HTTPError:
            time.sleep(0.2)
            continue
        if response.status_code == 200:
            return
        time.sleep(0.2)
    raise _UsageError("target app did not become ready")


def _evidence_lines(finding: Finding) -> list[str]:
    lines = [evidence_line(item) for item in finding.evidence] or ["-"]
    if finding.coverage_gaps:
        lines.append(f"Coverage gaps: {len(finding.coverage_gaps)}")
    return lines


def _print_report(findings: Sequence[Finding], tokens: Sequence[str], model_run: ModelRun) -> None:
    prepared = [
        (
            f"{finding.method} {finding.route}",
            finding.status,
            _clip(finding.reason, 70),
            _evidence_lines(finding),
        )
        for finding in findings
    ]
    print(_redact(_table(prepared), tokens))
    confirmed = sum(1 for finding in findings if finding.status == "Confirmed")
    print(_redact(f"{len(findings)} findings, {confirmed} confirmed", tokens))
    _print_model_run(model_run, tokens)


def _print_model_run(model_run: ModelRun, tokens: Sequence[str]) -> None:
    print(_redact(model_run.text(), tokens))


def _table(rows: Sequence[tuple[str, str, str, list[str]]]) -> str:
    headers = ("route", "status", "reason", "evidence")
    widths = [len(header) for header in headers]
    for route, status, reason, lines in rows:
        widths[0] = max(widths[0], len(route))
        widths[1] = max(widths[1], len(status))
        widths[2] = max(widths[2], len(reason))
        widths[3] = max(widths[3], len(lines[0]))

    def format_row(cells: Sequence[str]) -> str:
        return "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(cells)).rstrip()

    output = [format_row(headers), format_row(tuple("-" * width for width in widths))]
    if not rows:
        output.append("(no findings)")
        return "\n".join(output)
    indent = " " * (widths[0] + widths[1] + widths[2] + 6)
    for route, status, reason, lines in rows:
        output.append(format_row((route, status, reason, lines[0])))
        output.extend(f"{indent}{line}" for line in lines[1:])
    return "\n".join(output)


def _clip(text: str, limit: int) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


def _proposed_count(plan: object) -> int:
    cases = getattr(plan, "cases", None)
    if isinstance(plan, dict):
        cases = plan.get("cases")
    return len(cases) if isinstance(cases, list) else 0


def _redact(text: str, tokens: Sequence[str]) -> str:
    redacted = _BEARER.sub("Bearer [redacted]", text)
    for token in sorted({item for item in tokens if item}, key=len, reverse=True):
        redacted = redacted.replace(token, "[redacted]")
    return redacted


if __name__ == "__main__":
    raise SystemExit(main())
