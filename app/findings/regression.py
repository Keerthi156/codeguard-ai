"""Export a verified finding as a permanent localhost regression test.

The generated file is plain pytest. It reads the base URL and synthetic tokens
from the environment, and it refuses any URL that is not localhost.
"""

from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import yaml

from app.findings.classifier import Finding, git_revision
from app.findings.store import FindingStore
from app.schemas import OperationRules
from app.target_config import TargetConfig, load_target_config

_READY_TIMEOUT_SECONDS = 30.0
_STOP_TIMEOUT_SECONDS = 5.0
_PLACEHOLDER = re.compile(r"\{[^}]+\}")
_IDENTIFIER = re.compile(r"[^0-9A-Za-z]+")


class RegressionUsage(Exception):
    """A config problem. The regress command exits 2."""


@dataclass(frozen=True)
class _Case:
    name: str
    method: str
    path: str
    identity: str | None
    expected: str


def export_verified(
    finding: Finding,
    config: TargetConfig,
    *,
    root_cause: str,
    db_path: str | Path,
    output_dir: Path | None = None,
    when: datetime | None = None,
) -> Path | None:
    """Write one pytest file for a Verified finding. Other statuses write nothing."""
    if finding.status != "Verified":
        return None
    operation = _operation(config, finding.method, finding.route)
    rules = config.matrix().read if operation == "read" else config.matrix().write
    tokens = [user.token for user in config.users]
    cause = _redact(root_cause.strip() or finding.reason, tokens)
    policy = _policy(operation, rules)
    moment = when or datetime.now(timezone.utc)
    revision = finding.target_revision or git_revision() or ""
    directory = _output_dir(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / _file_name(finding.method, finding.route, operation)
    path.write_text(
        _render(finding, operation, cause, policy, revision, moment, config, rules),
        encoding="utf-8",
    )
    FindingStore(db_path).save_regression_test(
        finding_id=finding.id,
        method=finding.method.upper(),
        route=finding.route,
        operation=operation,
        file_path=str(path.resolve()),
        root_cause=cause,
        policy=policy,
        revision=revision,
        created_at=moment,
    )
    return path


def run_regress(
    config_path: str,
    *,
    source_dir: str | None = None,
    db_path: str | Path,
) -> int:
    """Start the target on localhost and run every saved regression test."""
    try:
        config = _load_config(config_path)
        directory = _resolve_source(config, config_path, source_dir)
        records = FindingStore(db_path).load_regression_tests()
        files = [Path(row["file_path"]) for row in records]
        missing = [path for path in files if not path.is_file()]
        if not records or missing:
            raise RegressionUsage("config error: no regression tests")
        if not config.target_app:
            raise RegressionUsage("config error: target_app is required")
    except RegressionUsage as exc:
        print(str(exc), file=sys.stderr)
        return 2
    process: subprocess.Popen[bytes] | None = None
    log_path: Path | None = None
    try:
        process, log_path, base_url = _start(config, directory)
        return _run_saved_tests(config, records, base_url)
    except RegressionUsage as exc:
        print(str(exc), file=sys.stderr)
        return 2
    finally:
        _stop(process, log_path)


def _output_dir(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit
    override = os.environ.get("CODEGUARD_REGRESSION_DIR", "").strip()
    if override:
        return Path(override)
    return Path("regression_tests")


def _operation(config: TargetConfig, method: str, route: str) -> str:
    for item in config.routes:
        if item.method.upper() == method.upper() and item.path == route:
            return item.operation
    return "read" if method.upper() in {"GET", "HEAD"} else "write"


def _policy(operation: str, rules: OperationRules) -> str:
    parts = [f"owner {rules.owner.expected}", f"non-owner {rules.non_owner.expected}"]
    if rules.unauthenticated is not None:
        parts.append(f"unauthenticated {rules.unauthenticated.expected}")
    return f"Policy assumption: {operation} access is " + ", ".join(parts) + "."


def _file_name(method: str, route: str, operation: str) -> str:
    slug = _PLACEHOLDER.sub(lambda match: match.group(0)[1:-1], route.strip("/"))
    slug = _IDENTIFIER.sub("_", slug).strip("_").lower() or "route"
    return f"{method.lower()}_{slug}_{operation}.py"


def _cases(finding: Finding, config: TargetConfig, rules: OperationRules) -> list[_Case]:
    owners = {resource.id: resource.owner for resource in config.resources}
    names = [user.name for user in config.users]
    cases: list[_Case] = []
    for resource in config.resources:
        owner = owners[resource.id]
        path = _PLACEHOLDER.sub(resource.id, finding.route)
        if rules.owner.expected == "allow" and owner in names:
            cases.append(_Case(_test_name("owner", owner, resource.id), finding.method, path, owner, "allow"))
        for name in names:
            if name == owner or rules.non_owner.expected != "deny":
                continue
            cases.append(
                _Case(_test_name("exploit_non_owner", name, resource.id), finding.method, path, name, "deny")
            )
        if rules.unauthenticated is not None and rules.unauthenticated.expected == "deny":
            cases.append(_Case(_test_name("exploit", None, resource.id), finding.method, path, None, "deny"))
    return cases


def _test_name(kind: str, identity: str | None, resource_id: str) -> str:
    who = "unauthenticated" if identity is None else _identifier(identity)
    return f"test_{kind}_{who}_{_identifier(resource_id)}"


def _identifier(value: str) -> str:
    cleaned = _IDENTIFIER.sub("_", value).strip("_").lower()
    return cleaned or "value"


def _render(
    finding: Finding,
    operation: str,
    root_cause: str,
    policy: str,
    revision: str,
    moment: datetime,
    config: TargetConfig,
    rules: OperationRules,
) -> str:
    cases = _cases(finding, config, rules)
    header = [
        "# Regression test for a verified authorization fix.",
        f"# Finding: {finding.id}",
        f"# Route: {finding.method.upper()} {finding.route}",
        f"# Operation: {operation}",
        f"# Date: {moment.date().isoformat()}",
        f"# Revision: {revision or 'unavailable'}",
        "# Root cause: " + " ".join(root_cause.split()),
        f"# {policy}",
        "# Tokens and the base URL come from the environment. This file has no keys.",
        "# Requests are refused unless the base URL is http://127.0.0.1 or http://localhost.",
        "",
    ]
    body = [
        "from __future__ import annotations",
        "",
        "import os",
        "from collections.abc import Iterator",
        "from urllib.parse import urlsplit",
        "",
        "import httpx",
        "import pytest",
        "",
        "_ALLOWED = {'127.0.0.1', 'localhost'}",
        "_WRITE = {'POST', 'PUT', 'PATCH'}",
        "_BODY = {'title': 'synthetic', 'content': 'synthetic'}",
        "",
        "",
        "def _base_url() -> str:",
        "    raw = os.environ.get('CODEGUARD_BASE_URL', '')",
        "    parsed = urlsplit(raw)",
        "    host = (parsed.hostname or '').lower()",
        "    if parsed.scheme != 'http' or host not in _ALLOWED or parsed.username or parsed.password:",
        "        pytest.fail('CODEGUARD_BASE_URL must be http://127.0.0.1 or http://localhost')",
        "    return raw.rstrip('/')",
        "",
        "",
        "def _token(name: str) -> str:",
        "    return os.environ[f'CODEGUARD_TOKEN_{name.upper()}']",
        "",
        "",
        "@pytest.fixture",
        "def client() -> Iterator[httpx.Client]:",
        "    with httpx.Client(",
        "        base_url=_base_url(),",
        "        trust_env=False,",
        "        timeout=5.0,",
        "        follow_redirects=False,",
        "    ) as http:",
        "        yield http",
        "",
        "",
        "def _request(http: httpx.Client, method: str, path: str, identity: str | None) -> httpx.Response:",
        "    headers = {} if identity is None else {'Authorization': f'Bearer {_token(identity)}'}",
        "    return http.request(method, path, headers=headers, json=_BODY if method.upper() in _WRITE else None)",
        "",
    ]
    for case in cases:
        identity = "None" if case.identity is None else repr(case.identity)
        body.extend(
            [
                "",
                f"def {case.name}(client: httpx.Client) -> None:",
                f"    response = _request(client, {case.method.upper()!r}, {case.path!r}, {identity})",
                _assertion(case.expected),
            ]
        )
    return "\n".join(header + body) + "\n"


def _assertion(expected: str) -> str:
    if expected == "allow":
        return (
            "    assert 200 <= response.status_code < 300, "
            "f'owner access was denied with status {response.status_code}'"
        )
    return (
        "    if 200 <= response.status_code < 300:\n"
        "        raise AssertionError(f'access was allowed with status {response.status_code}')\n"
        "    assert response.status_code in {401, 403, 404}, "
        "f'unexpected status {response.status_code}'"
    )


def _load_config(config_path: str) -> TargetConfig:
    try:
        return load_target_config(config_path)
    except FileNotFoundError as exc:
        raise RegressionUsage("config error: config file was not found") from exc
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise RegressionUsage("config error: invalid config") from exc


def _resolve_source(config: TargetConfig, config_path: str, source_dir: str | None) -> Path:
    raw = Path(source_dir) if source_dir else Path(config.source_dir or "")
    if not str(raw):
        raise RegressionUsage("config error: source_dir is required")
    if not raw.is_absolute():
        candidates = [Path.cwd() / raw, Path(config_path).resolve().parent / raw]
        raw = next((candidate for candidate in candidates if candidate.is_dir()), raw)
    if not raw.is_dir():
        raise RegressionUsage("config error: source_dir is not a directory")
    return raw


def _start(config: TargetConfig, source_dir: Path) -> tuple[subprocess.Popen[bytes], Path, str]:
    if not config.target_app:
        raise RegressionUsage("config error: target_app is required")
    target, cwd = _app_target(config.target_app, source_dir)
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    log_path = Path(tempfile.gettempdir()) / f"codeguard-regress-{port}.log"
    handle = log_path.open("wb")
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                target,
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
        raise RegressionUsage("target app failed to start") from exc
    handle.close()
    try:
        _wait_until_ready(base_url, process)
    except RegressionUsage:
        _stop(process, log_path)
        raise
    return process, log_path, base_url


def _app_target(target_app: str, source_dir: Path) -> tuple[str, Path]:
    module, _, attribute = target_app.partition(":")
    attribute = attribute or "app"
    top = module.split(".", 1)[0]
    for candidate in (source_dir, *source_dir.resolve().parents):
        if (candidate / top / "__init__.py").is_file() or (candidate / f"{top}.py").is_file():
            return target_app, candidate
    if (source_dir / "app.py").is_file():
        return f"app:{attribute}", source_dir
    raise RegressionUsage("config error: source_dir is not a directory")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_until_ready(base_url: str, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + _READY_TIMEOUT_SECONDS
    probe = f"{base_url}/openapi.json"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RegressionUsage("target app failed to start")
        try:
            response = httpx.get(probe, timeout=0.5, trust_env=False, follow_redirects=False)
        except httpx.HTTPError:
            time.sleep(0.2)
            continue
        if response.status_code == 200:
            return
        time.sleep(0.2)
    raise RegressionUsage("target app failed to start")


def _stop(process: subprocess.Popen[bytes] | None, log_path: Path | None) -> None:
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=_STOP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=_STOP_TIMEOUT_SECONDS)
    if log_path is None:
        return
    for _attempt in range(5):
        try:
            log_path.unlink(missing_ok=True)
            return
        except OSError:
            time.sleep(0.1)


def _run_saved_tests(config: TargetConfig, records: list[object], base_url: str) -> int:
    files = [Path(row["file_path"]) for row in records]
    directory = files[0].parent
    xml_path = Path(tempfile.gettempdir()) / f"codeguard-regress-{os.getpid()}.xml"
    child = os.environ.copy()
    child["CODEGUARD_BASE_URL"] = base_url
    for user in config.users:
        child[f"CODEGUARD_TOKEN_{user.name.upper()}"] = user.token
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            *[str(path) for path in files],
            "-q",
            "--tb=line",
            "--noconftest",
            f"--rootdir={directory}",
            f"--junitxml={xml_path}",
        ],
        cwd=directory,
        env=child,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    try:
        if not xml_path.is_file():
            raise RegressionUsage("config error: regression tests did not report a result")
        outcomes, regressions = _outcomes(xml_path, records)
    finally:
        xml_path.unlink(missing_ok=True)
    print(_table(outcomes))
    for route in regressions:
        print(f"REGRESSION: {route} is vulnerable again")
    if regressions or any(result == "fail" for _file, _route, result in outcomes):
        return 1
    if completed.returncode not in {0, 1}:
        raise RegressionUsage("config error: regression tests did not report a result")
    return 0


def _outcomes(xml_path: Path, records: list[object]) -> tuple[list[tuple[str, str, str]], list[str]]:
    by_file = {Path(row["file_path"]).name: f"{row['method']} {row['route']}" for row in records}
    failed: dict[str, bool] = {name: False for name in by_file}
    regressions: list[str] = []
    root = ET.parse(xml_path).getroot()
    for case in root.iter("testcase"):
        name = Path(case.get("file") or "").name
        if name not in by_file:
            classname = case.get("classname") or ""
            name = next((item for item in by_file if item.removesuffix(".py") in classname), "")
        if name not in by_file:
            continue
        failure = case.find("failure")
        error = case.find("error")
        if failure is None and error is None:
            continue
        failed[name] = True
        detail = ""
        if failure is not None:
            detail = f"{failure.get('message') or ''} {failure.text or ''}"
        if (case.get("name") or "").startswith("test_exploit_") and "access was allowed" in detail:
            route = by_file[name]
            if route not in regressions:
                regressions.append(route)
    rows = [(name, by_file[name], "fail" if failed[name] else "pass") for name in by_file]
    return rows, regressions


def _table(rows: list[tuple[str, str, str]]) -> str:
    headers = ("test file", "route", "result")
    rendered = [headers, *rows]
    widths = [max(len(row[index]) for row in rendered) for index in range(3)]

    def line(row: tuple[str, ...]) -> str:
        return "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)).rstrip()

    output = [line(headers), line(tuple("-" * width for width in widths))]
    output.extend(line(row) for row in rows)
    return "\n".join(output)


def _redact(text: str, tokens: list[str]) -> str:
    redacted = re.sub(r"Bearer\s+\S+", "Bearer [redacted]", text, flags=re.IGNORECASE)
    redacted = re.sub(r"\bsk-[A-Za-z0-9_-]{8,}\b", "[redacted]", redacted)
    for token in sorted({item for item in tokens if item}, key=len, reverse=True):
        redacted = redacted.replace(token, "[redacted]")
    return redacted
