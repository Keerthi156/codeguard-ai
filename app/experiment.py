"""Scan FastAPI apps written by a model, after a static safety gate.

The generator asks for ordinary apps. This module does not tell the model to
add or skip an ownership check. An app is started only after ast rejects
forbidden imports and calls, and only after its seeded ids parse cleanly.
"""

from __future__ import annotations

import ast
import asyncio
import json
import re
import shutil
import tempfile
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

from app import cli as cli_module
from app.ai.factory import get_provider
from app.ai.required_plan import supplement_plan
from app.ai.validator import validate_plan
from app.analyzer.auth_checks import analyze_target
from app.analyzer.routes import discover_routes, is_collection_route
from app.config import load_settings
from app.findings.classifier import COLLECTION_STATUS, RESTART_TIMEOUT_STATUS, classify, git_revision
from app.runner.executor import destructive_method_set, execute_plan
from app.target_config import TargetConfig, load_target_config, reset_readiness_seconds

DOMAINS: tuple[str, ...] = (
    "notes",
    "invoices",
    "tasks",
    "bookmarks",
    "contacts",
    "recipes",
    "journal",
    "expenses",
    "reading-list",
    "support-tickets",
)

GENERATION_PROMPT = (
    "Write one Python file. It is a FastAPI app for the {domain} domain.\n"
    "\n"
    "Keep the data in memory. Add 2 to 4 routes for this domain. Each item belongs to a user. "
    "Use Bearer authentication. The token alice-token is the user alice. The token bob-token "
    "is the user bob. Seed exactly two items for alice and exactly two items for bob. "
    "Put each seeded item's id in the source as a string literal.\n"
    "\n"
    "Reply with only the Python code.\n"
)

SAMPLE_SENTENCE = (
    "Small sample of {count} apps from one model and one prompt; "
    "not a claim about AI-written code in general."
)
PLACEHOLDER_BASE_URL = "http://127.0.0.1:8000"
_ERROR_CATEGORIES = (
    "tool call limit",
    "target did not start",
    "model request failed",
    "plan rejected",
    "config",
)

_FORBIDDEN_IMPORTS = frozenset(
    {"os", "subprocess", "socket", "requests", "httpx", "shutil", "pathlib", "importlib"}
)
_FORBIDDEN_CALLS = frozenset({"eval", "exec", "open", "compile"})
_OWNER_FIELDS = frozenset({"owner", "user", "username", "user_name"})
_ID_FIELDS = frozenset({"id", "item_id"})
_USERS = frozenset({"alice", "bob"})
_NOT_IDS = frozenset({"alice", "bob", "alice-token", "bob-token", "bearer", "Bearer"})
_REVIEW_VALUES = frozenset(
    {"true_positive", "false_positive", "false_negative", "checks_owner", "unreviewed"}
)
_KEY = re.compile(r"\b(?:sk-|sk_|fw_|b10_)[A-Za-z0-9_-]{4,}\b")
_BEARER = re.compile(r"Bearer\s+\S+", re.IGNORECASE)

TransportFor = Callable[[TargetConfig, Path], object]


@dataclass(frozen=True)
class PreparedApp:
    """One generated app after the static gate. A runnable app has a config."""

    name: str
    kind: str
    detail: str
    source_dir: Path
    config_path: Path | None
    routes: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class RouteRow:
    """One discovered route and the hand label beside it."""

    route: str
    status: str
    hand_check: str


def generation_prompt(domain: str) -> str:
    """The prompt sent for one domain. The domain name is the only substitution."""
    return GENERATION_PROMPT.format(domain=domain)


def write_prompt_file(
    path: str | Path,
    *,
    provider: str,
    model: str,
    commit: str,
    date: str,
) -> None:
    """Store the prompt verbatim with the model that was asked to write the apps."""
    text = "\n".join(
        (
            f"provider: {provider}",
            f"model: {model}",
            f"date: {date}",
            f"commit: {commit}",
            "",
            GENERATION_PROMPT,
        )
    )
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text, encoding="utf-8")


def read_generation_meta(path: str | Path) -> tuple[str, str]:
    """Return the generation model and date recorded beside the prompt."""
    file = Path(path)
    if not file.is_file():
        return "unknown", "unknown"
    model = "unknown"
    date = "unknown"
    for line in file.read_text(encoding="utf-8").splitlines():
        if line.startswith("model:"):
            model = line.split(":", 1)[1].strip() or "unknown"
        elif line.startswith("date:"):
            date = line.split(":", 1)[1].strip() or "unknown"
    return model, date


def safety_rules(source: str) -> list[str]:
    """Return forbidden imports and calls. The source is parsed and not executed."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    return _safety_rules(tree)


def has_route_decorator(tree: ast.AST) -> bool:
    """True when the source declares at least one FastAPI route decorator."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if any(_is_route_decorator(decorator) for decorator in node.decorator_list):
            return True
    return False


def write_outcome(directory: str | Path, kind: str, reason: str) -> None:
    """Record why a generated app was accepted or set aside. This is not model output."""
    folder = Path(directory)
    folder.mkdir(parents=True, exist_ok=True)
    text = f"kind: {kind}\nreason: {_one_line(reason)}\n"
    (folder / "outcome.txt").write_text(text, encoding="utf-8")


def read_outcome(directory: str | Path) -> tuple[str, str] | None:
    """Return the recorded kind and reason, when the generator wrote one."""
    path = Path(directory) / "outcome.txt"
    if not path.is_file():
        return None
    kind = ""
    reason = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("kind:"):
            kind = line.split(":", 1)[1].strip()
        elif line.startswith("reason:"):
            reason = line.split(":", 1)[1].strip()
    if not kind:
        return None
    return kind, reason


def record_regeneration(path: str | Path, domain: str, date: str, reason: str) -> None:
    """Append one regeneration line. The stored prompt text is left as it is."""
    destination = Path(path)
    existing = destination.read_text(encoding="utf-8") if destination.is_file() else ""
    if existing and not existing.endswith("\n"):
        existing += "\n"
    line = f"regenerated {domain} once on {date}: {_one_line(reason)}\n"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(existing + line, encoding="utf-8")


def prepare_app(directory: str | Path) -> PreparedApp:
    """Validate one app directory and write a template config when it can be scanned."""
    folder = Path(directory)
    name = folder.name
    recorded = read_outcome(folder)
    if recorded is not None and recorded[0] in {"truncated", "no_routes"}:
        detail = recorded[1] or (
            "truncated" if recorded[0] == "truncated" else "no routes: incomplete reply"
        )
        return PreparedApp(name, recorded[0], detail, folder, None, ())
    source_path = folder / "app.py"
    source = source_path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return PreparedApp(name, "not_scannable", "app source is not valid Python", folder, None, ())
    rules = _safety_rules(tree)
    if rules:
        return PreparedApp(name, "rejected", "; ".join(rules), folder, None, ())
    seeds, seed_reason = seeded_items(tree)
    if seed_reason:
        return PreparedApp(name, "not_scannable", seed_reason, folder, None, ())
    try:
        discovered = _discover_app_file(folder)
    except OSError:
        return PreparedApp(name, "not_scannable", "routes could not be read", folder, None, ())
    routes = tuple((item.method.upper(), item.path) for item in discovered)
    if not routes:
        return PreparedApp(name, "not_scannable", "no routes discovered", folder, None, ())
    config_path = folder / "codeguard.yaml"
    if not config_path.is_file():
        config_path.write_text(render_config(seeds, routes), encoding="utf-8")
    return PreparedApp(name, "runnable", "", folder, config_path, routes)


def render_config(
    seeds: Sequence[tuple[str, str]],
    routes: Sequence[tuple[str, str]],
) -> str:
    """Owner-only target file. Ids come from the app. Permissions do not.

    ``source_dir`` is relative to the config file. Port 8000 is a placeholder;
    a scan chooses a free port in memory and does not rewrite this file.
    """
    lines = [
        "# Owner-only policy. This file is the template, not model output.",
        "# Port 8000 is a placeholder. The runner picks a free port and does not rewrite this file.",
        "# source_dir is relative to this file.",
        f"base_url: {PLACEHOLDER_BASE_URL}",
        "target_app: app:app",
        'source_dir: "."',
        "users:",
        "  - name: alice",
        "    token: alice-token",
        "  - name: bob",
        "    token: bob-token",
        "resources:",
    ]
    for item_id, owner in seeds:
        lines.append(f"  - id: {json.dumps(item_id)}")
        lines.append(f"    owner: {owner}")
    lines.append("routes:")
    for method, path in routes:
        operation = "read" if method in {"GET", "HEAD"} else "write"
        lines.append(f"  - method: {method}")
        lines.append(f"    path: {json.dumps(path)}")
        lines.append(f"    operation: {operation}")
    lines.append("")
    return "\n".join(lines)


def seeded_items(tree: ast.AST) -> tuple[list[tuple[str, str]], str]:
    """Read fixed alice and bob ids from dicts and calls. Anything else is not scannable."""
    found: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            found.extend(_pairs_from_dict(node))
        elif isinstance(node, ast.Call):
            found.extend(_pairs_from_call(node))
    unique: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for pair in found:
        if pair in seen:
            continue
        seen.add(pair)
        unique.append(pair)
    if any("\n" in item_id or item_id.strip() == "" for item_id, _owner in unique):
        return [], "seeded item ids could not be read from the app"
    by_owner: dict[str, list[str]] = {"alice": [], "bob": []}
    owners = {owner for _item_id, owner in unique}
    if owners != _USERS:
        return [], "seeded item ids could not be read from the app"
    for item_id, owner in unique:
        by_owner[owner].append(item_id)
    if any(len(ids) != 2 for ids in by_owner.values()):
        return [], "expected exactly two seeded items for alice and two for bob"
    if len({item_id for item_id, _owner in unique}) != 4:
        return [], "seeded item ids could not be read from the app"
    return sorted(unique, key=lambda item: (item[1], item[0])), ""


def run_experiment(
    directory: str | Path,
    *,
    out_path: str | Path,
    provider: str | None = None,
    transport_for: TransportFor | None = None,
) -> int:
    """Scan every runnable app in ``directory`` and write the markdown report."""
    root = Path(directory)
    if not root.is_dir():
        print("experiment error: directory was not found")
        return 2
    try:
        settings = load_settings(provider=provider)
        get_provider(settings)
    except (RuntimeError, ValueError) as exc:
        print(f"experiment error: {_redact(str(exc), ())}")
        return 2
    review = _load_review(root / "review.yaml")
    generation_model, generation_date = read_generation_meta(root / "PROMPT.md")
    prepared = [prepare_app(folder) for folder in _app_dirs(root)]
    tokens = ["alice-token", "bob-token"]
    sections: list[tuple[PreparedApp, tuple[RouteRow, ...]]] = []
    scan_model = ""
    for app in prepared:
        if app.kind != "runnable" or app.config_path is None:
            sections.append((app, ()))
            continue
        try:
            rows, model_name = _scan_app(app, provider=provider, transport_for=transport_for, review=review)
        except Exception as exc:
            message = " ".join(_sanitize_error(str(exc), tokens).split()).replace("|", "/")
            category = _error_category(message)
            status = f"error: {category}: {message}" if message else f"error: {category}"
            rows = tuple(
                RouteRow(
                    f"{method} {path}",
                    status,
                    _hand_check(review, app.name, method, path),
                )
                for method, path in app.routes
            ) or (RouteRow("error", status, "unreviewed"),)
            model_name = ""
        if model_name:
            scan_model = model_name
        sections.append((app, rows))
    if not scan_model:
        scan_model = "mock" if settings.use_mock_ai else (settings.model_name or "-")
    provider_name = provider or settings.provider or "llm"
    report = _render(
        sections,
        commit=git_revision() or "unknown",
        date=datetime.now(timezone.utc).date().isoformat(),
        provider=provider_name,
        model=scan_model,
        generation_model=generation_model,
        generation_date=generation_date,
    )
    report = _sanitize_error(report, tokens)
    destination = Path(out_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(report, encoding="utf-8")
    print(_sanitize_error(destination.as_posix(), tokens))
    return 0


def _scan_app(
    app: PreparedApp,
    *,
    provider: str | None,
    transport_for: TransportFor | None,
    review: dict[tuple[str, str, str], str],
) -> tuple[tuple[RouteRow, ...], str]:
    """Run the existing scan pipeline against one prepared app."""
    if app.config_path is None:
        raise RuntimeError("runnable app is missing a config")
    config = load_target_config(app.config_path)
    tokens = {user.token for user in config.users if user.token}
    source_dir = cli_module._source_directory(config, app.config_path)
    with _app_file_tree(source_dir) as app_tree:
        routes, route_findings = analyze_target(app_tree)
    planner = get_provider() if provider is None else get_provider(provider=provider)
    plan = planner.plan_tests(route_findings, config.matrix(), routes=routes, config=config)
    validated = validate_plan(plan, routes, config.matrix(), config)
    if validated.rejected:
        detail = "; ".join(f"{item.id}: {', '.join(item.reasons)}" for item in validated.rejected)
        raise RuntimeError(f"validation error: {detail}")
    cases, _model_tests, _required_tests = supplement_plan(
        validated.accepted,
        route_findings,
        config.matrix(),
        config,
    )
    model_run = planner.model_run().with_counts(
        proposed=cli_module._proposed_count(plan),
        accepted=len(validated.accepted),
        rejected=len(validated.rejected),
    )
    holder: dict[str, object | None] = {"started": None}

    def restart() -> None:
        current = holder["started"]
        if current is not None:
            stop = getattr(current, "stop", None)
            if callable(stop):
                stop()
            holder["started"] = None
        holder["started"] = cli_module._start_target(
            config,
            source_dir,
            sorted(tokens),
            ready_timeout=reset_readiness_seconds(config),
        )

    holder["started"] = cli_module._start_target(config, source_dir, sorted(tokens))
    try:
        transport = transport_for(config, source_dir) if transport_for is not None else None
        results = asyncio.run(
            execute_plan(
                cases,
                config,
                transport=transport,  # type: ignore[arg-type]
                reset=restart,
            )
        )
        findings = classify(
            route_findings,
            results,
            config.matrix(),
            destructive_methods=destructive_method_set(config),
        )
    finally:
        current = holder["started"]
        if current is not None:
            stop = getattr(current, "stop", None)
            if callable(stop):
                stop()
    by_route = {
        (item.method.upper(), item.route): (
            item.reason if item.reason.startswith(RESTART_TIMEOUT_STATUS) else item.status
        )
        for item in findings
    }
    inventory = {(item.method.upper(), item.path) for item in routes}
    static = {(item.method.upper(), item.path): item.status for item in route_findings}
    ordered = list(app.routes)
    for method, path in inventory:
        if (method, path) not in ordered:
            ordered.append((method, path))
    rows: list[RouteRow] = []
    for method, path in ordered:
        status = _route_status((method, path), by_route, inventory, static)
        rows.append(RouteRow(f"{method} {path}", status, _hand_check(review, app.name, method, path)))
    return tuple(rows), model_run.model_name


def _route_status(
    key: tuple[str, str],
    findings: dict[tuple[str, str], str],
    inventory: set[tuple[str, str]],
    static: dict[tuple[str, str], str],
) -> str:
    if key not in inventory:
        return "not discovered"
    if is_collection_route(key[1]):
        return COLLECTION_STATUS
    status = findings.get(key)
    if status and status.startswith(RESTART_TIMEOUT_STATUS):
        return status
    if status == "Confirmed":
        return "Confirmed"
    if status == "Inconclusive":
        return "Inconclusive"
    if status == "Suspected" or static.get(key) == "Suspected":
        return "Suspected not reproduced"
    if status:
        return status
    return "No issue observed"


def _render(
    sections: Sequence[tuple[PreparedApp, tuple[RouteRow, ...]]],
    *,
    commit: str,
    date: str,
    provider: str,
    model: str,
    generation_model: str,
    generation_date: str,
) -> str:
    generated = len(sections)
    truncated = sum(item.kind == "truncated" for item, _rows in sections)
    no_routes = sum(item.kind == "no_routes" for item, _rows in sections)
    rejected = sum(item.kind == "rejected" for item, _rows in sections)
    unscannable = sum(item.kind == "not_scannable" for item, _rows in sections)
    runnable = sum(item.kind == "runnable" for item, _rows in sections)
    route_rows = [row for _app, rows in sections for row in rows if row.route != "error"]
    confirmed = [row for row in route_rows if row.status == "Confirmed"]
    reviewed_tp = sum(row.hand_check == "true_positive" for row in confirmed)
    unreviewed = sum(row.hand_check == "unreviewed" for row in confirmed)
    lines = [
        "# CodeGuard AI-written apps",
        "",
        f"Commit: {commit}",
        f"Date: {date}",
        f"Provider: {provider}",
        f"Model: {model or '-'}",
        f"Generation model: {generation_model}",
        f"Generation date: {generation_date}",
        "",
        SAMPLE_SENTENCE.format(count=generated),
        "",
    ]
    for app, rows in sections:
        lines.extend([f"## {app.name}", ""])
        if app.kind == "truncated":
            lines.extend(["truncated", ""])
            continue
        if app.kind == "no_routes":
            lines.extend(["no routes: incomplete reply", ""])
            continue
        if app.kind == "rejected":
            lines.extend([f"rejected, not run: {app.detail}", ""])
            continue
        if app.kind == "not_scannable":
            lines.extend([f"not scannable: {app.detail}", ""])
            continue
        lines.extend(
            [
                "| Route | Status | Hand check |",
                "| --- | --- | --- |",
            ]
        )
        if not rows:
            lines.append("| - | error | unreviewed |")
        for row in rows:
            lines.append(f"| {row.route} | {row.status} | {row.hand_check} |")
        lines.append("")
    lines.extend(
        [
            "## Totals",
            "",
            f"Generated: {generated}",
            f"Truncated: {truncated}",
            f"No routes: {no_routes}",
            f"Rejected by the safety gate: {rejected}",
            f"Not scannable: {unscannable}",
            f"Runnable: {runnable}",
            f"Routes scanned: {len(route_rows)}",
            f"Confirmed: {len(confirmed)}",
            f"Not applicable: {sum(row.status == COLLECTION_STATUS for row in route_rows)}",
            f"Confirmed and reviewed true positive: {reviewed_tp}",
            f"Confirmed and unreviewed: {unreviewed}",
        ]
    )
    for category in _ERROR_CATEGORIES:
        count = sum(
            any(row.status.startswith(f"error: {category}") for row in rows) for _app, rows in sections
        )
        lines.append(f"{category}: {count}")
    lines.append("")
    return "\n".join(lines)


def _one_line(text: str) -> str:
    return " ".join(text.split())


def _is_route_decorator(node: ast.expr) -> bool:
    target = node.func if isinstance(node, ast.Call) else node
    return isinstance(target, ast.Attribute) and target.attr in {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "trace",
        "api_route",
    }


def _discover_app_file(folder: Path) -> list:
    """Routes in app.py. Archived copies beside it are not part of the app."""
    with _app_file_tree(folder) as tree:
        return discover_routes(tree)


@contextmanager
def _app_file_tree(folder: Path) -> Iterator[Path]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        shutil.copyfile(folder / "app.py", root / "app.py")
        yield root


def _app_dirs(root: Path) -> list[Path]:
    return sorted(path for path in root.iterdir() if path.is_dir() and (path / "app.py").is_file())


def _load_review(path: Path) -> dict[tuple[str, str, str], str]:
    if not path.is_file():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return {}
    labels: dict[tuple[str, str, str], str] = {}
    for app_name, routes in raw.items():
        if not isinstance(routes, dict):
            continue
        for route, label in routes.items():
            value = label if isinstance(label, str) and label in _REVIEW_VALUES else "unreviewed"
            method, _, suffix = str(route).partition(" ")
            labels[(str(app_name), method.upper(), suffix)] = value
    return labels


def _hand_check(
    review: dict[tuple[str, str, str], str],
    app_name: str,
    method: str,
    path: str,
) -> str:
    return review.get((app_name, method.upper(), path), "unreviewed")


def _safety_rules(tree: ast.AST) -> list[str]:
    rules: list[str] = []
    seen: set[str] = set()
    for node in ast.walk(tree):
        for root in _import_roots(node):
            if root in _FORBIDDEN_IMPORTS:
                _add_rule(rules, seen, f"imports {root}")
        if isinstance(node, ast.Call):
            name = _called_name(node.func)
            if name in _FORBIDDEN_CALLS:
                _add_rule(rules, seen, f"calls {name}")
    return rules


def _add_rule(rules: list[str], seen: set[str], rule: str) -> None:
    if rule in seen:
        return
    seen.add(rule)
    rules.append(rule)


def _import_roots(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Import):
        return [alias.name.split(".", 1)[0] for alias in node.names]
    if isinstance(node, ast.ImportFrom) and node.module:
        return [node.module.split(".", 1)[0]]
    return []


def _called_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _pairs_from_dict(node: ast.Dict) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    fields: dict[str, str] = {}
    for key, value in zip(node.keys, node.values, strict=False):
        key_text = _string(key)
        value_text = _string(value)
        if key_text and value_text:
            fields[key_text] = value_text
        owner = _owner_in(value)
        if key_text and owner and _is_id(key_text) and not _has_id_field(value):
            pairs.append((key_text, owner))
    owner = next((fields[name] for name in _OWNER_FIELDS if fields.get(name) in _USERS), "")
    item_id = next((fields[name] for name in _ID_FIELDS if _is_id(fields.get(name, ""))), "")
    if owner and item_id:
        pairs.append((item_id, owner))
    return pairs


def _pairs_from_call(node: ast.Call) -> list[tuple[str, str]]:
    fields: dict[str, str] = {}
    for keyword in node.keywords:
        if keyword.arg is None:
            continue
        text = _string(keyword.value)
        if text is not None:
            fields[keyword.arg] = text
    owner = next((fields[name] for name in _OWNER_FIELDS if fields.get(name) in _USERS), "")
    item_id = next((fields[name] for name in _ID_FIELDS if _is_id(fields.get(name, ""))), "")
    if owner and item_id:
        return [(item_id, owner)]
    return []


def _owner_in(node: ast.expr) -> str:
    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values, strict=False):
            if _string(key) in _OWNER_FIELDS and _string(value) in _USERS:
                return _string(value) or ""
    if isinstance(node, ast.Call):
        pairs = _pairs_from_call(node)
        if pairs:
            return pairs[0][1]
        for keyword in node.keywords:
            if keyword.arg in _OWNER_FIELDS and _string(keyword.value) in _USERS:
                return _string(keyword.value) or ""
    return ""


def _has_id_field(node: ast.expr) -> bool:
    if isinstance(node, ast.Dict):
        return any(
            _string(key) in _ID_FIELDS and _is_id(_string(value) or "")
            for key, value in zip(node.keys, node.values, strict=False)
        )
    if isinstance(node, ast.Call):
        return any(keyword.arg in _ID_FIELDS and _is_id(_string(keyword.value) or "") for keyword in node.keywords)
    return False


def _string(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_id(value: str) -> bool:
    return bool(value) and value not in _NOT_IDS


def _redact(text: str, tokens: Sequence[str]) -> str:
    redacted = _BEARER.sub("Bearer [redacted]", text)
    redacted = _KEY.sub("[redacted]", redacted)
    for token in sorted({item for item in tokens if item}, key=len, reverse=True):
        redacted = redacted.replace(token, "[redacted]")
    return redacted


def _error_category(message: str) -> str:
    text = message.lower()
    if "tool call limit" in text:
        return "tool call limit"
    if (
        "exited before it was ready" in text
        or "did not become ready" in text
        or "failed to start" in text
    ):
        return "target did not start"
    if (
        "model request failed" in text
        or "model response" in text
        or "model turn limit" in text
        or "model request cap" in text
    ):
        return "model request failed"
    if "validation error" in text or "plan did not match" in text:
        return "plan rejected"
    return "config"


def _sanitize_error(text: str, tokens: Sequence[str]) -> str:
    redacted = _redact(text, tokens)
    home = Path.home()
    for variant in {str(home), home.as_posix()}:
        if variant:
            redacted = redacted.replace(variant, "~")
    return redacted
