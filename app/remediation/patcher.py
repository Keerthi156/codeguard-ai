"""Propose a minimal authorization fix and apply it only to a temporary copy.

The model submits exact text edits. This module applies them, generates the
unified diff itself, and checks that diff before writing anything. The original
source directory is never modified.
"""

from __future__ import annotations

import ast
import difflib
import json
import logging
import re
import shutil
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict

from app.analyzer.auth_checks import RouteFinding
from app.config import Settings, load_settings
from app.findings.classifier import Finding
from app.schemas import AuthorizationMatrix, OperationRules

logger = logging.getLogger(__name__)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

_MAX_CHANGED_LINES = 40
_TIMEOUT_SECONDS = 60.0
_MAX_TOKENS = 4000
_FENCE = re.compile(r"^```[a-zA-Z0-9]*\s*|\s*```$", re.MULTILINE)
_HUNK = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_PATCH_KEYS = frozenset({"file", "edits", "root_cause", "side_effects"})
_EDIT_KEYS = frozenset({"old", "new"})
_BANNED_IMPORTS = frozenset({"os", "subprocess", "socket", "requests", "httpx"})
_BANNED_CALLS = frozenset({"eval", "exec", "open"})
_CANNED_LABEL = "CannedPatch (tests and --canned-patch only)"
_CANNED_ROUTE = "/documents/{id}"


class PatchRejected(Exception):
    """The proposed edit failed a safety check and was not written."""


class _NotJson(PatchRejected):
    """The model reply was not valid JSON. One immediate retry is allowed."""


class PatchProposal(BaseModel):
    """A fix written only under a temporary copy of the source directory."""

    __test__ = False
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    file: str
    diff: str
    root_cause: str
    side_effects: str
    temp_copy_path: str
    status: Literal["Fix proposed"] = "Fix proposed"


class CannedPatch:
    """Deterministic owner check for the document fixtures.

    This is not a model-written fix. It is used by tests and when the scan is
    run with --canned-patch.
    """

    label = _CANNED_LABEL

    def fields(
        self,
        finding: Finding,
        source: str,
        relative: str,
        line_numbers: Sequence[int],
    ) -> dict[str, object]:
        """Build the JSON fields for one document handler."""
        if finding.route != _CANNED_ROUTE or finding.method.upper() not in {"GET", "PUT"}:
            raise PatchRejected(f"{_CANNED_LABEL} only covers GET and PUT {_CANNED_ROUTE}")
        if not line_numbers:
            raise PatchRejected(f"{_CANNED_LABEL} needs the handler line numbers")
        patched = _rewrite_document_handler(source, finding.method, line_numbers)
        return {
            "file": relative,
            "edits": [{"old": source, "new": patched}],
            "root_cause": (
                f"{_CANNED_LABEL}: the handler returns the document without comparing "
                "the caller to the resource owner."
            ),
            "side_effects": (
                f"{_CANNED_LABEL}: a non-owner receives 404. The original tree is not modified."
            ),
        }


def materialize(source_dir: str | Path, patches: Sequence[tuple[str, str]]) -> Path:
    """Copy ``source_dir`` and apply diffs there. The original directory is not modified.

    Diffs for one file are applied from the bottom of the file upward so an
    earlier hunk still matches after a later one has been applied.
    """
    root = Path(source_dir)
    destination = _copy_tree(root)
    try:
        grouped: dict[str, list[str]] = {}
        for relative, diff in patches:
            grouped.setdefault(_clean_relative(relative), []).append(diff)
        for relative, diffs in grouped.items():
            text = (destination / relative).read_text(encoding="utf-8")
            ordered = sorted(diffs, key=lambda item: _first_hunk(item, relative), reverse=True)
            for diff in ordered:
                text = _checked_text(text, diff, relative)
            (destination / relative).write_text(text, encoding="utf-8")
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    return destination


def _first_hunk(diff: str, relative: str) -> int:
    hunks, _changed = _parse_diff(diff, relative)
    return hunks[0][0]


def propose_patch(
    finding: Finding,
    *,
    source_dir: str | Path,
    route_file: str,
    handler_source: str,
    line_numbers: Sequence[int],
    matrix: AuthorizationMatrix,
    settings: Settings | None = None,
    transport: httpx.BaseTransport | None = None,
    canned: bool = False,
    feedback: str | None = None,
) -> PatchProposal:
    """Ask for one fix, validate it, and write it under a new temporary directory."""
    if finding.status != "Confirmed":
        raise PatchRejected("only a Confirmed finding can be patched")
    root = Path(source_dir)
    relative = _confirmed_file(root, route_file)
    original = (root / relative).read_text(encoding="utf-8")
    if canned:
        payload = CannedPatch().fields(finding, original, relative, line_numbers)
    else:
        active = settings if settings is not None else load_settings()
        payload = _ask_model(
            active,
            transport,
            finding,
            relative,
            handler_source,
            line_numbers,
            matrix,
            feedback,
        )
    return _validate_and_apply(finding.id, root, relative, original, payload)


def _ask_model(
    settings: Settings,
    transport: httpx.BaseTransport | None,
    finding: Finding,
    relative: str,
    handler_source: str,
    line_numbers: Sequence[int],
    matrix: AuthorizationMatrix,
    feedback: str | None = None,
) -> dict[str, object]:
    missing = [
        name
        for name, value in (
            ("MODEL_API_KEY", settings.model_api_key),
            ("MODEL_NAME", settings.model_name),
            ("MODEL_BASE_URL", settings.model_base_url),
        )
        if not value.strip()
    ]
    if missing:
        raise RuntimeError("model settings are missing: " + ", ".join(missing))
    url = f"{settings.model_base_url.rstrip('/')}/chat/completions"
    headers = {"Authorization": f"Bearer {settings.model_api_key}"}
    note = feedback
    last_error = _NotJson("model fix was not JSON")
    for parse_try in range(2):
        body = {
            "model": settings.model_name,
            "messages": [
                {"role": "system", "content": _system_prompt()},
                {
                    "role": "user",
                    "content": json.dumps(
                        _request_view(finding, relative, handler_source, line_numbers, matrix, note),
                        sort_keys=True,
                    ),
                },
            ],
            "max_tokens": _MAX_TOKENS,
            "tools": [_patch_tool()],
            "tool_choice": "auto",
        }
        try:
            with httpx.Client(transport=transport, timeout=_TIMEOUT_SECONDS, trust_env=False) as client:
                response = client.post(url, headers=headers, json=body, follow_redirects=False)
        except httpx.HTTPError:
            raise RuntimeError("model request failed") from None
        if response.status_code != 200:
            raise RuntimeError(f"model request failed with status {response.status_code}")
        try:
            payload = response.json()
        except json.JSONDecodeError as exc:
            last_error = _NotJson(f"model fix was not JSON: {exc.msg}")
        else:
            try:
                return _patch_payload(payload, settings.model_api_key)
            except _NotJson as exc:
                last_error = exc
        if parse_try == 1:
            raise last_error
        note = _with_parse_error(feedback, str(last_error))
    raise last_error


def _validate_and_apply(
    finding_id: str,
    source_dir: Path,
    relative: str,
    original: str,
    payload: dict[str, object],
) -> PatchProposal:
    file_value = payload["file"]
    if not isinstance(file_value, str):
        raise PatchRejected("file is not the confirmed route file")
    file_name = _clean_relative(file_value)
    if file_name != relative:
        raise PatchRejected("file is not the confirmed route file")
    patched = _apply_edits(original, _edit_pairs(payload["edits"]))
    diff = _unified(original, patched, relative)
    checked = _checked_text(original, diff, relative)
    destination = _copy_tree(source_dir)
    (destination / relative).write_text(checked, encoding="utf-8")
    root_cause = payload["root_cause"]
    side_effects = payload["side_effects"]
    if not isinstance(root_cause, str) or not isinstance(side_effects, str):
        raise PatchRejected("model fix fields must be non-empty strings")
    return PatchProposal(
        finding_id=finding_id,
        file=relative,
        diff=diff,
        root_cause=root_cause,
        side_effects=side_effects,
        temp_copy_path=str(destination),
        status="Fix proposed",
    )


def _apply_edits(original: str, edits: Sequence[tuple[str, str]]) -> str:
    """Replace each snippet once. ``old`` must occur exactly once in the current text."""
    text = original
    for old, new in edits:
        found = text.count(old)
        if found == 0:
            raise PatchRejected("old text not found")
        if found > 1:
            raise PatchRejected("old text matched more than once")
        text = text.replace(old, new, 1)
    return text


def _edit_pairs(value: object) -> list[tuple[str, str]]:
    if not isinstance(value, list) or not value:
        raise PatchRejected("model fix has unexpected fields")
    pairs: list[tuple[str, str]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != _EDIT_KEYS:
            raise PatchRejected("model fix has unexpected fields")
        old = item["old"]
        new = item["new"]
        if not isinstance(old, str) or not isinstance(new, str) or not old:
            raise PatchRejected("model fix fields must be non-empty strings")
        pairs.append((old, new))
    return pairs


def _checked_text(original: str, diff: str, relative: str) -> str:
    hunks, changed = _parse_diff(diff, relative)
    if changed > _MAX_CHANGED_LINES:
        raise PatchRejected(f"diff changes more than {_MAX_CHANGED_LINES} lines")
    patched = _apply(original, hunks)
    try:
        original_tree = ast.parse(original)
        patched_tree = ast.parse(patched)
    except SyntaxError:
        raise PatchRejected("patched file does not parse") from None
    added = _import_roots(patched_tree) - _import_roots(original_tree)
    forbidden = added & _BANNED_IMPORTS
    if forbidden:
        name = sorted(forbidden)[0]
        raise PatchRejected(f"diff adds a forbidden import: {name}")
    before = _call_counts(original_tree)
    after = _call_counts(patched_tree)
    for name in _BANNED_CALLS:
        if after[name] > before[name]:
            raise PatchRejected(f"diff adds a call to {name}")
    return patched


def _parse_diff(diff: str, expected: str) -> tuple[list[tuple[int, list[tuple[str, str]]]], int]:
    if not diff.strip():
        raise PatchRejected("diff is not a valid unified diff")
    lines = diff.splitlines(keepends=True)
    index = 0
    hunks: list[tuple[int, list[tuple[str, str]]]] = []
    changed = 0
    saw_file = False
    while index < len(lines):
        line = lines[index]
        if line.startswith(("diff ", "index ", "new file", "deleted file", "similarity ", "rename ", "\\")):
            index += 1
            continue
        if line.startswith("--- "):
            old_path = _diff_path(line)
            index += 1
            if index >= len(lines) or not lines[index].startswith("+++ "):
                raise PatchRejected("diff is not a valid unified diff")
            new_path = _diff_path(lines[index])
            if old_path != expected or new_path != expected:
                raise PatchRejected("diff touches another file")
            saw_file = True
            index += 1
            continue
        if line.startswith("@@"):
            if not saw_file:
                raise PatchRejected("diff is not a valid unified diff")
            match = _HUNK.match(line.rstrip("\r\n"))
            if match is None:
                raise PatchRejected("diff is not a valid unified diff")
            body: list[tuple[str, str]] = []
            index += 1
            while index < len(lines) and not lines[index].startswith(("@@", "--- ", "diff ")):
                item = lines[index]
                if item.startswith("\\"):
                    index += 1
                    continue
                if not item or item[0] not in " +-":
                    raise PatchRejected("diff is not a valid unified diff")
                if item[0] in "+-":
                    changed += 1
                body.append((item[0], item[1:]))
                index += 1
            hunks.append((int(match.group(1)), body))
            continue
        raise PatchRejected("diff is not a valid unified diff")
    if not saw_file or not hunks:
        raise PatchRejected("diff is not a valid unified diff")
    return hunks, changed


def _apply(original: str, hunks: Sequence[tuple[int, Sequence[tuple[str, str]]]]) -> str:
    source = original.splitlines(keepends=True)
    output: list[str] = []
    cursor = 0
    for old_start, body in hunks:
        target = max(old_start, 1) - 1
        if target < cursor or target > len(source):
            raise PatchRejected("diff is not a valid unified diff")
        output.extend(source[cursor:target])
        cursor = target
        for kind, text in body:
            if kind in {" ", "-"}:
                if cursor >= len(source) or not _same_line(source[cursor], text):
                    raise PatchRejected("diff is not a valid unified diff")
                if kind == " ":
                    output.append(source[cursor])
                cursor += 1
                continue
            output.append(text if text.endswith(("\n", "\r\n")) else text + "\n")
    output.extend(source[cursor:])
    return "".join(output)


def _confirmed_file(source_dir: Path, route_file: str) -> str:
    relative = _clean_relative(route_file)
    root = source_dir.resolve()
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root) or not candidate.is_file():
        raise PatchRejected("file is outside the source directory")
    return relative


def _copy_tree(source_dir: Path) -> Path:
    destination = Path(tempfile.mkdtemp(prefix="codeguard-patch-"))
    shutil.copytree(
        source_dir,
        destination,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    return destination


def _rewrite_document_handler(source: str, method: str, line_numbers: Sequence[int]) -> str:
    lines = source.splitlines(keepends=True)
    start, end = _handler_span(source, line_numbers)
    if start < 1 or end > len(lines) or start > end:
        raise PatchRejected(f"{_CANNED_LABEL} line numbers are outside the file")
    chunk = "".join(lines[start - 1 : end])
    rewritten = _owner_check(chunk, method)
    if rewritten == chunk:
        raise PatchRejected(f"{_CANNED_LABEL} did not match the document fixture handler")
    return "".join(lines[: start - 1]) + rewritten + "".join(lines[end:])


def _handler_span(source: str, line_numbers: Sequence[int]) -> tuple[int, int]:
    """Line range of the handler, ignoring helper lines that share the signal set."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        raise PatchRejected(f"{_CANNED_LABEL} line numbers are outside the file") from None
    numbers = set(line_numbers)
    chosen: tuple[int, int] | None = None
    overlap = 0
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.end_lineno is None:
            continue
        shared = len(set(range(node.lineno, node.end_lineno + 1)) & numbers)
        if shared > overlap:
            overlap = shared
            chosen = (node.lineno, node.end_lineno)
    if chosen is None or overlap == 0:
        if not line_numbers:
            raise PatchRejected(f"{_CANNED_LABEL} needs the handler line numbers")
        return min(line_numbers), max(line_numbers)
    return chosen


def _owner_check(chunk: str, method: str) -> str:
    newline = "\r\n" if "\r\n" in chunk else "\n"
    text = chunk.replace("_user", "user", 1)
    check = (
        f"    if document.owner != user:{newline}"
        f"        raise HTTPException(status_code=404, detail=\"Document not found\"){newline}"
    )
    if method.upper() == "GET":
        old = f"    return _existing_document(id){newline}"
        new = f"    document = _existing_document(id){newline}{check}    return document{newline}"
    elif method.upper() == "PUT":
        old = f"    document = _existing_document(id){newline}"
        new = f"{old}{check}"
    else:
        raise PatchRejected(f"{_CANNED_LABEL} only covers GET and PUT {_CANNED_ROUTE}")
    if old not in text:
        raise PatchRejected(f"{_CANNED_LABEL} did not match the document fixture handler")
    return text.replace(old, new, 1)


def _unified(original: str, patched: str, relative: str) -> str:
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=f"a/{relative}",
            tofile=f"b/{relative}",
        )
    )


def _patch_payload(payload: object, key: str) -> dict[str, object]:
    """Read the edit object. Reasoning text on the message is ignored."""
    message = _message(payload)
    calls = message.get("tool_calls")
    if isinstance(calls, list) and calls:
        parsed = _tool_arguments(calls[0], key)
    else:
        content = message.get("content")
        text = content if isinstance(content, str) else ""
        parsed = _object_from_text(_redact_key(text, key))
    if set(parsed) != _PATCH_KEYS:
        raise PatchRejected("model fix has unexpected fields")
    file_name = parsed["file"]
    root_cause = parsed["root_cause"]
    side_effects = parsed["side_effects"]
    if any(not isinstance(value, str) or not value.strip() for value in (file_name, root_cause, side_effects)):
        raise PatchRejected("model fix fields must be non-empty strings")
    pairs = _edit_pairs(parsed["edits"])
    return {
        "file": file_name,
        "edits": [{"old": old, "new": new} for old, new in pairs],
        "root_cause": root_cause,
        "side_effects": side_effects,
    }


def _tool_arguments(item: object, key: str) -> dict[str, object]:
    if not isinstance(item, dict):
        raise PatchRejected("model fix was not JSON")
    function = item.get("function")
    if not isinstance(function, dict) or function.get("name") != "submit_patch":
        raise PatchRejected("model fix was not JSON")
    raw = function.get("arguments")
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str):
        raise PatchRejected("model fix was not JSON")
    return _object_from_text(_redact_key(raw, key))


def _object_from_text(text: str) -> dict[str, object]:
    stripped = _FENCE.sub("", text.strip()).strip()
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise _NotJson(f"model fix was not JSON: {exc.msg}") from None
    if isinstance(data, dict) and set(data) == {"tool", "args"} and data.get("tool") == "submit_patch":
        args = data.get("args")
        if isinstance(args, dict):
            return args
        raise PatchRejected("model fix was not JSON")
    if not isinstance(data, dict):
        raise PatchRejected("model fix was not JSON")
    return data


def _message(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict):
        return {}
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return {}
    message = choices[0].get("message")
    return message if isinstance(message, dict) else {}


def _with_parse_error(feedback: str | None, error: str) -> str:
    """Append the parse error and ask for JSON only. This retry is not a new repair."""
    extra = f"{error}\nreturn only the JSON object, no prose, no markdown"
    if feedback:
        return f"{feedback}\n{extra}"
    return extra


def _request_view(
    finding: Finding,
    relative: str,
    handler_source: str,
    line_numbers: Sequence[int],
    matrix: AuthorizationMatrix,
    feedback: str | None,
) -> dict[str, object]:
    view: dict[str, object] = {
        "finding_id": finding.id,
        "route": finding.route,
        "method": finding.method,
        "reason": finding.reason,
        "file": relative,
        "line_numbers": list(line_numbers),
        "handler_source": handler_source,
        "matrix": _matrix_view(matrix),
    }
    if feedback:
        view["failure"] = feedback
    return view


def _patch_tool() -> dict[str, object]:
    string = {"type": "string", "minLength": 1}
    return {
        "type": "function",
        "function": {
            "name": "submit_patch",
            "description": "Submit exact text edits for the confirmed handler. This does not apply them.",
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["file", "edits", "root_cause", "side_effects"],
                "properties": {
                    "file": string,
                    "edits": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["old", "new"],
                            "properties": {
                                "old": string,
                                "new": {"type": "string"},
                            },
                        },
                    },
                    "root_cause": string,
                    "side_effects": string,
                },
            },
        },
    }


def _system_prompt() -> str:
    return (
        "Reply with JSON only, or call submit_patch. "
        "The object has exactly these keys: file, edits, root_cause, side_effects. "
        "file is the relative path of the confirmed handler. "
        "edits is a list of objects with old and new. "
        "old is an exact snippet that appears once in that file, and new is its replacement. "
        "Do not write a unified diff. "
        "Change at most 40 lines. "
        "Do not add imports of os, subprocess, socket, requests, or httpx. "
        "Do not call eval, exec, or open. Do not include commands. "
        "If failure is present, submit a corrected edit for that failure."
    )


def _matrix_view(matrix: AuthorizationMatrix) -> dict[str, object]:
    return {
        "identities": [user.name for user in matrix.users],
        "resources": [{"id": resource.id, "owner": resource.owner} for resource in matrix.resources],
        "read": _rule_view(matrix.read),
        "write": _rule_view(matrix.write),
    }


def _rule_view(rules: OperationRules) -> dict[str, str]:
    values = {
        "owner": rules.owner.expected,
        "non_owner": rules.non_owner.expected,
    }
    if rules.unauthenticated is not None:
        values["unauthenticated"] = rules.unauthenticated.expected
    return values


def _import_roots(tree: ast.AST) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module.split(".", 1)[0])
    return found


def _call_counts(tree: ast.AST) -> dict[str, int]:
    counts = {name: 0 for name in _BANNED_CALLS}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in counts:
            counts[node.func.id] += 1
    return counts


def _diff_path(header: str) -> str:
    raw = header[4:].split("\t", 1)[0].strip()
    if raw in {"/dev/null", "dev/null"}:
        raise PatchRejected("diff touches another file")
    try:
        return _clean_relative(raw[2:] if raw.startswith(("a/", "b/")) else raw)
    except PatchRejected:
        raise PatchRejected("diff touches another file") from None


def _clean_relative(value: str) -> str:
    parts = [part for part in value.strip().replace("\\", "/").split("/") if part not in {"", "."}]
    if not parts or any(part == ".." for part in parts):
        raise PatchRejected("file is outside the source directory")
    if re.match(r"^[A-Za-z]:", parts[0]):
        raise PatchRejected("file is outside the source directory")
    return "/".join(parts)


def _same_line(actual: str, expected: str) -> bool:
    return actual.replace("\r\n", "\n").rstrip("\n") == expected.replace("\r\n", "\n").rstrip("\n")


def _redact_key(text: str, key: str) -> str:
    if len(key) < 8:
        return text
    return text.replace(key, "[redacted]")


def route_for(finding: Finding, routes: Sequence[RouteFinding]) -> RouteFinding | None:
    """The static route that matches a classified finding."""
    for route in routes:
        if route.method.upper() == finding.method.upper() and route.path == finding.route:
            return route
    return None
