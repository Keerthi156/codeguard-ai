"""Discover FastAPI routes by parsing source with ast.

Target files are read as text and parsed. They are never imported or executed.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from pydantic import BaseModel

_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete"})
_PATH_PARAMETER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)(?::[^{}]*)?\}")
_Function = ast.FunctionDef | ast.AsyncFunctionDef


class DiscoveredRoute(BaseModel):
    """One HTTP route found in source."""

    file: str
    function_name: str
    method: str
    path: str
    path_parameters: list[str]
    start_line: int
    end_line: int
    source: str


def discover_routes(directory: str | Path) -> list[DiscoveredRoute]:
    """Return routes declared under ``directory``, in file and source order."""
    root = Path(directory)
    if not root.is_dir():
        raise NotADirectoryError(str(root))
    found: list[DiscoveredRoute] = []
    for path in _python_files(root):
        found.extend(_discover_file(path, root))
    return found


def _python_files(root: Path) -> list[Path]:
    return sorted(
        path for path in root.rglob("*.py") if "__pycache__" not in path.parts
    )


def _discover_file(path: Path, root: Path) -> list[DiscoveredRoute]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    prefixes = _router_prefixes(tree)
    relative = path.relative_to(root).as_posix()
    routes: list[DiscoveredRoute] = []
    for function in _functions(tree):
        span = _function_span(function)
        if span is None:
            continue
        start_line, end_line = span
        for decorator in function.decorator_list:
            route = _route_from_decorator(decorator, prefixes)
            if route is None:
                continue
            receiver_prefix, method, raw_path = route
            full_path = _join_path(receiver_prefix, raw_path)
            routes.append(
                DiscoveredRoute(
                    file=relative,
                    function_name=function.name,
                    method=method,
                    path=full_path,
                    path_parameters=_PATH_PARAMETER.findall(full_path),
                    start_line=start_line,
                    end_line=end_line,
                    source=_snippet(source, start_line, end_line),
                )
            )
    return routes


def _router_prefixes(tree: ast.Module) -> dict[str, list[tuple[int, str]]]:
    """Map a module-level name to the APIRouter prefixes assigned to it."""
    bindings: dict[str, list[tuple[int, str]]] = {}
    for statement in tree.body:
        assigned = _assigned_call(statement)
        if assigned is None:
            continue
        name, call = assigned
        if not _is_apirouter(call):
            continue
        prefix = _keyword_string(call, "prefix") or ""
        bindings.setdefault(name, []).append((statement.lineno, prefix))
    return bindings


def _assigned_call(statement: ast.stmt) -> tuple[str, ast.Call] | None:
    if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
        target: ast.expr = statement.targets[0]
        value: ast.expr | None = statement.value
    elif isinstance(statement, ast.AnnAssign):
        target = statement.target
        value = statement.value
    else:
        return None
    if isinstance(target, ast.Name) and isinstance(value, ast.Call):
        return target.id, value
    return None


def _is_apirouter(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id == "APIRouter"
    if isinstance(func, ast.Attribute):
        return func.attr == "APIRouter"
    return False


def _functions(node: ast.AST) -> list[_Function]:
    found: list[_Function] = []
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            found.append(child)
        found.extend(_functions(child))
    return found


def _function_span(function: _Function) -> tuple[int, int] | None:
    """Line span from the first decorator through the end of the function."""
    if function.end_lineno is None:
        return None
    start_line = function.lineno
    if function.decorator_list:
        start_line = min(decorator.lineno for decorator in function.decorator_list)
    return start_line, function.end_lineno


def _route_from_decorator(
    decorator: ast.expr,
    prefixes: dict[str, list[tuple[int, str]]],
) -> tuple[str, str, str] | None:
    if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
        return None
    method = decorator.func.attr
    receiver = decorator.func.value
    if method not in _HTTP_METHODS or not isinstance(receiver, ast.Name):
        return None
    raw_path = _literal_path(decorator)
    if raw_path is None:
        return None
    return _prefix_before(prefixes.get(receiver.id, []), decorator.lineno), method.upper(), raw_path


def _literal_path(call: ast.Call) -> str | None:
    node = call.args[0] if call.args else _keyword_value(call, "path")
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _keyword_value(call: ast.Call, name: str) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _keyword_string(call: ast.Call, name: str) -> str | None:
    value = _keyword_value(call, name)
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    return None


def _prefix_before(bindings: list[tuple[int, str]], line: int) -> str:
    prefix = ""
    for binding_line, binding_prefix in bindings:
        if binding_line < line:
            prefix = binding_prefix
    return prefix


def _join_path(prefix: str, path: str) -> str:
    prefix = prefix.strip()
    path = path.strip()
    if prefix and not prefix.startswith("/"):
        prefix = f"/{prefix}"
    if path and not path.startswith("/"):
        path = f"/{path}"
    if not prefix:
        return path or "/"
    if path in {"", "/"}:
        return prefix.rstrip("/") or "/"
    return f"{prefix.rstrip('/')}/{path.lstrip('/')}"


def _snippet(source: str, start_line: int, end_line: int) -> str:
    lines = source.splitlines()
    return "\n".join(lines[start_line - 1 : end_line])
