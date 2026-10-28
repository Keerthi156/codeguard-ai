"""Static authorization heuristics for routes discovered from source.

Each handler is parsed with ast. Same-file functions it calls are parsed too,
because an ownership comparison often lives in a helper. Target code is never
imported or executed. These checks are indicators, not proof.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from app.analyzer.routes import DiscoveredRoute, discover_routes

_Function = ast.FunctionDef | ast.AsyncFunctionDef
_NOT_PROOF = "Heuristics are indicators, not proof."
_USER_GETTER_PARTS = ("user", "principal", "access_token", "bearer")
_CREDENTIAL_PARTS = ("authorization", "token", "bearer")
_LOOKUP_ATTRS = frozenset(
    {"get", "pop", "filter", "filter_by", "find", "find_one", "fetch", "query", "one", "first"}
)
_OWNER_ATTRS = frozenset(
    {"owner", "owner_id", "user_id", "account_id", "created_by", "author_id"}
)
_USER_ID_ATTRS = frozenset({"id", "user_id", "sub", "username", "owner_id"})
_ROLE_ATTRS = frozenset(
    {"role", "roles", "is_admin", "is_superuser", "scopes", "permissions", "is_staff"}
)
_ROLE_CALL_PARTS = ("role", "is_admin", "permission", "require_admin", "has_scope")
_Status = Literal["Suspected", "No issue observed"]
_Confidence = Literal["low", "medium"]


class RouteFinding(BaseModel):
    """Heuristic result for one route. Not a confirmed vulnerability."""

    file: str
    function_name: str
    method: str
    path: str
    status: _Status
    reason: str
    confidence: _Confidence
    line_numbers: list[int]
    source: str = ""


def assess_routes(directory: str | Path) -> list[RouteFinding]:
    """Apply authorization heuristics to every route under ``directory``."""
    root = Path(directory)
    parsed: dict[str, dict[str, _Function]] = {}
    return [_assess_route(root, route, parsed) for route in discover_routes(root)]


@dataclass
class _Signals:
    auth: bool = False
    lookup: bool = False
    ownership: bool = False
    role: bool = False
    lines: set[int] = field(default_factory=set)


def _assess_route(
    root: Path,
    route: DiscoveredRoute,
    parsed: dict[str, dict[str, _Function]],
) -> RouteFinding:
    functions = _functions_for(root, route.file, parsed)
    handler = _match_handler(functions, route)
    signals = _Signals()
    signals.lines.update((route.start_line, route.end_line))
    if handler is not None:
        _scan_function(
            handler,
            set(route.path_parameters),
            set(),
            functions,
            signals,
            set(),
            handler=True,
        )
    status, confidence, reason = _classify(signals)
    return RouteFinding(
        file=route.file,
        function_name=route.function_name,
        method=route.method,
        path=route.path,
        status=status,
        reason=reason,
        confidence=confidence,
        line_numbers=sorted(signals.lines),
        source=route.source,
    )


def _functions_for(
    root: Path,
    relative: str,
    parsed: dict[str, dict[str, _Function]],
) -> dict[str, _Function]:
    cached = parsed.get(relative)
    if cached is not None:
        return cached
    source = (root / relative).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=relative)
    functions = {
        statement.name: statement
        for statement in tree.body
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    parsed[relative] = functions
    return functions


def _match_handler(
    functions: dict[str, _Function],
    route: DiscoveredRoute,
) -> _Function | None:
    candidates = [func for func in functions.values() if func.name == route.function_name]
    if len(candidates) == 1:
        return candidates[0]
    for func in candidates:
        if func.end_lineno == route.end_line:
            return func
    return None


def _scan_function(
    func: _Function,
    path_aliases: set[str],
    auth_aliases: set[str],
    functions: dict[str, _Function],
    signals: _Signals,
    seen: set[tuple[str, tuple[str, ...], tuple[str, ...]]],
    *,
    handler: bool,
) -> None:
    key = (func.name, tuple(sorted(path_aliases)), tuple(sorted(auth_aliases)))
    if key in seen:
        return
    seen.add(key)
    path_names = set(path_aliases)
    auth_names = set(auth_aliases)
    if handler:
        names = set(_param_names(func))
        path_names &= names
        _collect_signature_auth(func, auth_names, signals)
    _Scanner(func, path_names, auth_names, functions, signals, seen).visit(func)


def _classify(signals: _Signals) -> tuple[_Status, _Confidence, str]:
    if signals.ownership and signals.role:
        return (
            "No issue observed",
            "medium",
            f"{_NOT_PROOF} An ownership comparison and a role check were observed "
            "in the handler or a same-file helper.",
        )
    if signals.ownership:
        return (
            "No issue observed",
            "medium",
            f"{_NOT_PROOF} An ownership comparison between a resource's owner field "
            "and the current user was observed in the handler or a same-file helper.",
        )
    if signals.role:
        return (
            "No issue observed",
            "medium",
            f"{_NOT_PROOF} A role check was observed in the handler or a same-file helper.",
        )
    if signals.auth and signals.lookup:
        return (
            "Suspected",
            "medium",
            f"{_NOT_PROOF} Authentication was observed and a path parameter is used "
            "to look up a resource, but no ownership comparison or role check was "
            "observed in the handler or a same-file helper.",
        )
    return (
        "No issue observed",
        "low",
        f"{_NOT_PROOF} Authentication and a path parameter used to look up a resource "
        "were not both observed.",
    )


class _Scanner(ast.NodeVisitor):
    def __init__(
        self,
        function: _Function,
        path_aliases: set[str],
        auth_aliases: set[str],
        functions: dict[str, _Function],
        signals: _Signals,
        seen: set[tuple[str, tuple[str, ...], tuple[str, ...]]],
    ) -> None:
        self.function = function
        self.path_aliases = path_aliases
        self.auth_aliases = auth_aliases
        self.functions = functions
        self.signals = signals
        self.seen = seen

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node is self.function:
            self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        if node is self.function:
            self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_Assign(self, node: ast.Assign) -> None:
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            self._alias(node.targets[0].id, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and node.value is not None:
            self._alias(node.target.id, node.value)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if _uses_name(node.slice, self.path_aliases):
            self.signals.lookup = True
            self.signals.lines.add(node.lineno)
        if _string_text(node.slice) == "authorization":
            self.signals.auth = True
            self.signals.lines.add(node.lineno)
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        sides = [node.left, *node.comparators]
        owner = any(_is_owner_field(side) for side in sides)
        current_user = any(_is_current_user(side, self.auth_aliases) for side in sides)
        if owner and current_user:
            self.signals.ownership = True
            self.signals.lines.add(node.lineno)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in _ROLE_ATTRS:
            self.signals.role = True
            self.signals.lines.add(node.lineno)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load) and node.id.lower() in {"token", "access_token", "bearer_token"}:
            self.signals.auth = True
            self.signals.lines.add(node.lineno)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self._note_call(node)
        self.generic_visit(node)

    def _alias(self, target: str, value: ast.expr) -> None:
        if isinstance(value, ast.Name) and value.id in self.path_aliases:
            self.path_aliases.add(target)
        if _is_current_user(value, self.auth_aliases):
            self.auth_aliases.add(target)

    def _note_call(self, node: ast.Call) -> None:
        for arg in (*node.args, *(keyword.value for keyword in node.keywords)):
            if _string_text(arg) == "authorization":
                self.signals.auth = True
                self.signals.lines.add(node.lineno)
        func_name = _expr_name(node.func)
        if func_name and any(part in func_name.lower() for part in _ROLE_CALL_PARTS):
            self.signals.role = True
            self.signals.lines.add(node.lineno)
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in _LOOKUP_ATTRS
            and _call_uses_path(node, self.path_aliases)
        ):
            self.signals.lookup = True
            self.signals.lines.add(node.lineno)
        if isinstance(node.func, ast.Name):
            callee = self.functions.get(node.func.id)
            if callee is None:
                return
            mapped_path, mapped_auth = _map_call(node, callee, self.path_aliases, self.auth_aliases)
            if mapped_path or mapped_auth:
                _scan_function(
                    callee,
                    mapped_path,
                    mapped_auth,
                    self.functions,
                    self.signals,
                    self.seen,
                    handler=False,
                )


def _collect_signature_auth(func: _Function, auth_names: set[str], signals: _Signals) -> None:
    defaults = _defaults_by_name(func)
    for arg in _args(func):
        for node in (arg.annotation, defaults.get(arg.arg)):
            if node is None:
                continue
            for call in _dependency_calls(node):
                getter = _expr_name(call.args[0]) if call.args else None
                if getter and any(part in getter.lower() for part in _USER_GETTER_PARTS):
                    auth_names.add(arg.arg)
                    signals.auth = True
                    signals.lines.add(call.lineno)
            if _mentions_header(node) and any(part in arg.arg.lower() for part in _CREDENTIAL_PARTS):
                auth_names.add(arg.arg)
                signals.auth = True
                signals.lines.add(node.lineno)
        if any(part in arg.arg.lower() for part in _CREDENTIAL_PARTS):
            auth_names.add(arg.arg)
            signals.auth = True
            line = arg.lineno if isinstance(arg.lineno, int) else None
            if line is not None:
                signals.lines.add(line)


def _dependency_calls(node: ast.expr) -> list[ast.Call]:
    return [
        child
        for child in ast.walk(node)
        if isinstance(child, ast.Call) and _expr_name(child.func) in {"Depends", "Security"}
    ]


def _mentions_header(node: ast.expr) -> bool:
    for child in ast.walk(node):
        if _expr_name(child) == "Header":
            return True
    return False


def _defaults_by_name(func: _Function) -> dict[str, ast.expr]:
    positional = [*func.args.posonlyargs, *func.args.args]
    found: dict[str, ast.expr] = {}
    for arg, default in zip(positional[-len(func.args.defaults) :], func.args.defaults):
        found[arg.arg] = default
    for arg, default in zip(func.args.kwonlyargs, func.args.kw_defaults):
        if default is not None:
            found[arg.arg] = default
    return found


def _args(func: _Function) -> list[ast.arg]:
    return [*func.args.posonlyargs, *func.args.args, *func.args.kwonlyargs]


def _param_names(func: _Function) -> list[str]:
    return [arg.arg for arg in _args(func)]


def _map_call(
    call: ast.Call,
    func: _Function,
    path_aliases: set[str],
    auth_aliases: set[str],
) -> tuple[set[str], set[str]]:
    mapped_path: set[str] = set()
    mapped_auth: set[str] = set()
    positional = [arg.arg for arg in (*func.args.posonlyargs, *func.args.args)]
    for name, value in zip(positional, call.args):
        _transfer(value, name, path_aliases, auth_aliases, mapped_path, mapped_auth)
    known = set(_param_names(func))
    for keyword in call.keywords:
        if keyword.arg is not None and keyword.arg in known:
            _transfer(keyword.value, keyword.arg, path_aliases, auth_aliases, mapped_path, mapped_auth)
    return mapped_path, mapped_auth


def _transfer(
    value: ast.expr,
    name: str,
    path_aliases: set[str],
    auth_aliases: set[str],
    mapped_path: set[str],
    mapped_auth: set[str],
) -> None:
    if isinstance(value, ast.Name) and value.id in path_aliases:
        mapped_path.add(name)
    if _is_current_user(value, auth_aliases):
        mapped_auth.add(name)


def _call_uses_path(call: ast.Call, path_aliases: set[str]) -> bool:
    values = [*call.args, *(keyword.value for keyword in call.keywords)]
    return any(_uses_name(value, path_aliases) for value in values)


def _uses_name(node: ast.expr, names: set[str]) -> bool:
    return any(isinstance(child, ast.Name) and child.id in names for child in ast.walk(node))


def _is_owner_field(node: ast.expr) -> bool:
    if isinstance(node, ast.Attribute):
        return node.attr in _OWNER_ATTRS
    return _string_text(node) in _OWNER_ATTRS


def _is_current_user(node: ast.expr, auth_names: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in auth_names
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return node.value.id in auth_names and node.attr in _USER_ID_ATTRS
    return False


def _expr_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _expr_name(node.func)
    return None


def _string_text(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.lower()
    return None
