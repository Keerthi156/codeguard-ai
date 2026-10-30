"""Static authorization heuristics for routes discovered from source.

Each handler is parsed with ast. Same-file functions it calls are parsed too,
because an ownership comparison often lives in a helper. One level of FastAPI
``Depends`` callables is parsed the same way, including a function imported
from another file under the scanned directory. Target code is never imported
or executed. These checks are indicators, not proof.
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
    parsed: dict[str, _Module] = {}
    return [_assess_route(root, route, parsed) for route in discover_routes(root)]


@dataclass
class _Signals:
    auth: bool = False
    lookup: bool = False
    ownership: bool = False
    role: bool = False
    lines: set[int] = field(default_factory=set)
    notes: list[tuple[str, str]] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)


@dataclass
class _Module:
    functions: dict[str, _Function]
    imports: dict[str, tuple[str, str | None]]


def _assess_route(
    root: Path,
    route: DiscoveredRoute,
    parsed: dict[str, _Module],
) -> RouteFinding:
    module = _module_for(root, route.file, parsed)
    functions = {} if module is None else module.functions
    handler = _match_handler(functions, route)
    signals = _Signals()
    signals.lines.update((route.start_line, route.end_line))
    if handler is not None:
        seen: set[tuple[str, tuple[str, ...], tuple[str, ...]]] = set()
        _scan_function(
            handler,
            set(route.path_parameters),
            set(),
            functions,
            signals,
            seen,
            handler=True,
            where="the handler",
            record_lines=True,
        )
        _follow_dependencies(root, route, handler, parsed, signals, seen)
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


def _module_for(root: Path, relative: str, parsed: dict[str, _Module]) -> _Module | None:
    cached = parsed.get(relative)
    if cached is not None:
        return cached
    path = root / relative
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=relative)
    except (OSError, SyntaxError, UnicodeError):
        empty = _Module({}, {})
        parsed[relative] = empty
        return empty
    functions = {
        statement.name: statement
        for statement in tree.body
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    module = _Module(functions, _import_map(tree, root, relative))
    parsed[relative] = module
    return module


def _import_map(tree: ast.AST, root: Path, relative: str) -> dict[str, tuple[str, str | None]]:
    """Map a local name to a file under ``root`` and, for ``from`` imports, the symbol."""
    current = Path(relative)
    found: dict[str, tuple[str, str | None]] = {}
    for statement in tree.body if isinstance(tree, ast.Module) else []:
        if isinstance(statement, ast.Import):
            for alias in statement.names:
                file_rel = _find_module(root, current, alias.name, 0)
                if file_rel is None:
                    continue
                found[alias.asname or alias.name] = (file_rel, None)
        elif isinstance(statement, ast.ImportFrom):
            file_rel = _find_module(root, current, statement.module or "", statement.level)
            if file_rel is None:
                continue
            for alias in statement.names:
                if alias.name == "*":
                    continue
                found[alias.asname or alias.name] = (file_rel, alias.name)
    return found


def _find_module(root: Path, current: Path, module: str, level: int) -> str | None:
    parts = [part for part in module.split(".") if part]
    if level:
        parent = current.parent
        for _ in range(level - 1):
            if parent == Path("."):
                return None
            parent = parent.parent
        bases = [parent.joinpath(*parts)] if parts else [parent]
    elif not parts:
        return None
    else:
        bases = [current.parent.joinpath(*parts), Path(*parts)]
    for base in bases:
        for suffix in (".py", "/__init__.py"):
            candidate = Path(str(base) + suffix)
            located = _inside_root(root, candidate)
            if located is not None:
                return located
    return None


def _inside_root(root: Path, candidate: Path) -> str | None:
    try:
        resolved = (root / candidate).resolve()
        root_resolved = root.resolve()
    except OSError:
        return None
    if not resolved.is_file() or not resolved.is_relative_to(root_resolved):
        return None
    return resolved.relative_to(root_resolved).as_posix()


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
    where: str,
    record_lines: bool,
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
        _collect_signature_auth(func, auth_names, signals, where, record_lines)
    _Scanner(func, path_names, auth_names, functions, signals, seen, where, record_lines).visit(func)


def _follow_dependencies(
    root: Path,
    route: DiscoveredRoute,
    handler: _Function,
    parsed: dict[str, _Module],
    signals: _Signals,
    seen: set[tuple[str, tuple[str, ...], tuple[str, ...]]],
) -> None:
    """Parse one level of Depends/Security callables. Nested dependencies are not entered."""
    for ref in _dependency_refs(handler):
        if not ref:
            _remember(signals.unresolved, "Depends")
            continue
        resolved = _resolve_dependency(root, route.file, ref, parsed)
        if resolved is None:
            _remember(signals.unresolved, ref)
            continue
        func, functions = resolved
        _scan_function(
            func,
            set(route.path_parameters),
            set(),
            functions,
            signals,
            seen,
            handler=True,
            where=f"dependency {func.name}",
            record_lines=False,
        )


def _resolve_dependency(
    root: Path,
    relative: str,
    name: str,
    parsed: dict[str, _Module],
) -> tuple[_Function, dict[str, _Function]] | None:
    module = _module_for(root, relative, parsed)
    if module is None:
        return None
    if "." not in name:
        local = module.functions.get(name)
        if local is not None:
            return local, module.functions
        imported = module.imports.get(name)
        if imported is None:
            return None
        return _imported_function(root, imported, name, parsed)
    parts = name.split(".")
    for cut in range(len(parts) - 1, 0, -1):
        imported = module.imports.get(".".join(parts[:cut]))
        if imported is None:
            continue
        file_rel, symbol = imported
        if symbol is not None:
            continue
        other = _module_for(root, file_rel, parsed)
        if other is None or len(parts[cut:]) != 1:
            return None
        func = other.functions.get(parts[cut])
        if func is None:
            return None
        return func, other.functions
    return None


def _imported_function(
    root: Path,
    imported: tuple[str, str | None],
    fallback: str,
    parsed: dict[str, _Module],
) -> tuple[_Function, dict[str, _Function]] | None:
    file_rel, symbol = imported
    other = _module_for(root, file_rel, parsed)
    if other is None:
        return None
    func = other.functions.get(symbol or fallback)
    if func is None:
        return None
    return func, other.functions


def _dependency_refs(func: _Function) -> list[str]:
    refs: list[str] = []
    defaults = _defaults_by_name(func)
    for arg in _args(func):
        for node in (arg.annotation, defaults.get(arg.arg)):
            if node is None:
                continue
            for call in _dependency_calls(node):
                _remember(refs, _dependency_ref(call))
    return refs


def _dependency_ref(call: ast.Call) -> str:
    if not call.args:
        return ""
    return _dotted_name(call.args[0]) or ""


def _remember(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def _classify(signals: _Signals) -> tuple[_Status, _Confidence, str]:
    scope = "in the handler or a same-file helper"
    if any(where.startswith("dependency ") for _kind, where in signals.notes):
        scope = "in the handler, a same-file helper, or a dependency"
    dependency_auth = _from_dependency(signals, "auth")
    dependency_lookup = _from_dependency(signals, "lookup")
    if signals.ownership and signals.role:
        text = (
            "An ownership comparison and a role check were observed "
            f"{scope}."
        )
        return "No issue observed", "medium", _finish(text, signals)
    if signals.ownership:
        text = (
            "An ownership comparison between a resource's owner field "
            f"and the current user was observed {scope}."
        )
        return "No issue observed", "medium", _finish(text, signals)
    if signals.role:
        text = f"A role check was observed {scope}."
        return "No issue observed", "medium", _finish(text, signals)
    if (signals.auth and signals.lookup) or dependency_auth or dependency_lookup:
        text = (
            "Authentication was observed and a path parameter is used "
            "to look up a resource, but no ownership comparison or role check was "
            f"observed {scope}."
        )
        if dependency_auth and not signals.lookup:
            text = (
                "Authentication was observed in a dependency, but no ownership comparison "
                f"or role check was observed {scope}."
            )
        elif dependency_lookup and not signals.auth:
            text = (
                "A path parameter is used to look up a resource in a dependency, but no "
                f"ownership comparison or role check was observed {scope}."
            )
        return "Suspected", "medium", _finish(text, signals)
    text = (
        "Authentication and a path parameter used to look up a resource "
        "were not both observed."
    )
    return "No issue observed", "low", _finish(text, signals)


def _from_dependency(signals: _Signals, kind: str) -> bool:
    return any(note == kind and where.startswith("dependency ") for note, where in signals.notes)


def _finish(body: str, signals: _Signals) -> str:
    parts = [f"{_NOT_PROOF} {body.strip()}"]
    contributed = _contribution_text(signals)
    if contributed:
        parts.append(contributed)
    unresolved = _unresolved_text(signals)
    if unresolved:
        parts.append(unresolved)
    return " ".join(parts)


def _contribution_text(signals: _Signals) -> str:
    labels = {
        "auth": "authentication",
        "lookup": "a resource lookup by a path parameter",
        "ownership": "an ownership comparison",
        "role": "a role check",
    }
    grouped: dict[str, list[str]] = {}
    for kind, where in signals.notes:
        if not where.startswith("dependency "):
            continue
        name = where.removeprefix("dependency ")
        grouped.setdefault(name, [])
        if kind not in grouped[name]:
            grouped[name].append(kind)
    sentences: list[str] = []
    for name, kinds in grouped.items():
        described = [labels[kind] for kind in ("auth", "lookup", "ownership", "role") if kind in kinds]
        if described:
            sentences.append(f"Dependency {name} contributed {_english_join(described)}.")
    return " ".join(sentences)


def _unresolved_text(signals: _Signals) -> str:
    names = [name or "Depends" for name in signals.unresolved]
    if not names:
        return ""
    label = "dependency" if len(names) == 1 else "dependencies"
    return f"Unresolved {label} {_english_join(names)}."


def _english_join(items: list[str]) -> str:
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + ", and " + items[-1]


class _Scanner(ast.NodeVisitor):
    def __init__(
        self,
        function: _Function,
        path_aliases: set[str],
        auth_aliases: set[str],
        functions: dict[str, _Function],
        signals: _Signals,
        seen: set[tuple[str, tuple[str, ...], tuple[str, ...]]],
        where: str,
        record_lines: bool,
    ) -> None:
        self.function = function
        self.path_aliases = path_aliases
        self.auth_aliases = auth_aliases
        self.functions = functions
        self.signals = signals
        self.seen = seen
        self.where = where
        self.record_lines = record_lines

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
            _mark(self.signals, "lookup", self.where, node.lineno, self.record_lines)
        if _string_text(node.slice) == "authorization":
            _mark(self.signals, "auth", self.where, node.lineno, self.record_lines)
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        sides = [node.left, *node.comparators]
        owner = any(_is_owner_field(side) for side in sides)
        current_user = any(_is_current_user(side, self.auth_aliases) for side in sides)
        if owner and current_user:
            _mark(self.signals, "ownership", self.where, node.lineno, self.record_lines)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in _ROLE_ATTRS:
            _mark(self.signals, "role", self.where, node.lineno, self.record_lines)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load) and node.id.lower() in {"token", "access_token", "bearer_token"}:
            _mark(self.signals, "auth", self.where, node.lineno, self.record_lines)
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
                _mark(self.signals, "auth", self.where, node.lineno, self.record_lines)
        func_name = _expr_name(node.func)
        if func_name and any(part in func_name.lower() for part in _ROLE_CALL_PARTS):
            _mark(self.signals, "role", self.where, node.lineno, self.record_lines)
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in _LOOKUP_ATTRS
            and             _call_uses_path(node, self.path_aliases)
        ):
            _mark(self.signals, "lookup", self.where, node.lineno, self.record_lines)
        if isinstance(node.func, ast.Name):
            callee = self.functions.get(node.func.id)
            if callee is None:
                return
            mapped_path, mapped_auth = _map_call(node, callee, self.path_aliases, self.auth_aliases)
            if mapped_path or mapped_auth:
                where = self.where if self.where.startswith("dependency ") else f"helper {callee.name}"
                _scan_function(
                    callee,
                    mapped_path,
                    mapped_auth,
                    self.functions,
                    self.signals,
                    self.seen,
                    handler=False,
                    where=where,
                    record_lines=self.record_lines,
                )


def _collect_signature_auth(
    func: _Function,
    auth_names: set[str],
    signals: _Signals,
    where: str,
    record_lines: bool,
) -> None:
    defaults = _defaults_by_name(func)
    for arg in _args(func):
        for node in (arg.annotation, defaults.get(arg.arg)):
            if node is None:
                continue
            for call in _dependency_calls(node):
                getter = _expr_name(call.args[0]) if call.args else None
                if getter and any(part in getter.lower() for part in _USER_GETTER_PARTS):
                    auth_names.add(arg.arg)
                    _mark(signals, "auth", where, call.lineno, record_lines)
            if _mentions_header(node) and any(part in arg.arg.lower() for part in _CREDENTIAL_PARTS):
                auth_names.add(arg.arg)
                _mark(signals, "auth", where, node.lineno, record_lines)
        if any(part in arg.arg.lower() for part in _CREDENTIAL_PARTS):
            auth_names.add(arg.arg)
            line = arg.lineno if isinstance(arg.lineno, int) else None
            _mark(signals, "auth", where, line, record_lines)


def _mark(signals: _Signals, kind: str, where: str, line: int | None, record_line: bool) -> None:
    if kind == "auth":
        signals.auth = True
    elif kind == "lookup":
        signals.lookup = True
    elif kind == "ownership":
        signals.ownership = True
    elif kind == "role":
        signals.role = True
    if record_line and isinstance(line, int):
        signals.lines.add(line)
    note = (kind, where)
    if note not in signals.notes:
        signals.notes.append(note)


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


def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        if base:
            return f"{base}.{node.attr}"
    return None


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
