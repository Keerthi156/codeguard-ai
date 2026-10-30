"""Heuristic authorization checks for the document fixtures."""

from __future__ import annotations

import builtins
import importlib
from pathlib import Path

import pytest

from app.analyzer.auth_checks import _module_for, assess_routes

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("fixture_name", "status"),
    [("vulnerable", "Suspected"), ("secure", "No issue observed")],
)
def test_document_routes(fixture_name: str, status: str) -> None:
    directory = ROOT / "fixtures" / f"{fixture_name}_api"
    findings = [item for item in assess_routes(directory) if item.path == "/documents/{id}"]
    source = (directory / "app.py").read_text(encoding="utf-8").splitlines()
    owner_lines = [
        number
        for number, line in enumerate(source, start=1)
        if "owner" in line and "user" in line
    ]

    assert [(item.method, item.function_name) for item in findings] == [
        ("GET", "get_document"),
        ("PUT", "update_document"),
    ]
    for finding in findings:
        assert finding.status == status
        assert finding.confidence == "medium"
        assert finding.file == "app.py"
        assert finding.reason.startswith("Heuristics are indicators, not proof.")
        assert finding.line_numbers == sorted(set(finding.line_numbers))
        assert all(1 <= number <= len(source) for number in finding.line_numbers)
        if status == "Suspected":
            assert "no ownership comparison" in finding.reason
            assert "role check" in finding.reason
            continue
        assert "no ownership comparison" not in finding.reason
        assert "ownership comparison" in finding.reason
        assert any(number in owner_lines for number in finding.line_numbers)


def test_role_check_and_missing_lookup(tmp_path: Path) -> None:
    source = "\n".join(
        [
            '@app.get("/documents/{id}")',
            "def read_open(id: int, user=Depends(require_user)):",
            "    return items[id]",
            "",
            '@app.get("/admin/documents/{id}")',
            "def read_admin(id: int, user=Depends(require_user)):",
            '    if user.role != "admin":',
            "        return None",
            "    return items[id]",
            "",
            '@app.get("/health")',
            "def health(user=Depends(require_user)):",
            '    return "ok"',
            "",
        ]
    )
    (tmp_path / "api.py").write_text(source, encoding="utf-8")

    by_name = {item.function_name: item for item in assess_routes(tmp_path)}

    assert by_name["read_open"].status == "Suspected"
    assert by_name["read_open"].confidence == "medium"
    assert by_name["read_admin"].status == "No issue observed"
    assert "role check" in by_name["read_admin"].reason
    assert by_name["health"].status == "No issue observed"
    assert by_name["health"].confidence == "low"
    assert "proof. Authentication and a path parameter" in by_name["health"].reason
    for finding in by_name.values():
        assert finding.reason.startswith("Heuristics are indicators, not proof.")


def test_dependency_ownership_comparison_is_not_suspected(tmp_path: Path) -> None:
    (tmp_path / "api.py").write_text(
        "\n".join(
            [
                "def require_user(authorization: Annotated[str | None, Header()] = None) -> str:",
                "    return authorization or ''",
                "",
                "def owned_document(id: int, user: Annotated[str, Depends(require_user)]):",
                "    document = items.get(id)",
                "    if document.owner != user:",
                "        return None",
                "    return document",
                "",
                '@app.get("/documents/{id}")',
                "def read_item(document: Annotated[dict, Depends(owned_document)]):",
                "    return document",
                "",
            ]
        ),
        encoding="utf-8",
    )

    finding = _route(tmp_path, "read_item")

    assert finding.status == "No issue observed"
    assert finding.confidence == "medium"
    assert "ownership comparison" in finding.reason
    assert "no ownership comparison" not in finding.reason
    assert "Dependency owned_document contributed" in finding.reason
    assert "an ownership comparison" in finding.reason


def test_dependency_that_only_authenticates_and_loads_is_suspected(tmp_path: Path) -> None:
    (tmp_path / "api.py").write_text(
        "\n".join(
            [
                "def require_user(document_id: int, authorization: Annotated[str | None, Header()] = None):",
                "    document = items.get(document_id)",
                "    if document.owner != authorization:",
                "        return ''",
                "    return authorization or ''",
                "",
                "def authenticated_document(id: int, user: Annotated[str, Depends(require_user)]):",
                "    return items.get(id)",
                "",
                '@app.get("/documents/{id}")',
                "def read_item(document: Annotated[dict, Depends(authenticated_document)]):",
                "    return document",
                "",
            ]
        ),
        encoding="utf-8",
    )

    finding = _route(tmp_path, "read_item")

    assert finding.status == "Suspected"
    assert finding.confidence == "medium"
    assert "Dependency authenticated_document contributed" in finding.reason
    assert "authentication" in finding.reason
    assert "a resource lookup by a path parameter" in finding.reason
    assert "no ownership comparison" in finding.reason


def test_imported_dependency_is_parsed_and_not_executed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    marker = tmp_path / "executed.txt"
    (tmp_path / "checks.py").write_text(
        "\n".join(
            [
                "from pathlib import Path",
                f"Path({str(marker)!r}).write_text('executed')",
                "",
                "def owned_document(id: int, user=Depends(require_user)):",
                "    document = items.get(id)",
                "    if document.owner != user:",
                "        return None",
                "    return document",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "api.py").write_text(
        "\n".join(
            [
                "from checks import owned_document",
                "",
                '@app.get("/documents/{id}")',
                "def read_item(document=Depends(owned_document)):",
                "    return document",
                "",
            ]
        ),
        encoding="utf-8",
    )
    real_import = builtins.__import__

    def guarded(name: str, *args: object, **kwargs: object) -> object:
        if name == "checks" or name.startswith("checks."):
            raise AssertionError(name)
        return real_import(name, *args, **kwargs)

    def blocked(name: str, package: str | None = None) -> object:
        raise AssertionError(name)

    monkeypatch.setattr(builtins, "__import__", guarded)
    monkeypatch.setattr(importlib, "import_module", blocked)

    finding = _route(tmp_path, "read_item")

    assert finding.status == "No issue observed"
    assert "Dependency owned_document contributed" in finding.reason
    assert "an ownership comparison" in finding.reason
    assert not marker.exists()


def test_unresolvable_dependencies_are_reported_and_do_not_crash(tmp_path: Path) -> None:
    (tmp_path / "checks.py").write_text("def unrelated() -> None:\n    return None\n", encoding="utf-8")
    (tmp_path / "api.py").write_text(
        "\n".join(
            [
                "from checks import loader",
                "from absent_pkg import gone",
                "",
                '@app.get("/documents/{id}")',
                "def read_open(id: int, user=Depends(missing_user)):",
                "    return items[id]",
                "",
                '@app.get("/items/{item_id}")',
                "def read_missing_symbol(item=Depends(loader)):",
                "    return item",
                "",
                '@app.get("/other/{item_id}")',
                "def read_missing_module(item=Depends(gone)):",
                "    return item",
                "",
                '@app.get("/health")',
                "def health(user=Depends()):",
                "    return 'ok'",
                "",
            ]
        ),
        encoding="utf-8",
    )

    by_name = {item.function_name: item for item in assess_routes(tmp_path)}

    assert by_name["read_open"].status == "Suspected"
    assert "Unresolved dependency missing_user." in by_name["read_open"].reason
    assert by_name["read_missing_symbol"].status == "No issue observed"
    assert "Unresolved dependency loader." in by_name["read_missing_symbol"].reason
    assert "Unresolved dependency gone." in by_name["read_missing_module"].reason
    assert "Unresolved dependency Depends." in by_name["health"].reason
    assert "proof. Authentication and a path parameter" in by_name["health"].reason


def test_syntax_error_in_a_dependency_file_does_not_crash(tmp_path: Path) -> None:
    (tmp_path / "bad.py").write_text("def loader(:\n", encoding="utf-8")

    module = _module_for(tmp_path, "bad.py", {})

    assert module is not None
    assert module.functions == {}


def _route(directory: Path, function_name: str) -> object:
    matches = [item for item in assess_routes(directory) if item.function_name == function_name]
    assert len(matches) == 1
    return matches[0]
