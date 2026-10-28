"""Static route discovery for the local document fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.analyzer.routes import discover_routes

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = [
    pytest.param(ROOT / "fixtures" / "vulnerable_api", id="vulnerable"),
    pytest.param(ROOT / "fixtures" / "secure_api", id="secure"),
]

_EXPECTED_LINES = {
    "GET": (74, 77, "get_document"),
    "PUT": (80, 90, "update_document"),
}


@pytest.mark.parametrize("fixture_dir", FIXTURES)
def test_discovers_document_routes(fixture_dir: Path) -> None:
    routes = discover_routes(fixture_dir)

    assert [(route.method, route.path) for route in routes] == [
        ("GET", "/documents/{id}"),
        ("PUT", "/documents/{id}"),
    ]
    file_lines = (fixture_dir / "app.py").read_text(encoding="utf-8").splitlines()
    for route in routes:
        start_line, end_line, function_name = _EXPECTED_LINES[route.method]
        assert route.file == "app.py"
        assert route.function_name == function_name
        assert route.path_parameters == ["id"]
        assert route.start_line == start_line
        assert route.end_line == end_line
        assert route.source == "\n".join(file_lines[start_line - 1 : end_line])
        assert route.source.splitlines()[0] == f'@app.{route.method.lower()}("/documents/{{id}}")'


def test_router_prefix_and_other_methods(tmp_path: Path) -> None:
    source = "\n".join(
        [
            "from fastapi import APIRouter, FastAPI",
            "",
            'router = APIRouter(prefix="/v1")',
            "app = FastAPI()",
            "",
            '@router.post("/documents/{document_id}")',
            "async def create_document(document_id: int) -> None:",
            "    return None",
            "",
            '@app.put("/documents/{document_id}")',
            '@app.patch(path="/documents/{document_id}")',
            "def replace_document(document_id: int) -> None:",
            "    return None",
            "",
            '@app.delete("/health/{name}")',
            "def drop(name: str) -> None:",
            "    return None",
            "",
        ]
    )
    (tmp_path / "api.py").write_text(source, encoding="utf-8")

    routes = discover_routes(tmp_path)

    assert [(route.method, route.path, route.function_name) for route in routes] == [
        ("POST", "/v1/documents/{document_id}", "create_document"),
        ("PUT", "/documents/{document_id}", "replace_document"),
        ("PATCH", "/documents/{document_id}", "replace_document"),
        ("DELETE", "/health/{name}", "drop"),
    ]
    assert routes[0].path_parameters == ["document_id"]
    assert routes[0].start_line == 6
    assert routes[0].end_line == 8
    assert routes[2].path_parameters == ["document_id"]
    assert routes[3].path_parameters == ["name"]
    assert routes[1].start_line == 10
    assert routes[1].end_line == 13


def test_parses_without_executing_target(tmp_path: Path) -> None:
    source = "\n".join(
        [
            "raise RuntimeError('executed')",
            "from fastapi import FastAPI",
            "app = FastAPI()",
            '@app.get("/live")',
            "def live() -> None:",
            "    return None",
            "",
        ]
    )
    (tmp_path / "live.py").write_text(source, encoding="utf-8")

    routes = discover_routes(tmp_path)

    assert len(routes) == 1
    assert routes[0].method == "GET"
    assert routes[0].path == "/live"
    assert routes[0].path_parameters == []
    assert routes[0].function_name == "live"
