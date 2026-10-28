"""Heuristic authorization checks for the document fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.analyzer.auth_checks import assess_routes

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
    for finding in by_name.values():
        assert finding.reason.startswith("Heuristics are indicators, not proof.")
