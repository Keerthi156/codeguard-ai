"""Loading and validation of local target configs."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.schemas import default_owner_only_matrix
from app.target_config import load_target_config

ROOT = Path(__file__).resolve().parents[1]


def _config_text(base_url: str, owner: str = "alice") -> str:
    return "\n".join(
        [
            f"base_url: {base_url}",
            "users:",
            "  - name: alice",
            "    token: alice-token",
            "  - name: bob",
            "    token: bob-token",
            "resources:",
            "  - id: 101",
            f"    owner: {owner}",
            "routes:",
            "  - method: GET",
            "    path: /documents/{id}",
            "    operation: read",
            "",
        ]
    )


@pytest.mark.parametrize(
    ("filename", "base_url"),
    [
        ("codeguard.vulnerable.yaml", "http://127.0.0.1:8001"),
        ("codeguard.secure.yaml", "http://127.0.0.1:8002"),
    ],
)
def test_valid_config_loads(filename: str, base_url: str) -> None:
    config = load_target_config(ROOT / "fixtures" / filename)
    defaults = default_owner_only_matrix()

    assert config.base_url == base_url
    expected_target = {
        "codeguard.vulnerable.yaml": ("fixtures.vulnerable_api.app:app", "fixtures/vulnerable_api"),
        "codeguard.secure.yaml": ("fixtures.secure_api.app:app", "fixtures/secure_api"),
    }[filename]
    assert (config.target_app, config.source_dir) == expected_target
    assert [(user.name, user.token) for user in config.users] == [
        ("alice", "alice-token"),
        ("bob", "bob-token"),
    ]
    assert [(resource.id, resource.owner) for resource in config.resources] == [
        ("101", "alice"),
        ("202", "bob"),
    ]
    assert [(route.method, route.path, route.operation) for route in config.routes] == [
        ("GET", "/documents/{id}", "read"),
        ("PUT", "/documents/{id}", "write"),
    ]
    matrix = config.matrix()
    assert matrix.read == defaults.read
    assert matrix.write == defaults.write
    assert matrix.read.owner.expected == "allow"
    assert matrix.read.non_owner.expected == "deny"
    assert matrix.read.unauthenticated.expected == "deny"
    assert matrix.write.owner.expected == "allow"
    assert matrix.write.non_owner.expected == "deny"
    assert matrix.write.unauthenticated.expected == "deny"


def test_localhost_hostname_loads(tmp_path: Path) -> None:
    path = tmp_path / "codeguard.yaml"
    path.write_text(_config_text("http://localhost:8002"), encoding="utf-8")

    config = load_target_config(path)

    assert config.base_url == "http://localhost:8002"


@pytest.mark.parametrize(
    "base_url",
    ["http://example.com", "https://127.0.0.1:8001", "http://0.0.0.0:8001"],
)
def test_non_localhost_base_url_is_rejected(tmp_path: Path, base_url: str) -> None:
    path = tmp_path / "codeguard.yaml"
    path.write_text(_config_text(base_url), encoding="utf-8")

    with pytest.raises(ValidationError, match="127.0.0.1 or http://localhost"):
        load_target_config(path)


def test_unknown_resource_owner_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "codeguard.yaml"
    path.write_text(_config_text("http://127.0.0.1:8001", owner="carol"), encoding="utf-8")

    with pytest.raises(ValidationError, match="unknown user"):
        load_target_config(path)
