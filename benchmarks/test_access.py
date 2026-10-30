# Local testing only. Proves benchmark labels through ASGI. Does not run CodeGuard.
"""Non-owner access must match the hand-written labels. Nothing listens on a port."""

from __future__ import annotations

import importlib
import re
from pathlib import Path
from types import ModuleType

import httpx
import pytest
import yaml

from app.target_config import load_target_config

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "benchmarks"
_LABELS = yaml.safe_load((BENCH / "labels.yaml").read_text(encoding="utf-8"))
_APPS = _LABELS["apps"]
_DENY = {401, 403, 404}
_PLACEHOLDER = re.compile(r"\{[^}]+\}")


def _apps() -> list[dict[str, object]]:
    return list(_APPS)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def test_readme_records_that_no_pair_was_used_while_building() -> None:
    text = (BENCH / "README.md").read_text(encoding="utf-8")
    assert "Pairs used while building the tool: none." in text
    assert "Results are reported as measured." in text
    assert _LABELS["pairs_used_while_building"] == "none"


def test_every_benchmark_file_says_local_testing_only() -> None:
    for path in BENCH.rglob("*"):
        if not path.is_file() or path.suffix == ".pyc" or "__pycache__" in path.parts:
            continue
        first = path.read_text(encoding="utf-8").splitlines()[0]
        assert first.startswith("#") or first.startswith("<!--"), path
        assert "local testing only" in first.lower(), path


@pytest.mark.anyio
@pytest.mark.parametrize("described", _apps(), ids=lambda item: str(item["id"]))
async def test_non_owner_access_matches_the_hand_written_label(described: dict[str, object]) -> None:
    config_path = ROOT / str(described["config"])
    config = load_target_config(config_path)
    labeled = {(str(route["method"]), str(route["path"])): bool(route["vulnerable"]) for route in described["routes"]}  # type: ignore[index,union-attr]
    configured = {(route.method, route.path) for route in config.routes}
    assert set(labeled) == configured
    assert config_path.parent == ROOT / str(config.source_dir)

    module_name = str(config.target_app).split(":", 1)[0]
    module = importlib.import_module(module_name)
    module.reset()
    tokens = {user.name: user.token for user in config.users}
    transport = httpx.ASGITransport(app=module.app)
    try:
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1",
            trust_env=False,
        ) as client:
            for method, path in configured:
                vulnerable = labeled[(method, path)]
                for resource in config.resources:
                    owner = tokens[resource.owner]
                    other_name = next(user.name for user in config.users if user.name != resource.owner)
                    other = tokens[other_name]
                    url = _fill(path, resource.id)
                    await _expect_owner(client, module, method, url, owner, resource.id)
                    await _expect_non_owner(
                        client,
                        module,
                        method,
                        url,
                        other,
                        resource.id,
                        resource.owner,
                        vulnerable,
                    )
                await _expect_missing(client, module, method, path, tokens[config.resources[0].owner])
                await _expect_anonymous(client, module, method, _fill(path, config.resources[0].id))
    finally:
        module.reset()


async def _expect_owner(
    client: httpx.AsyncClient,
    module: ModuleType,
    method: str,
    url: str,
    token: str,
    resource_id: str,
) -> None:
    module.reset()
    response = await _send(client, method, url, token)
    assert 200 <= response.status_code < 300, response.text
    if method == "GET":
        assert _private(module, resource_id) in response.text
    module.reset()


async def _expect_non_owner(
    client: httpx.AsyncClient,
    module: ModuleType,
    method: str,
    url: str,
    token: str,
    resource_id: str,
    owner: str,
    vulnerable: bool,
) -> None:
    module.reset()
    before = _private(module, resource_id)
    response = await _send(client, method, url, token)
    if vulnerable:
        assert 200 <= response.status_code < 300, response.text
        if method == "GET":
            assert f"{owner}-private" in response.text
        if method == "DELETE":
            assert _private(module, resource_id) is None
        if method == "PUT":
            assert _private(module, resource_id) == "synthetic"
    else:
        assert response.status_code in _DENY, response.text
        assert f"{owner}-private" not in response.text
        assert _private(module, resource_id) == before
    module.reset()


async def _expect_missing(client: httpx.AsyncClient, module: ModuleType, method: str, path: str, token: str) -> None:
    module.reset()
    response = await _send(client, method, _fill(path, _missing_id(path)), token)
    assert response.status_code == 404, response.text
    module.reset()


async def _expect_anonymous(client: httpx.AsyncClient, module: ModuleType, method: str, url: str) -> None:
    module.reset()
    response = await _send(client, method, url, None)
    assert response.status_code == 401, response.text
    module.reset()


async def _send(client: httpx.AsyncClient, method: str, url: str, token: str | None) -> httpx.Response:
    headers = {} if token is None else {"Authorization": f"Bearer {token}"}
    body = {"title": "synthetic", "content": "synthetic"} if method == "PUT" else None
    return await client.request(method, url, headers=headers, json=body)


def _fill(path: str, resource_id: str) -> str:
    filled, count = _PLACEHOLDER.subn(resource_id, path, count=1)
    if count != 1 or _PLACEHOLDER.search(filled):
        raise AssertionError(path)
    return filled


def _missing_id(path: str) -> str:
    if "invoice_id" in path:
        return "inv-999"
    if path == "/documents/{id}":
        return "999"
    return "00000000-0000-4000-8000-000000000000"


def _private(module: ModuleType, resource_id: str) -> str | None:
    """Return the private marker still stored for this resource, if any."""
    if hasattr(module, "DOCUMENTS"):
        key: object = int(resource_id) if resource_id.isdigit() else resource_id
        document = module.DOCUMENTS.get(key)
        if document is None:
            return None
        return str(document.content)
    owner = module.INVOICES.get(resource_id)
    if owner is None:
        return None
    return str(module.ITEMS[resource_id][0].note)
