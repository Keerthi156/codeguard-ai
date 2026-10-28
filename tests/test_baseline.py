"""Baseline access checks for the vulnerable and secure document fixtures.

Both apps are exercised in-process with HTTPX's ASGI transport. The vulnerable
app is expected to fail the non-owner checks; those cases are marked
``xfail(strict=True)`` so an unexpected pass fails the suite.
"""

from __future__ import annotations

import importlib
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from types import ModuleType
from typing import AsyncIterator

import httpx
import pytest

ALICE_HEADERS = {"Authorization": "Bearer alice-token"}
BOB_HEADERS = {"Authorization": "Bearer bob-token"}
ALICE_DOCUMENT_ID = 101
BOB_DOCUMENT_ID = 202
UNKNOWN_DOCUMENT_ID = 999
REPLACEMENT = {"title": "Revised notes", "content": "revised-by-caller"}

_VULNERABLE_DENIAL_XFAIL = pytest.mark.xfail(
    strict=True,
    reason="Vulnerable app allows any authenticated user to read and update every document.",
)

ALL_TARGETS = [
    pytest.param("vulnerable", id="vulnerable"),
    pytest.param("secure", id="secure"),
]
NON_OWNER_TARGETS = [
    pytest.param("vulnerable", id="vulnerable", marks=_VULNERABLE_DENIAL_XFAIL),
    pytest.param("secure", id="secure"),
]

CheckFn = Callable[[httpx.AsyncClient], Awaitable[None]]


@dataclass(frozen=True)
class BaselineCheck:
    name: str
    run: CheckFn
    expect_vulnerable_failure: bool = False


def load_app(target: str) -> ModuleType:
    """Import one fixture app module. ``target`` is ``vulnerable`` or ``secure``."""
    if target not in {"vulnerable", "secure"}:
        raise ValueError(f"Unknown target app: {target}")
    return importlib.import_module(f"fixtures.{target}_api.app")


def reset_documents(target: str) -> None:
    """Restore the in-memory documents so checks do not leak into each other."""
    module = load_app(target)
    module.DOCUMENTS.clear()
    module.DOCUMENTS[ALICE_DOCUMENT_ID] = module.Document(
        id=ALICE_DOCUMENT_ID,
        owner="alice",
        title="Alice notes",
        content="alice-private",
    )
    module.DOCUMENTS[BOB_DOCUMENT_ID] = module.Document(
        id=BOB_DOCUMENT_ID,
        owner="bob",
        title="Bob notes",
        content="bob-private",
    )


@asynccontextmanager
async def api_client(target: str) -> AsyncIterator[httpx.AsyncClient]:
    """HTTPX client bound to the fixture ASGI app on a localhost base URL."""
    reset_documents(target)
    transport = httpx.ASGITransport(app=load_app(target).app)
    try:
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1",
            trust_env=False,
        ) as client:
            yield client
    finally:
        reset_documents(target)


async def check_owner_read(client: httpx.AsyncClient) -> None:
    response = await client.get(f"/documents/{ALICE_DOCUMENT_ID}", headers=ALICE_HEADERS)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["id"] == ALICE_DOCUMENT_ID
    assert body["owner"] == "alice"
    assert body["content"] == "alice-private"


async def check_owner_write(client: httpx.AsyncClient) -> None:
    response = await client.put(
        f"/documents/{ALICE_DOCUMENT_ID}",
        headers=ALICE_HEADERS,
        json=REPLACEMENT,
    )
    assert response.status_code == 200, response.text
    assert response.json()["owner"] == "alice"
    assert response.json()["content"] == REPLACEMENT["content"]
    follow_up = await client.get(f"/documents/{ALICE_DOCUMENT_ID}", headers=ALICE_HEADERS)
    assert follow_up.status_code == 200, follow_up.text
    assert follow_up.json()["content"] == REPLACEMENT["content"]


async def check_non_owner_read(client: httpx.AsyncClient) -> None:
    response = await client.get(f"/documents/{BOB_DOCUMENT_ID}", headers=ALICE_HEADERS)
    assert response.status_code == 404, response.text


async def check_non_owner_write(client: httpx.AsyncClient) -> None:
    response = await client.put(
        f"/documents/{BOB_DOCUMENT_ID}",
        headers=ALICE_HEADERS,
        json=REPLACEMENT,
    )
    assert response.status_code == 404, response.text
    follow_up = await client.get(f"/documents/{BOB_DOCUMENT_ID}", headers=BOB_HEADERS)
    assert follow_up.status_code == 200, follow_up.text
    assert follow_up.json()["content"] == "bob-private"
    assert follow_up.json()["title"] == "Bob notes"


async def check_unauthenticated(client: httpx.AsyncClient) -> None:
    read = await client.get(f"/documents/{ALICE_DOCUMENT_ID}")
    write = await client.put(f"/documents/{ALICE_DOCUMENT_ID}", json=REPLACEMENT)
    assert read.status_code == 401, read.text
    assert write.status_code == 401, write.text


async def check_invalid_id(client: httpx.AsyncClient) -> None:
    read = await client.get(f"/documents/{UNKNOWN_DOCUMENT_ID}", headers=ALICE_HEADERS)
    write = await client.put(
        f"/documents/{UNKNOWN_DOCUMENT_ID}",
        headers=ALICE_HEADERS,
        json=REPLACEMENT,
    )
    assert read.status_code == 404, read.text
    assert write.status_code == 404, write.text


CHECKS: tuple[BaselineCheck, ...] = (
    BaselineCheck("owner read", check_owner_read),
    BaselineCheck("owner write", check_owner_write),
    BaselineCheck("non-owner read", check_non_owner_read, expect_vulnerable_failure=True),
    BaselineCheck("non-owner write", check_non_owner_write, expect_vulnerable_failure=True),
    BaselineCheck("unauthenticated", check_unauthenticated),
    BaselineCheck("invalid id", check_invalid_id),
)

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.parametrize("target", ALL_TARGETS)
async def test_owner_read_allowed(target: str) -> None:
    async with api_client(target) as client:
        await check_owner_read(client)


@pytest.mark.parametrize("target", ALL_TARGETS)
async def test_owner_write_allowed(target: str) -> None:
    async with api_client(target) as client:
        await check_owner_write(client)


@pytest.mark.parametrize("target", NON_OWNER_TARGETS)
async def test_non_owner_read_denied(target: str) -> None:
    async with api_client(target) as client:
        await check_non_owner_read(client)


@pytest.mark.parametrize("target", NON_OWNER_TARGETS)
async def test_non_owner_write_denied(target: str) -> None:
    async with api_client(target) as client:
        await check_non_owner_write(client)


@pytest.mark.parametrize("target", ALL_TARGETS)
async def test_unauthenticated_denied(target: str) -> None:
    async with api_client(target) as client:
        await check_unauthenticated(client)


@pytest.mark.parametrize("target", ALL_TARGETS)
async def test_invalid_id_returns_404(target: str) -> None:
    async with api_client(target) as client:
        await check_invalid_id(client)
