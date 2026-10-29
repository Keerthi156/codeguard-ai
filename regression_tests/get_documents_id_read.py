# Regression test for a verified authorization fix.
# Finding: get-documents-id
# Route: GET /documents/{id}
# Operation: read
# Date: 2026-10-29
# Revision: d7f85ab829493a3e48daace28cd9f2a006c89596
# Root cause: Missing object-level authorization: get_document returned any document by ID for any authenticated user without verifying ownership, allowing IDOR. The docstring explicitly noted ownership was not checked.
# Policy assumption: read access is owner allow, non-owner deny, unauthenticated deny.
# Tokens and the base URL come from the environment. This file has no keys.
# Requests are refused unless the base URL is http://127.0.0.1 or http://localhost.

from __future__ import annotations

import os
from collections.abc import Iterator
from urllib.parse import urlsplit

import httpx
import pytest

_ALLOWED = {'127.0.0.1', 'localhost'}
_WRITE = {'POST', 'PUT', 'PATCH'}
_BODY = {'title': 'synthetic', 'content': 'synthetic'}


def _base_url() -> str:
    raw = os.environ.get('CODEGUARD_BASE_URL', '')
    parsed = urlsplit(raw)
    host = (parsed.hostname or '').lower()
    if parsed.scheme != 'http' or host not in _ALLOWED or parsed.username or parsed.password:
        pytest.fail('CODEGUARD_BASE_URL must be http://127.0.0.1 or http://localhost')
    return raw.rstrip('/')


def _token(name: str) -> str:
    return os.environ[f'CODEGUARD_TOKEN_{name.upper()}']


@pytest.fixture
def client() -> Iterator[httpx.Client]:
    with httpx.Client(
        base_url=_base_url(),
        trust_env=False,
        timeout=5.0,
        follow_redirects=False,
    ) as http:
        yield http


def _request(http: httpx.Client, method: str, path: str, identity: str | None) -> httpx.Response:
    headers = {} if identity is None else {'Authorization': f'Bearer {_token(identity)}'}
    return http.request(method, path, headers=headers, json=_BODY if method.upper() in _WRITE else None)


def test_owner_alice_101(client: httpx.Client) -> None:
    response = _request(client, 'GET', '/documents/101', 'alice')
    assert 200 <= response.status_code < 300, f'owner access was denied with status {response.status_code}'

def test_exploit_non_owner_bob_101(client: httpx.Client) -> None:
    response = _request(client, 'GET', '/documents/101', 'bob')
    if 200 <= response.status_code < 300:
        raise AssertionError(f'access was allowed with status {response.status_code}')
    assert response.status_code in {401, 403, 404}, f'unexpected status {response.status_code}'

def test_exploit_unauthenticated_101(client: httpx.Client) -> None:
    response = _request(client, 'GET', '/documents/101', None)
    if 200 <= response.status_code < 300:
        raise AssertionError(f'access was allowed with status {response.status_code}')
    assert response.status_code in {401, 403, 404}, f'unexpected status {response.status_code}'

def test_owner_bob_202(client: httpx.Client) -> None:
    response = _request(client, 'GET', '/documents/202', 'bob')
    assert 200 <= response.status_code < 300, f'owner access was denied with status {response.status_code}'

def test_exploit_non_owner_alice_202(client: httpx.Client) -> None:
    response = _request(client, 'GET', '/documents/202', 'alice')
    if 200 <= response.status_code < 300:
        raise AssertionError(f'access was allowed with status {response.status_code}')
    assert response.status_code in {401, 403, 404}, f'unexpected status {response.status_code}'

def test_exploit_unauthenticated_202(client: httpx.Client) -> None:
    response = _request(client, 'GET', '/documents/202', None)
    if 200 <= response.status_code < 300:
        raise AssertionError(f'access was allowed with status {response.status_code}')
    assert response.status_code in {401, 403, 404}, f'unexpected status {response.status_code}'
