"""Patch proposal tests. The fake transport never opens a network connection."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from app.analyzer.auth_checks import assess_routes
from app.config import Settings
from app.findings.classifier import Finding
from app.remediation.patcher import PatchProposal, PatchRejected, propose_patch
from app.schemas import AuthorizationMatrix, Resource, User, default_owner_only_matrix

_KEY = "sk-test-secret-key"
_REASONING = "private-chain-of-thought-9c1e"
_TOKEN = "alice-token-secret"
_ORIGINAL = "def get_document(user, document):\n    return document\n"
_PATCHED = (
    "def get_document(user, document):\n"
    "    if document.owner != user:\n"
    "        raise RuntimeError('missing')\n"
    "    return document\n"
)


def _settings() -> Settings:
    return Settings(
        model_api_key=_KEY,
        model_name="muse-spark-1.3",
        model_base_url="http://127.0.0.1:9/v1",
        use_mock_ai=False,
    )


def _matrix() -> AuthorizationMatrix:
    return default_owner_only_matrix().model_copy(
        update={
            "users": [User(name="alice", token=_TOKEN)],
            "resources": [Resource(id="101", owner="alice")],
        }
    )


def _finding() -> Finding:
    return Finding(
        id="get-documents-id",
        route="/documents/{id}",
        method="GET",
        status="Confirmed",
        reason="non-owner was allowed",
        source_lines=[1, 2],
        created_at=datetime.now(timezone.utc),
    )


def _source(tmp_path: Path, text: str = _ORIGINAL) -> Path:
    root = tmp_path / "api"
    root.mkdir()
    (root / "app.py").write_text(text, encoding="utf-8")
    return root


def _payload(old: str, new: str, file_name: str = "app.py") -> str:
    return json.dumps(
        {
            "file": file_name,
            "edits": [{"old": old, "new": new}],
            "root_cause": "the handler does not compare the caller with the owner",
            "side_effects": "a non-owner is denied",
        }
    )


def _reply(content: str) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "reasoning": _REASONING,
            "choices": [{"message": {"role": "assistant", "content": content, "reasoning_content": _REASONING}}],
        },
    )


def _transport(content: str, seen: list[httpx.Request]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _reply(content)

    return httpx.MockTransport(handler)


def _propose(
    tmp_path: Path,
    old: str,
    new: str,
    *,
    file_name: str = "app.py",
    source: str = _ORIGINAL,
) -> PatchProposal:
    seen: list[httpx.Request] = []
    root = _source(tmp_path, source)
    return propose_patch(
        _finding(),
        source_dir=root,
        route_file="app.py",
        handler_source=source,
        line_numbers=[1, 2],
        matrix=_matrix(),
        settings=_settings(),
        transport=_transport(_payload(old, new, file_name), seen),
    )


def test_valid_diff_is_applied_only_to_the_temp_copy(tmp_path: Path) -> None:
    seen: list[httpx.Request] = []
    root = _source(tmp_path)
    original = (root / "app.py").read_text(encoding="utf-8")
    proposal = propose_patch(
        _finding(),
        source_dir=root,
        route_file="app.py",
        handler_source=original,
        line_numbers=[1, 2],
        matrix=_matrix(),
        settings=_settings(),
        transport=_transport(_payload(_ORIGINAL, _PATCHED), seen),
    )

    copied = Path(proposal.temp_copy_path) / "app.py"
    assert proposal.status == "Fix proposed"
    assert proposal.finding_id == "get-documents-id"
    assert proposal.file == "app.py"
    assert copied.read_text(encoding="utf-8") == _PATCHED
    assert (root / "app.py").read_text(encoding="utf-8") == original
    assert Path(proposal.temp_copy_path).resolve() != root.resolve()
    assert len(seen) == 1
    body = seen[0].content.decode()
    assert _TOKEN not in body
    assert _KEY not in body
    assert _REASONING not in proposal.model_dump_json()
    assert "submit_patch" in body
    tool = next(item for item in json.loads(body)["tools"] if item["function"]["name"] == "submit_patch")
    assert tool["function"]["parameters"]["additionalProperties"] is False
    assert "unified_diff" not in tool["function"]["parameters"]["properties"]
    assert "edits" in tool["function"]["parameters"]["required"]


def test_diff_touching_another_file_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(PatchRejected, match="confirmed route file"):
        _propose(tmp_path, _ORIGINAL, _PATCHED, file_name="other.py")
    assert (tmp_path / "api" / "app.py").read_text(encoding="utf-8") == _ORIGINAL


def test_diff_over_40_lines_is_rejected(tmp_path: Path) -> None:
    added = "".join(f"line_{index} = {index}\n" for index in range(41))
    with pytest.raises(PatchRejected, match="40"):
        _propose(tmp_path, _ORIGINAL, _ORIGINAL + added)
    assert (tmp_path / "api" / "app.py").read_text(encoding="utf-8") == _ORIGINAL


def test_diff_that_breaks_syntax_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(PatchRejected, match="does not parse"):
        _propose(tmp_path, "return document", "return (")
    assert (tmp_path / "api" / "app.py").read_text(encoding="utf-8") == _ORIGINAL


def test_diff_adding_subprocess_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(PatchRejected, match="subprocess"):
        _propose(tmp_path, _ORIGINAL, "import subprocess\n" + _ORIGINAL)
    assert (tmp_path / "api" / "app.py").read_text(encoding="utf-8") == _ORIGINAL


def test_old_text_must_match_once(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    repeat = tmp_path / "repeat"
    missing.mkdir()
    repeat.mkdir()
    with pytest.raises(PatchRejected, match="old text not found"):
        _propose(missing, "missing snippet", "return document\n")
    with pytest.raises(PatchRejected, match="old text matched more than once"):
        _propose(repeat, "document", "record")
    assert (missing / "api" / "app.py").read_text(encoding="utf-8") == _ORIGINAL
    assert (repeat / "api" / "app.py").read_text(encoding="utf-8") == _ORIGINAL


def test_canned_patch_adds_an_owner_check_on_a_copy() -> None:
    root = Path(__file__).resolve().parents[1] / "fixtures" / "vulnerable_api"
    before = (root / "app.py").read_bytes()
    route = next(
        item
        for item in assess_routes(root)
        if item.method == "GET" and item.path == "/documents/{id}"
    )
    proposal = propose_patch(
        _finding(),
        source_dir=root,
        route_file=route.file,
        handler_source=route.source,
        line_numbers=route.line_numbers,
        matrix=_matrix(),
        canned=True,
    )

    copied = (Path(proposal.temp_copy_path) / route.file).read_text(encoding="utf-8")
    assert proposal.status == "Fix proposed"
    assert "CannedPatch (tests and --canned-patch only)" in proposal.root_cause
    assert "CannedPatch (tests and --canned-patch only)" in proposal.side_effects
    assert "if document.owner != user:" in copied
    assert 'HTTPException(status_code=404, detail="Document not found")' in copied
    assert (root / "app.py").read_bytes() == before
