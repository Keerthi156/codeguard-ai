"""Ask the configured model for ten ordinary FastAPI apps and store them.

The prompt does not mention security, authorization, vulnerabilities, ownership
checks, or testing. A reply that hits the length limit is stored and marked
truncated. A parsed file with no route decorator is not accepted. Seed ids are
read from the saved source. The config beside each accepted app is the
owner-only template.

    python scripts/generate_ai_apps.py
    python scripts/generate_ai_apps.py --provider meta --model muse-spark-1.3
    python scripts/generate_ai_apps.py --domain notes
"""

from __future__ import annotations

import argparse
import ast
import sys
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.config import credential_names, load_settings
from app.experiment import (
    DOMAINS,
    generation_prompt,
    has_route_decorator,
    prepare_app,
    read_outcome,
    record_regeneration,
    write_outcome,
    write_prompt_file,
)
from app.findings.classifier import git_revision

_MAX_TOKENS = 8000
_LENGTH_REASONS = frozenset({"length", "max_tokens"})
_TRANSPORT: httpx.BaseTransport | None = None


@dataclass(frozen=True)
class ModelReply:
    """One completion. ``finish_reason`` is the provider's stop cause."""

    content: str
    finish_reason: str


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate ten in-memory FastAPI apps")
    parser.add_argument("--provider", default="meta", help="meta, baseten, or fireworks")
    parser.add_argument("--model", default="muse-spark-1.3", help="model name sent to the provider")
    parser.add_argument(
        "--dir",
        default="experiments/ai_written",
        help="directory that receives one folder per domain",
    )
    parser.add_argument(
        "--domain",
        default="",
        help="regenerate one domain and archive its previous file",
    )
    args = parser.parse_args(argv)
    provider = args.provider.strip().lower()
    if provider not in {"meta", "baseten", "fireworks"}:
        print("Invalid PROVIDER. Use meta, baseten, or fireworks.", file=sys.stderr)
        return 2
    domain_arg = args.domain.strip()
    if domain_arg and domain_arg not in DOMAINS:
        print("Unknown domain.", file=sys.stderr)
        return 2
    try:
        settings = load_settings(provider=provider)
    except ValueError as exc:
        print(f"generation error: {exc}", file=sys.stderr)
        return 2
    if settings.use_mock_ai:
        print("generation error: the mock provider cannot generate apps", file=sys.stderr)
        return 2
    settings = replace(settings, model_name=args.model, provider=provider)
    key_name, _model_name, url_name = credential_names(provider)
    missing = [
        name
        for name, value in ((key_name, settings.model_api_key), (url_name, settings.model_base_url))
        if not value.strip()
    ]
    if missing:
        print("generation error: " + ", ".join(missing) + " is not set", file=sys.stderr)
        return 2
    destination = Path(args.dir)
    date = datetime.now(timezone.utc).date().isoformat()
    prompt_path = destination / "PROMPT.md"
    regenerating = bool(domain_arg)
    if not (regenerating and prompt_path.is_file()):
        write_prompt_file(
            prompt_path,
            provider=provider,
            model=settings.model_name,
            commit=git_revision() or "unknown",
            date=date,
        )
    domains = (domain_arg,) if regenerating else DOMAINS
    counts = {"generated": 0, "truncated": 0, "no_routes": 0, "rejected": 0, "not_scannable": 0, "runnable": 0}
    for domain in domains:
        counts["generated"] += 1
        folder = destination / domain
        folder.mkdir(parents=True, exist_ok=True)
        archived = _archive_previous(folder) if regenerating else ""
        _remove_config(folder)
        outcome = folder / "outcome.txt"
        if outcome.is_file():
            outcome.unlink()
        try:
            reply = _complete(settings, generation_prompt(domain))
        except RuntimeError as exc:
            print(f"generation error: {domain}: {exc}", file=sys.stderr)
            return 2
        (folder / "app.py").write_text(_code_only(reply.content), encoding="utf-8")
        if reply.finish_reason in _LENGTH_REASONS:
            write_outcome(folder, "truncated", "truncated")
            _remove_config(folder)
            counts["truncated"] += 1
            print(f"{domain}: truncated")
        else:
            kind = _classify(folder, counts)
            print(f"{domain}: {kind}")
        if regenerating and archived:
            record_regeneration(prompt_path, domain, date, archived)
    _print_counts(counts)
    print(destination.as_posix())
    return 0


def _classify(folder: Path, counts: dict[str, int]) -> str:
    """Accept a finished reply, or record why it was not accepted. No config on failure."""
    source = (folder / "app.py").read_text(encoding="utf-8")
    try:
        tree = ast.parse(source)
    except SyntaxError:
        tree = None
    if tree is not None and not has_route_decorator(tree):
        write_outcome(folder, "no_routes", "no routes: incomplete reply")
        _remove_config(folder)
        counts["no_routes"] += 1
        return "no routes: incomplete reply"
    prepared = prepare_app(folder)
    write_outcome(folder, prepared.kind, prepared.detail or prepared.kind)
    if prepared.kind != "runnable":
        _remove_config(folder)
    if prepared.kind == "rejected":
        counts["rejected"] += 1
        return f"rejected: {prepared.detail}"
    if prepared.kind == "not_scannable":
        counts["not_scannable"] += 1
        return f"not scannable: {prepared.detail}"
    if prepared.kind == "no_routes":
        counts["no_routes"] += 1
        return "no routes: incomplete reply"
    if prepared.kind == "truncated":
        counts["truncated"] += 1
        return "truncated"
    counts["runnable"] += 1
    return "runnable"


def _archive_previous(folder: Path) -> str:
    """Move app.py aside. A truncated app keeps the truncated name."""
    previous = folder / "app.py"
    if not previous.is_file():
        return ""
    recorded = read_outcome(folder)
    kind = recorded[0] if recorded else ""
    reason = recorded[1] if recorded and recorded[1] else (kind or "replaced")
    archive = folder / ("app.truncated.py" if kind == "truncated" else "app.rejected.py")
    archive.write_bytes(previous.read_bytes())
    previous.unlink()
    return reason


def _remove_config(folder: Path) -> None:
    config = folder / "codeguard.yaml"
    if config.is_file():
        config.unlink()


def _print_counts(counts: dict[str, int]) -> None:
    print(f"Generated: {counts['generated']}")
    print(f"Truncated: {counts['truncated']}")
    print(f"No routes: {counts['no_routes']}")
    print(f"Rejected by the safety gate: {counts['rejected']}")
    print(f"Not scannable: {counts['not_scannable']}")
    print(f"Runnable: {counts['runnable']}")


def _complete(settings: object, prompt: str) -> ModelReply:
    model = getattr(settings, "model_name")
    base_url = str(getattr(settings, "model_base_url")).rstrip("/")
    key = str(getattr(settings, "model_api_key"))
    url = f"{base_url}/chat/completions"
    body = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": _MAX_TOKENS,
    }
    headers = {"Authorization": f"Bearer {key}"}
    try:
        with httpx.Client(timeout=120.0, trust_env=False, transport=_TRANSPORT) as client:
            response = client.post(url, headers=headers, json=body, follow_redirects=False)
    except httpx.HTTPError:
        raise RuntimeError("model request failed") from None
    response.read()
    if response.status_code != 200:
        raise RuntimeError(f"model request failed with status {response.status_code}")
    try:
        payload = response.json()
    except ValueError:
        raise RuntimeError("model response was not JSON") from None
    choices = payload.get("choices") if isinstance(payload, dict) else None
    choice = choices[0] if isinstance(choices, list) and choices and isinstance(choices[0], dict) else None
    message = choice.get("message") if isinstance(choice, dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    finish = choice.get("finish_reason") if isinstance(choice, dict) else None
    finish_reason = finish if isinstance(finish, str) else ""
    if finish_reason in _LENGTH_REASONS:
        return ModelReply(content if isinstance(content, str) else "", finish_reason)
    if not isinstance(content, str) or not content.strip():
        raise RuntimeError("model response was empty")
    return ModelReply(content, finish_reason or "stop")


def _code_only(text: str) -> str:
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped + "\n"
    lines = stripped.splitlines()[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip() + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
