"""Suite defaults: in-process apps, and real uvicorn only when marked slow."""

from __future__ import annotations

import importlib
from typing import Iterator

import pytest

SERVERS = [
    pytest.param("asgi", id="asgi"),
    pytest.param("uvicorn", marks=pytest.mark.slow, id="uvicorn"),
]


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "slow: end-to-end test that starts a real uvicorn process",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip slow tests unless the command names a marker expression."""
    if config.getoption("markexpr"):
        return
    skip = pytest.mark.skip(reason="slow end-to-end test; run with pytest -m slow")
    for item in items:
        if "slow" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def fixture_apps() -> dict[str, object]:
    """Import each document fixture once. Tests still reset its documents."""
    return {
        name: importlib.import_module(f"fixtures.{name}_api.app")
        for name in ("vulnerable", "secure")
    }


@pytest.fixture(scope="session", autouse=True)
def _preload_fixture_apps(fixture_apps: dict[str, object]) -> Iterator[None]:
    yield


def use_server(server: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Serve the target in-process unless this case is the real uvicorn run."""
    if server == "asgi":
        _serve_in_process(monkeypatch)


def _serve_in_process(monkeypatch: pytest.MonkeyPatch) -> None:
    import uuid
    import importlib.util
    from pathlib import Path

    import httpx

    from app.cli import _import_root
    from app.remediation.verifier import FixUsageError
    from app.runner.executor import execute_plan

    state: dict[str, object] = {"app": None}

    def load(target_app: str, cwd: Path) -> object:
        module_name, _, attribute = target_app.partition(":")
        path = cwd / Path(*module_name.split(".")).with_suffix(".py")
        spec = importlib.util.spec_from_file_location(f"codeguard_asgi_{uuid.uuid4().hex}", path)
        if spec is None or spec.loader is None:
            raise ImportError(str(path))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return getattr(module, attribute or "app")

    class _Stopped:
        def stop(self) -> None:
            return None

    def start_cli(config: object, source_dir: Path, _tokens: object) -> _Stopped:
        target_app = getattr(config, "target_app")
        state["app"] = load(target_app, _import_root(source_dir, target_app))
        return _Stopped()

    def start_fix(target_app: str, cwd: Path, _base_url: str, _tokens: object, *, label: str = "patched app") -> _Stopped:
        try:
            state["app"] = load(target_app, cwd)
        except Exception as exc:
            raise FixUsageError(f"{label} failed to start") from exc
        return _Stopped()

    async def execute(tests: object, config: object, **kwargs: object) -> object:
        if kwargs.get("transport") is None:
            app = state["app"]
            if app is None:
                raise RuntimeError("in-process app was not started")
            kwargs["transport"] = httpx.ASGITransport(app=app)
        return await execute_plan(tests, config, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr("app.cli._start_target", start_cli)
    monkeypatch.setattr("app.cli.execute_plan", execute)
    monkeypatch.setattr("app.remediation.verifier._start", start_fix)
    monkeypatch.setattr("app.remediation.verifier.execute_plan", execute)
    monkeypatch.setattr("app.cli.time.sleep", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("app.remediation.verifier.time.sleep", lambda *_args, **_kwargs: None)
