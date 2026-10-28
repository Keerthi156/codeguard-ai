"""Load a codeguard YAML target description.

Only http://127.0.0.1 and http://localhost are accepted, with an optional port.
The file supplies synthetic users, resources, and the routes to test. Access
rules come from the owner-only authorization matrix.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal, Self
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from app.schemas import AuthorizationMatrix, Resource, User, default_owner_only_matrix

_ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost"})
HttpMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
Operation = Literal["read", "write"]


class TargetRoute(BaseModel):
    """One route the runner may call."""

    method: HttpMethod
    path: str = Field(min_length=1)
    operation: Operation

    @field_validator("method", mode="before")
    @classmethod
    def uppercase_method(cls, value: object) -> object:
        if isinstance(value, str):
            return value.upper()
        return value

    @field_validator("path")
    @classmethod
    def absolute_path(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("route path must start with /")
        return value


class TargetConfig(BaseModel):
    """A local target and the objects its routes should protect."""

    base_url: str
    users: list[User] = Field(min_length=1)
    resources: list[Resource] = Field(min_length=1)
    routes: list[TargetRoute] = Field(min_length=1)

    @field_validator("base_url")
    @classmethod
    def localhost_only(cls, value: str) -> str:
        return _normalize_base_url(value)

    @model_validator(mode="after")
    def reject_unknown_owners(self) -> Self:
        self.matrix()
        return self

    def matrix(self) -> AuthorizationMatrix:
        """Owner-only policy bound to this target's users and resources."""
        defaults = default_owner_only_matrix()
        return AuthorizationMatrix(
            users=self.users,
            resources=self.resources,
            read=defaults.read,
            write=defaults.write,
        )


def load_target_config(path: str | Path) -> TargetConfig:
    """Read and validate a codeguard YAML file."""
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("codeguard config must be a mapping")
    return TargetConfig.model_validate(raw)


def _normalize_base_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    host = parsed.hostname
    if parsed.scheme != "http" or host not in _ALLOWED_HOSTS or parsed.username or parsed.password:
        raise ValueError("base_url must be http://127.0.0.1 or http://localhost")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("base_url must be http://127.0.0.1 or http://localhost")
    port = f":{parsed.port}" if parsed.port is not None else ""
    return f"http://{host}{port}"
