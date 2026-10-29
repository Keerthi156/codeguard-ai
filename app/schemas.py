"""Authorization policy for a local target."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic.json_schema import SkipJsonSchema

Decision = Literal["allow", "deny"]
HttpMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE"]


class User(BaseModel):
    """A synthetic caller. ``name`` is what resource owners refer to."""

    name: str = Field(min_length=1)
    token: str = Field(min_length=1)


class Resource(BaseModel):
    """An object id and the user who owns it."""

    id: str = Field(min_length=1)
    owner: str = Field(min_length=1)

    @field_validator("id", mode="before")
    @classmethod
    def stringify_id(cls, value: object) -> object:
        if isinstance(value, int) and not isinstance(value, bool):
            return str(value)
        return value


class AccessRule(BaseModel):
    """Expected result for one operation under one caller condition."""

    expected: Decision


class OperationRules(BaseModel):
    """Allow or deny for the owner, another user, and an anonymous caller."""

    owner: AccessRule
    non_owner: AccessRule
    unauthenticated: AccessRule | None = None


class AuthorizationMatrix(BaseModel):
    """Users, the resources they own, and the expected access rules."""

    users: list[User] = Field(default_factory=list)
    resources: list[Resource] = Field(default_factory=list)
    read: OperationRules
    write: OperationRules

    @model_validator(mode="after")
    def owners_are_known_users(self) -> Self:
        names = [user.name for user in self.users]
        if len(names) != len(set(names)):
            raise ValueError("user names must be unique")
        known = set(names)
        seen_ids: set[str] = set()
        for resource in self.resources:
            if resource.id in seen_ids:
                raise ValueError(f"duplicate resource id {resource.id}")
            seen_ids.add(resource.id)
            if resource.owner not in known:
                raise ValueError(f"resource {resource.id} is owned by unknown user {resource.owner!r}")
        return self


def _owner_only() -> OperationRules:
    return OperationRules(
        owner=AccessRule(expected="allow"),
        non_owner=AccessRule(expected="deny"),
        unauthenticated=AccessRule(expected="deny"),
    )


def default_owner_only_matrix() -> AuthorizationMatrix:
    """Only the owner can read or modify their resource.

    Other authenticated users and unauthenticated callers are denied for both
    operations. The returned matrix has no users or resources yet.
    """
    return AuthorizationMatrix(read=_owner_only(), write=_owner_only())


class TestCase(BaseModel):
    """One planned request. This is data for a later runner, not an executable command."""

    __test__ = False
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    route: str = Field(min_length=1)
    method: HttpMethod
    identity: str = Field(min_length=1)
    resource_id: str = Field(min_length=1)
    expected: Decision
    reason: str = Field(min_length=1)
    source: SkipJsonSchema[Literal["model", "required"]] = Field(default="model", exclude=True)


class TestPlan(BaseModel):
    """A set of planned access checks."""

    __test__ = False
    model_config = ConfigDict(extra="forbid")

    cases: list[TestCase]

    @model_validator(mode="after")
    def case_ids_are_unique(self) -> Self:
        ids = [case.id for case in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("test case ids must be unique")
        return self
