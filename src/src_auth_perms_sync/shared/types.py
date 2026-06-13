"""Shared Sourcegraph GraphQL response shapes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, NotRequired, TypedDict


class AuthProvider(TypedDict):
    serviceType: str
    serviceID: str
    clientID: str
    displayName: str
    isBuiltin: bool
    configID: str


class ExternalAccount(TypedDict):
    serviceType: str
    serviceID: str
    clientID: str
    # Provider-specific JSON; for SAML this is the gosaml2 AssertionInfo
    # (Assertions[].AttributeStatement.Attributes[].{Name,Values[].Value}).
    # See `src/src_auth_perms_sync/shared/saml_groups.py` for the parser. Site-admin only;
    # null for accounts where the server does not expose it.
    accountData: NotRequired[dict[str, Any] | None]


class ExternalAccountConnection(TypedDict):
    nodes: list[ExternalAccount]


class UserEmail(TypedDict):
    email: str
    verified: bool


class OrganizationReference(TypedDict):
    id: str
    name: str


class OrganizationReferenceConnection(TypedDict):
    nodes: list[OrganizationReference]


class User(TypedDict):
    id: str
    username: str
    builtinAuth: bool
    externalAccounts: ExternalAccountConnection
    emails: NotRequired[list[UserEmail]]
    organizations: NotRequired[OrganizationReferenceConnection]


@dataclass(frozen=True, slots=True)
class UserIdentity:
    user_id: str
    username: str


@dataclass(frozen=True, slots=True)
class MutationCounts:
    succeeded: int = 0
    failed: int = 0
    canceled: int = 0
    skipped: int = 0


@dataclass(frozen=True, slots=True)
class SamlGroupMembership:
    provider_config_id: str
    group_name: str


@dataclass(frozen=True, slots=True)
class SamlGroupUser(UserIdentity):
    saml_group_memberships: tuple[SamlGroupMembership, ...]


@dataclass(frozen=True, slots=True)
class ScopedSamlGroupUser(UserIdentity):
    """One in-scope user for a scoped (per-user) SAML organization sync.

    Unlike `SamlGroupUser`, users with zero group memberships are kept:
    scoped org sync must still remove them from synced orgs they no
    longer belong to. `synced_organizations` carries the user's current
    memberships in tool-managed (`synced-` prefixed) organizations.
    """

    saml_group_memberships: tuple[SamlGroupMembership, ...]
    synced_organizations: tuple[OrganizationReference, ...]


class SiteUserCandidate(TypedDict):
    id: str
    username: str
    email: str | None
    createdAt: str
    deletedAt: str | None
