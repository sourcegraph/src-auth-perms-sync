"""TypedDict shapes for Sourcegraph organization sync."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, TypeAlias, TypedDict

from ..shared import types as shared_types

OrganizationChangeKind: TypeAlias = Literal["add", "remove"]


class OrgMember(TypedDict):
    id: str
    username: str


class CreatedOrganization(TypedDict):
    id: str
    name: str


class OrganizationSnapshotStats(TypedDict):
    target_organizations: int
    existing_organizations: int
    total_current_members: int
    total_desired_members: int


class OrganizationSnapshotEntry(TypedDict):
    id: str | None
    provider_config_id: str
    saml_group: str
    members: list[OrgMember]
    desired_members: list[OrgMember]


class OrganizationSnapshot(TypedDict):
    schema_version: int
    captured_at: str
    endpoint: str
    stats: OrganizationSnapshotStats
    organizations: dict[str, OrganizationSnapshotEntry]


class OrganizationSnapshotDiffSummary(TypedDict):
    organizations_changed: int
    organizations_created: int
    members_added: int
    members_removed: int


class OrganizationSnapshotDiffEntry(TypedDict):
    name: str
    id: str | None
    provider_config_id: str
    saml_group: str
    created: bool
    before_count: int
    after_count: int
    added: list[str]
    removed: list[str]


class OrganizationSnapshotDiff(TypedDict):
    schema_version: int
    diff_kind: Literal["saml_organizations"]
    before_captured_at: str
    after_captured_at: str
    endpoint: str
    summary: OrganizationSnapshotDiffSummary
    organizations: list[OrganizationSnapshotDiffEntry]


@dataclass
class TargetOrganization:
    name: str
    provider_config_id: str
    saml_group: str
    desired_members_by_id: dict[str, OrgMember] = field(default_factory=dict[str, OrgMember])


@dataclass
class OrganizationState:
    id: str | None
    name: str
    members_by_id: dict[str, OrgMember]


@dataclass(frozen=True, slots=True)
class OrganizationUserChange(shared_types.UserIdentity):
    organization_name: str


class OrganizationBatchLookup(TypedDict):
    current_user: OrgMember
    states: dict[str, OrganizationState]


class OrganizationPlan(TypedDict):
    create_names: list[str]
    additions: list[OrganizationUserChange]
    removals: list[OrganizationUserChange]
