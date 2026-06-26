"""Parse shared SAML group memberships out of `ExternalAccount.accountData`.

Sourcegraph stores the full gosaml2 `AssertionInfo` JSON as the
`accountData` blob on each SAML external account (see
[QUERY_USERS](queries.py)). Group claims live inside the SAML assertion
attribute named by the provider's `groupsAttributeName` site config
(default `"groups"`).

This module does NOT fetch - it only parses user rows fetched with
`include_account_data=True`. Two on-disk shapes are handled defensively:

  1. Raw `*saml2.AssertionInfo`:
         accountData["Assertions"][i]["AttributeStatement"]["Attributes"][j]
                    {"Name": "<attr>", "Values": [{"Value": "..."}, ...]}

  2. The flattened `SAMLValues` shape:
     (`gosaml2 SAMLValues{Values: map[string]SAMLAttribute}`):
         accountData["Values"]["<attr>"]["Values"][j]["Value"]

Either form yields the same flat list of group-name strings.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any, cast

from . import types as shared_types

DEFAULT_GROUPS_ATTRIBUTE_NAME: str = "groups"
SAML_SERVICE_TYPE: str = "saml"

# Every organization this tool creates gets this name prefix. No human
# would name an org `synced-...`, so the prefix doubles as the ownership
# marker: an org is tool-managed if and only if its name starts with it.
SYNCED_ORGANIZATION_NAME_PREFIX: str = "synced-"
ORGANIZATION_NAME_MAX_LENGTH: int = 255

_ORGANIZATION_NAME_PART_RE = re.compile(r"[^A-Za-z0-9]+")
_ORGANIZATION_NAME_DASH_RUN_RE = re.compile(r"-+")


def organization_name_for_saml_group(provider_display_name: str, group_name: str) -> str:
    """Return the deterministic synced org name for one SAML group.

    Shape: `synced-<sanitized auth provider display name>-<sanitized group name>`.
    """
    provider_part = _organization_name_part(provider_display_name, "auth provider display name")
    group_part = _organization_name_part(group_name, "SAML group name")
    organization_name = f"{SYNCED_ORGANIZATION_NAME_PREFIX}{provider_part}-{group_part}"
    if len(organization_name) > ORGANIZATION_NAME_MAX_LENGTH:
        raise SystemExit(
            f"FATAL: generated org name for auth provider displayName={provider_display_name!r} "
            f"group={group_name!r} is {len(organization_name)} characters; "
            f"Sourcegraph org names must be <= {ORGANIZATION_NAME_MAX_LENGTH}."
        )
    return organization_name


def _organization_name_part(value: str, label: str) -> str:
    normalized = _ORGANIZATION_NAME_PART_RE.sub("-", value.strip())
    normalized = _ORGANIZATION_NAME_DASH_RUN_RE.sub("-", normalized).strip("-")
    if not normalized:
        raise SystemExit(
            f"FATAL: {label} {value!r} cannot be converted to a Sourcegraph org-name part."
        )
    return normalized


def is_synced_organization_name(organization_name: str) -> bool:
    """Return whether an org name marks the org as managed by this tool."""
    return organization_name.startswith(SYNCED_ORGANIZATION_NAME_PREFIX)


# Per-(serviceID, clientID) override of the SAML groups attribute name.
# `None` or a missing key means "use DEFAULT_GROUPS_ATTRIBUTE_NAME for
# this provider". Built by `attribute_names_by_provider_key()` from the
# discovered AuthProvider list joined against the configID-keyed
# overrides we parse out of site config.
SamlGroupsAttributeNameByProvider = dict[tuple[str, str], str]


def saml_providers_by_account_key(
    providers: Iterable[shared_types.AuthProvider],
) -> dict[tuple[str, str], shared_types.AuthProvider]:
    """Return SAML auth providers keyed like `ExternalAccount` rows."""
    return {
        (provider["serviceID"], provider["clientID"]): provider
        for provider in providers
        if provider["serviceType"] == SAML_SERVICE_TYPE
    }


def attribute_names_by_provider_key(
    providers: list[shared_types.AuthProvider],
    overrides_by_config_id: dict[str, str],
) -> SamlGroupsAttributeNameByProvider:
    """Re-key per-`configID` overrides to (serviceID, clientID).

    `extract_saml_groups` / `count_users_per_saml_group` look up by the
    pair the user's external account exposes (serviceID, clientID), but
    site config keys overrides by `configID`. Resolve the join here once,
    so callers of the parsing helpers can just hand them a single map.
    """
    by_provider: SamlGroupsAttributeNameByProvider = {}
    for provider in providers:
        if provider["serviceType"] != SAML_SERVICE_TYPE:
            continue
        attribute_name = overrides_by_config_id.get(provider["configID"])
        if attribute_name is None:
            continue
        by_provider[provider["serviceID"], provider["clientID"]] = attribute_name
    return by_provider


def attribute_name_for(
    overrides: SamlGroupsAttributeNameByProvider | None,
    service_id: str,
    client_id: str,
) -> str:
    """Lookup helper: return the per-provider override or the default."""
    if overrides is None:
        return DEFAULT_GROUPS_ATTRIBUTE_NAME
    return overrides.get((service_id, client_id), DEFAULT_GROUPS_ATTRIBUTE_NAME)


MISSING_GROUP_NAME: str = "missingGroup"


def extract_saml_groups(
    account_data: dict[str, Any] | None,
    attribute_name: str = DEFAULT_GROUPS_ATTRIBUTE_NAME,
) -> list[str]:
    """Pull the group-name strings out of one SAML `accountData` blob.

    Returns `[]` for null/empty data, missing attribute, or unknown shape
    - never raises. Duplicate group names within one assertion are
    de-duplicated; ordering is preserved.
    """
    if not account_data:
        return []
    groups: list[str] = []
    seen_set: set[str] = set()
    for group in _iter_saml_group_values(account_data, attribute_name):
        if group not in seen_set:
            groups.append(group)
            seen_set.add(group)
    return groups


def _iter_saml_group_values(account_data: dict[str, Any], attribute_name: str) -> Iterable[str]:
    yield from _iter_assertion_group_values(account_data, attribute_name)
    yield from _iter_flat_group_values(account_data, attribute_name)


def _iter_assertion_group_values(
    account_data: dict[str, Any], attribute_name: str
) -> Iterable[str]:
    """Yield groups from raw AssertionInfo accountData."""
    for assertion_dict in _dict_items(account_data.get("Assertions")):
        statement = assertion_dict.get("AttributeStatement")
        if not isinstance(statement, dict):
            continue
        statement_dict = cast(dict[str, Any], statement)
        for attribute_dict in _dict_items(statement_dict.get("Attributes")):
            if attribute_dict.get("Name") != attribute_name:
                continue
            yield from _iter_attribute_values(attribute_dict)


def _iter_flat_group_values(account_data: dict[str, Any], attribute_name: str) -> Iterable[str]:
    """Yield groups from flattened SAMLValues accountData."""
    flat = account_data.get("Values")
    if not isinstance(flat, dict):
        return
    attribute = cast(dict[str, Any], flat).get(attribute_name)
    if isinstance(attribute, dict):
        yield from _iter_attribute_values(cast(dict[str, Any], attribute))


def _iter_attribute_values(attribute: dict[str, Any]) -> Iterable[str]:
    for value in _dict_items(attribute.get("Values")):
        raw_value = value.get("Value")
        if isinstance(raw_value, str):
            yield raw_value


def _dict_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    items = cast(list[Any], value)
    return [cast(dict[str, Any], item) for item in items if isinstance(item, dict)]


def saml_group_memberships_for_user(
    user: shared_types.User,
    providers_by_account_key: dict[tuple[str, str], shared_types.AuthProvider],
    attribute_names_by_provider: SamlGroupsAttributeNameByProvider,
) -> tuple[shared_types.SamlGroupMembership, ...]:
    """Extract one user's distinct SAML provider/group memberships."""
    memberships: list[shared_types.SamlGroupMembership] = []
    seen: set[tuple[str, str, str]] = set()
    for account in user["externalAccounts"]["nodes"]:
        if account["serviceType"] != SAML_SERVICE_TYPE:
            continue
        provider = providers_by_account_key.get((account["serviceID"], account["clientID"]))
        if provider is None:
            continue
        attribute_name = attribute_name_for(
            attribute_names_by_provider,
            account["serviceID"],
            account["clientID"],
        )
        for group_name in extract_saml_groups(account.get("accountData"), attribute_name):
            membership_key = (provider["configID"], provider["displayName"], group_name)
            if membership_key in seen:
                continue
            memberships.append(
                shared_types.SamlGroupMembership(
                    provider_config_id=provider["configID"],
                    provider_display_name=provider["displayName"],
                    group_name=group_name,
                )
            )
            seen.add(membership_key)
    return tuple(memberships)


def compact_saml_group_user(
    user: shared_types.User,
    providers_by_account_key: dict[tuple[str, str], shared_types.AuthProvider],
    attribute_names_by_provider: SamlGroupsAttributeNameByProvider,
) -> shared_types.SamlGroupUser | None:
    """Return only the user fields org sync needs from one full user row."""
    memberships = saml_group_memberships_for_user(
        user, providers_by_account_key, attribute_names_by_provider
    )
    if not memberships:
        return None
    return shared_types.SamlGroupUser(
        user_id=user["id"],
        username=user["username"],
        saml_group_memberships=memberships,
    )


def compact_saml_group_users(
    users: Iterable[shared_types.User],
    providers: Iterable[shared_types.AuthProvider],
    attribute_names_by_provider: SamlGroupsAttributeNameByProvider,
) -> list[shared_types.SamlGroupUser]:
    """Compact full users to the org-sync data needed later in the run."""
    providers_by_account_key = saml_providers_by_account_key(providers)
    compact_users: list[shared_types.SamlGroupUser] = []
    for user in users:
        compact_user = compact_saml_group_user(
            user, providers_by_account_key, attribute_names_by_provider
        )
        if compact_user is not None:
            compact_users.append(compact_user)
    return compact_users


def compact_scoped_saml_group_users(
    users: Iterable[shared_types.User],
    providers: Iterable[shared_types.AuthProvider],
    attribute_names_by_provider: SamlGroupsAttributeNameByProvider,
) -> list[shared_types.ScopedSamlGroupUser]:
    """Compact in-scope users for a scoped (per-user) organization sync.

    Every user is kept - even with zero SAML group memberships - because
    scoped org sync also removes users from synced orgs they left. Each
    user's row must have been fetched with `include_organizations=True`;
    only `synced-` prefixed org memberships are retained.
    """
    providers_by_account_key = saml_providers_by_account_key(providers)
    scoped_users: list[shared_types.ScopedSamlGroupUser] = []
    for user in users:
        synced_organizations = tuple(
            organization
            for organization in user.get("organizations", {"nodes": []})["nodes"]
            if is_synced_organization_name(organization["name"])
        )
        scoped_users.append(
            shared_types.ScopedSamlGroupUser(
                user_id=user["id"],
                username=user["username"],
                saml_group_memberships=saml_group_memberships_for_user(
                    user, providers_by_account_key, attribute_names_by_provider
                ),
                synced_organizations=synced_organizations,
            )
        )
    return scoped_users


def count_users_per_saml_group(
    users: Iterable[shared_types.User],
    attribute_names_by_provider: SamlGroupsAttributeNameByProvider | None = None,
) -> dict[tuple[str, str], dict[str, int]]:
    """Tally users per `(serviceID, clientID)` SAML provider per group.

    Output keys mirror the `(serviceID, clientID)` pair on
    `AuthProvider`/`ExternalAccount` so the caller can join against
    `count_users_per_provider`'s discovered SAML providers without
    re-keying.

    `attribute_names_by_provider` is the per-(serviceID, clientID)
    override map produced by `attribute_names_by_provider_key()`.
    Providers without an entry fall back to
    `DEFAULT_GROUPS_ATTRIBUTE_NAME` ("groups"). Pass `None` (default)
    when no site config is available; every provider then falls back to
    the default.

    A user is counted at most once per (provider, group) - multiple
    accounts under the same provider with overlapping groups don't
    double-count, and groups that don't appear in any user's assertion
    don't appear in the output at all.

    SAML users on a provider whose assertion did not include any group
    membership are tallied under the synthetic group name
    `missingGroup` so operators can size the "ungrouped" cohort. A user
    with at least one account-with-groups on the provider is NOT counted
    as missing, even if another of their accounts on the same provider
    lacks groups.
    """
    seen: dict[tuple[str, str], dict[str, set[str]]] = {}
    provider_users: dict[tuple[str, str], set[str]] = {}
    grouped_users: dict[tuple[str, str], set[str]] = {}
    for user in users:
        for account in user["externalAccounts"]["nodes"]:
            if account["serviceType"] != SAML_SERVICE_TYPE:
                continue
            provider_key = (account["serviceID"], account["clientID"])
            provider_users.setdefault(provider_key, set()).add(user["id"])
            attribute_name = attribute_name_for(
                attribute_names_by_provider, account["serviceID"], account["clientID"]
            )
            groups = extract_saml_groups(account.get("accountData"), attribute_name)
            if not groups:
                continue
            grouped_users.setdefault(provider_key, set()).add(user["id"])
            per_group = seen.setdefault(provider_key, {})
            for group in groups:
                per_group.setdefault(group, set()).add(user["id"])
    result: dict[tuple[str, str], dict[str, int]] = {}
    for provider_key, all_user_ids in provider_users.items():
        per_group = seen.get(provider_key, {})
        counts = {group: len(user_ids) for group, user_ids in per_group.items()}
        missing = all_user_ids - grouped_users.get(provider_key, set())
        if missing:
            counts[MISSING_GROUP_NAME] = len(missing)
        if counts:
            result[provider_key] = counts
    return result
