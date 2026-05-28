"""Maps YAML: load mapping rules and dump read-only discovery references."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import json5
import src_py_lib as src
import yaml

from ..shared import id_codec, site_config
from ..shared import types as shared_types
from . import types as permission_types


def _strip_redacted(value: Any) -> Any:
    """Recursively drop any dict key whose value is exactly `"REDACTED"`.

    Sourcegraph's `ExternalService.config` resolver replaces secrets with
    that literal sentinel before returning the JSONC blob (see
    internal/types/secret.go in sourcegraph/sourcegraph). Some redactions
    live in nested arrays — e.g. GitHub `webhooks[].secret`,
    `gitSSHCredential.privateKey` — so the strip is recursive.

    Lists / scalars pass through unchanged. The redaction sentinel itself,
    if it appears as a top-level scalar (it shouldn't, but defensively),
    is replaced with `None`.
    """
    if isinstance(value, dict):
        return {
            field_name: _strip_redacted(field_value)
            for field_name, field_value in cast(dict[str, Any], value).items()
            if field_value != site_config.REDACTED_SENTINEL
        }
    if isinstance(value, list):
        return [_strip_redacted(item) for item in cast(list[Any], value)]
    return value


def auth_provider_to_yaml(
    provider: shared_types.AuthProvider,
    user_count: int,
    saml_group_user_counts: dict[str, int] | None = None,
    site_config_entry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Render an auth provider for the YAML config.

    Keys mirror the Sourcegraph site-config schema (`type`, `clientID`,
    `displayName`, `configID`). `serviceID` has no direct site-config field
    so we use the GraphQL name. `isBuiltin` is dropped (redundant with
    `type == "builtin"`). `userCount` is our addition.

    `site_config_entry`, when provided, is the matching `auth.providers[*]`
    JSONC entry (already stripped of redacted/secret fields by
    `auth_perms_sync/shared/site_config.py`). Any
    fields it carries that aren't already emitted from GraphQL are
    surfaced verbatim, so operators see the full provider config in the
    YAML — e.g. `identityProviderMetadataURL`, `serviceProviderIssuer`,
    `requireEmailDomain`, `allowSignup`. Order: GraphQL-derived identity
    keys first, then site-config extras, then observation-derived metadata.

    For SAML providers, `saml_group_user_counts` (group name → distinct
    user count) is ALWAYS surfaced under `samlGroupUserCounts:`, even
    when the mapping is empty. The empty case (`{}`) tells the operator
    the feature is supported but the IdP didn't release any
    `groupsAttributeName` (default `groups`) claim in this provider's
    assertions — typically because the IdP hasn't been configured to do
    so. Operators authoring `authProvider.samlGroup` mapping rules can use this
    field to size groups before writing rules, or to learn that they
    need to fix their IdP first. Pass `None` (the default for non-SAML
    providers) to omit the field entirely.

    Empty-string fields are omitted — the builtin provider has no
    serviceID / clientID / configID, so those keys would just be noise.
    """
    rendered: dict[str, Any] = {"type": provider["serviceType"]}
    if provider["serviceID"]:
        rendered["serviceID"] = provider["serviceID"]
    if provider["clientID"]:
        rendered["clientID"] = provider["clientID"]
    rendered["displayName"] = provider["displayName"]
    if provider["configID"]:
        rendered["configID"] = provider["configID"]
    if site_config_entry is not None:
        # Merge in every non-secret site-config field that isn't already
        # represented by a GraphQL-derived key above. The GraphQL value
        # wins on overlaps (`type`, `displayName`, `clientID`, `configID`)
        # since it's the resolved view the server actually uses.
        for field_name, value in site_config_entry.items():
            if field_name in rendered:
                continue
            rendered[field_name] = value
    rendered["userCount"] = user_count
    if saml_group_user_counts is not None:
        # Sort by descending count, then group name, so the largest groups
        # surface first when an operator skims the file.
        rendered["samlGroupUserCounts"] = dict(
            sorted(
                saml_group_user_counts.items(),
                key=lambda item: (-item[1], item[0]),
            )
        )
    return rendered


BUILTIN_PROVIDER_KEY: tuple[str, str, str] = ("builtin", "", "")


def count_users_per_provider(
    users: list[shared_types.User],
) -> dict[tuple[str, str, str], int]:
    """Distinct user count keyed by (serviceType, serviceID, clientID).

    A user contributes to:
      - each external-account provider key for which they have an account, AND
      - the synthetic builtin key ("builtin", "", "") when builtinAuth==true
        (they have a password set on the builtin provider).

    A user can therefore be counted under multiple providers (e.g. SAML +
    builtin) — this matches reality: such a user can sign in either way.
    """
    seen: dict[tuple[str, str, str], set[str]] = {}
    for user in users:
        if user.get("builtinAuth"):
            seen.setdefault(BUILTIN_PROVIDER_KEY, set()).add(user["id"])
        for account in user["externalAccounts"]["nodes"]:
            key = (account["serviceType"], account["serviceID"], account["clientID"])
            seen.setdefault(key, set()).add(user["id"])
    return {provider_key: len(user_ids) for provider_key, user_ids in seen.items()}


def external_service_to_yaml(service: permission_types.ExternalService) -> dict[str, Any]:
    """Render an external service for the YAML config.

    Keys mirror Sourcegraph GraphQL `ExternalService` field names directly
    (camelCase). Every scalar field exposed by the GraphQL schema is
    surfaced here, including the JSONC `config` blob (parsed and emitted
    as a nested mapping). Sourcegraph's `config` resolver redacts secrets
    by replacing their values with the literal string `"REDACTED"`; we
    strip those keys recursively via `_strip_redacted` so the YAML
    contains no useless redaction placeholders. Nested arrays
    (e.g. `webhooks[]`, `exclude[]`) are walked too.

    `id` is the decoded integer DB primary key, NOT the opaque base64
    GraphQL Node ID — operators copy this into mapping rules' `repos.
    codeHostConnection.id` field, where the integer form is much
    friendlier than `RXh0ZXJuYWxTZXJ2aWNlOjU=`.

    Optional / nullable fields are omitted when null/empty so the YAML
    stays readable. Booleans are always emitted (true or false) so the
    discovered state is explicit.
    """
    rendered: dict[str, Any] = {
        "id": id_codec.decode_external_service_id(service["id"]),
        "kind": service["kind"],
        "displayName": service["displayName"],
        "url": service["url"],
        "repoCount": service["repoCount"],
        "createdAt": service["createdAt"],
        "updatedAt": service["updatedAt"],
        "unrestricted": bool(service.get("unrestricted")),
        "suspended": bool(service.get("suspended")),
        "hasConnectionCheck": bool(service.get("hasConnectionCheck")),
        "supportsRepoExclusion": bool(service.get("supportsRepoExclusion")),
    }
    if service.get("lastSyncAt"):
        rendered["lastSyncAt"] = service["lastSyncAt"]
    if service.get("nextSyncAt"):
        rendered["nextSyncAt"] = service["nextSyncAt"]
    if service.get("lastSyncError"):
        rendered["lastSyncError"] = service["lastSyncError"]
    if service.get("warning"):
        rendered["warning"] = service["warning"]
    creator = service.get("creator")
    if creator and creator.get("username"):
        rendered["creator"] = creator["username"]
    last_updater = service.get("lastUpdater")
    if last_updater and last_updater.get("username"):
        rendered["lastUpdater"] = last_updater["username"]
    raw_config = service.get("config")
    if raw_config:
        try:
            parsed_config = cast(dict[str, Any], json5.loads(raw_config))
        except ValueError:
            # Unparsable JSONC: surface the raw string verbatim so the
            # operator can still see what's there. Stripping doesn't
            # apply since we have no structure to walk.
            rendered["config"] = raw_config
        else:
            rendered["config"] = _strip_redacted(parsed_config)
    return rendered


def dump_auth_providers_yaml(path: Path, providers: list[dict[str, Any]]) -> None:
    header = (
        "# Sourcegraph auth provider configs.\n"
        "# Generated/refreshed by:  auth-perms-sync --get\n"
        "# Use these values when writing maps.yaml rules under `users.authProvider`.\n"
        "# This file is read-only reference data; edit maps.yaml, not this file.\n"
    )
    _dump_readonly_discovery_yaml(path, header, "authProviders", providers)


def dump_code_hosts_yaml(path: Path, code_hosts: list[dict[str, Any]]) -> None:
    header = (
        "# Sourcegraph code host connection configs.\n"
        "# Generated/refreshed by:  auth-perms-sync --get\n"
        "# Use these values when writing maps.yaml rules under `repos.codeHostConnection`.\n"
        "# Secrets from ExternalService.config are stripped.\n"
        "# This file is read-only reference data; edit maps.yaml, not this file.\n"
    )
    _dump_readonly_discovery_yaml(path, header, "codeHostConnections", code_hosts)


def _dump_readonly_discovery_yaml(
    path: Path,
    header: str,
    section_name: str,
    entries: list[dict[str, Any]],
) -> None:
    with src.event(
        "disk_io",
        level="DEBUG",
        op="write",
        path=str(path),
        file_kind="yaml",
    ) as disk_event:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w") as output_file:
            output_file.write(header)
            output_file.write(f"{section_name}:\n")
            for entry in entries:
                output_file.write("\n")
                output_file.write(
                    yaml.safe_dump(
                        [entry],
                        sort_keys=True,
                        default_flow_style=False,
                        allow_unicode=True,
                    )
                )
        disk_event["bytes"] = path.stat().st_size


def create_maps_yaml_if_missing(path: Path) -> bool:
    """Create the operator-edited maps file once, preserving existing files."""
    content = (
        "# Auth provider → code host connection mapping rules\n"
        "# Maintain this file, using values from auth-providers.yaml "
        "and code-hosts.yaml as references\n"
        "\n"
        "maps:\n"
        "\n"
        "- name: Map 1\n"
    )
    with src.event(
        "disk_io",
        level="DEBUG",
        op="write",
        path=str(path),
        file_kind="yaml",
    ) as disk_event:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("x") as output_file:
                output_file.write(content)
        except FileExistsError:
            disk_event["skipped"] = True
            disk_event["bytes"] = 0
            return False
        disk_event["bytes"] = path.stat().st_size
        return True


def load_maps_yaml(path: Path) -> permission_types.ConfigFile:
    with src.event(
        "disk_io",
        level="DEBUG",
        op="read",
        path=str(path),
        file_kind="yaml",
    ) as disk_event:
        raw_bytes = path.read_bytes()
        disk_event["bytes"] = len(raw_bytes)
        loaded: Any = yaml.safe_load(raw_bytes)
    if loaded is None:
        return cast(permission_types.ConfigFile, {})
    if not isinstance(loaded, dict):
        raise SystemExit(f"{path}: top-level YAML must be a mapping, got {type(loaded).__name__}")
    return cast(permission_types.ConfigFile, loaded)
