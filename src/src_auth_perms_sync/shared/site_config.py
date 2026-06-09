"""Site config validation shared by mutating workflows."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, cast

import json5
import src_py_lib as src

from . import queries, saml_groups

# HTTP statuses that genuinely indicate the access token can't read site
# config (missing Site Admin role / SITE_CONFIG#READ). Everything else
# (5xx, network, parse, etc.) is a transport / server failure, not an
# authorization problem — say so instead of misleading the operator.
AUTHORIZATION_HTTP_STATUSES = frozenset({401, 403})

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class SiteConfig:
    """Site-config-derived values needed by the mutation paths.

    Returned by `validate_site_config` after it confirms the safety
    invariants. Holds the bits we'd otherwise re-parse out of
    `effectiveContents` from multiple call sites.
    """

    bind_id_mode: str
    """`"USERNAME"` (the only value validate_site_config accepts) — kept
    for downstream snapshot / apply layers that pass it through."""

    auth_providers_by_config_id: dict[str, dict[str, Any]]
    """Raw `auth.providers[*]` site-config entries keyed by explicit
    `configID`, with redacted/secret fields stripped (see
    `_strip_sensitive_provider_fields`). Entries without an explicit
    `configID` are dropped — Sourcegraph synthesizes one as a content-
    addressed hash we can't safely replicate from Python.

    Surfaced to `cmd_get` so the YAML config carries every non-secret
    provider attribute (e.g. `identityProviderMetadataURL`,
    `serviceProviderIssuer`, `requireEmailDomain`) alongside the
    GraphQL-discovered fields."""

    saml_groups_attribute_name_by_config_id: dict[str, str]
    """Per-SAML-provider override of the SAML assertion attribute name
    that holds group memberships, keyed by the auth-provider's explicit
    `configID` (e.g. `"okta"`). Joins against the discovered
    `AuthProvider.configID` field exactly.

    Only populated for SAML site-config entries that set BOTH a non-
    default `groupsAttributeName` AND an explicit `configID`. Entries
    that customize `groupsAttributeName` without setting `configID`
    are skipped (with a warning) — Sourcegraph synthesizes a `configID`
    of `<type>:<index>` for them internally, but that synthesis is an
    implementation detail and order-dependent. Operators who need this
    override should set explicit `configID` on each affected SAML
    provider in site config.

    Providers without an entry fall back to
    `DEFAULT_GROUPS_ATTRIBUTE_NAME` (`"groups"`) — the same default
    Sourcegraph itself uses when `groupsAttributeName` is unset, so
    the fallback is safe."""


def validate_site_config(client: src.SourcegraphClient) -> SiteConfig:
    """Verify required site-config invariants for safe explicit-permissions use.

    Hard-fails (SystemExit) unless ALL of the following are true:

      1. `permissions.userMapping.enabled: true`
         The explicit permissions API will not accept mutations otherwise.
         Read from `site.configuration.effectiveContents` JSONC (no dedicated
         GraphQL field).

      2. `permissionsUserMappingBindID == USERNAME`
         Read directly from the GraphQL enum
         `PermissionsUserMappingBindID = USERNAME | EMAIL`, which is the
         server-side resolved value (no JSONC parse needed). Sourcegraph
         allows multiple users to share the same email, so an email-keyed
         bindID can collide and silently grant permissions to the wrong
         user. Usernames are guaranteed unique.

      3. `auth.enableUsernameChanges: false` (or unset; default is false)
         If users can rename themselves, username-keyed permissions become
         unstable: a user could rename into another user's old name and
         inherit their permissions. Read from JSONC (no dedicated GraphQL
         field).

    Also surfaces site-level config validationMessages as warnings.
    """
    bind_id_enum, contents = _query_site_configuration(client, "validate_site_config")

    user_mapping = cast(dict[str, Any], contents.get("permissions.userMapping", {}))
    enabled = bool(user_mapping.get("enabled", False))
    enable_username_changes = bool(contents.get("auth.enableUsernameChanges", False))

    log.info(
        "Site config: permissions.userMapping.enabled=%s  bindID=%s  auth.enableUsernameChanges=%s",
        enabled,
        bind_id_enum,
        enable_username_changes,
    )

    safety_errors: list[str] = []

    if not enabled:
        safety_errors.append(
            "permissions.userMapping.enabled must be `true` (currently false). "
            "The explicit permissions API rejects mutations otherwise."
        )

    if bind_id_enum != "USERNAME":
        safety_errors.append(
            f'permissions.userMapping.bindID must be "username" '
            f"(GraphQL enum currently {bind_id_enum}). Multiple Sourcegraph "
            f"users can share the same email, so email-keyed bindIDs can "
            f"silently grant permissions to the wrong user."
        )

    if enable_username_changes:
        safety_errors.append(
            "auth.enableUsernameChanges must be `false` (currently true). "
            "Username-keyed permissions become unstable if users can rename "
            "themselves — a user could rename into another user's old name "
            "and inherit their permissions."
        )

    overrides, saml_groups_errors = _extract_saml_groups_attribute_names(contents)

    # Two distinct error buckets so each gets its own targeted fix
    # guidance. Bundling them under one footer (as we did before) made
    # the existing-and-correct safety settings look like the failure
    # whenever the only real problem was a missing SAML configID.
    if safety_errors or saml_groups_errors:
        message_sections: list[str] = []
        bullet = "\n  - "
        if safety_errors:
            message_sections.append(
                "Site-config safety requirements not met:"
                + bullet
                + bullet.join(safety_errors)
                + "\n\nFix: edit site config (Site admin → Configuration) so it "
                "includes:\n"
                '  "permissions.userMapping": { "enabled": true, "bindID": "username" },\n'
                '  "auth.enableUsernameChanges": false'
            )
        if saml_groups_errors:
            message_sections.append(
                "SAML auth provider(s) need an explicit `configID`:"
                + bullet
                + bullet.join(saml_groups_errors)
            )
        raise SystemExit("FATAL: " + "\n\n".join(message_sections))

    return SiteConfig(
        bind_id_mode=bind_id_enum,
        auth_providers_by_config_id=_extract_auth_providers_by_config_id(contents),
        saml_groups_attribute_name_by_config_id=overrides,
    )


def _query_site_configuration(
    client: src.SourcegraphClient, event_name: str
) -> tuple[str, dict[str, Any]]:
    """Fetch and parse site configuration once, with consistent errors."""
    # Wrap the read-the-site-config call in its own event so a failure
    # surfaces in the structured log with phase context (http_status,
    # error_reason) instead of just bubbling up as an un-annotated
    # `error_type=SystemExit` on the run end event. Each underlying GraphQL/HTTP
    # attempt still emits shared-library `graphql_query` / `http_request` events.
    with src.span(event_name) as site_config_event:
        try:
            data = client.graphql(queries.QUERY_VALIDATE_PERMISSIONS_CONFIG)
        except src.GraphQLError as exception:
            if exception.status_code in AUTHORIZATION_HTTP_STATUSES:
                reason = (
                    f"The access token was rejected (HTTP {exception.status_code}). "
                    "It must belong to a Site Admin (or have SITE_CONFIG#READ)."
                )
            else:
                reason = (
                    "Request to the Sourcegraph instance failed before site config "
                    "could be read. This is a transport / server-side error, not an "
                    "authorization failure."
                )
            site_config_event["http_status"] = exception.status_code
            site_config_event["error_reason"] = reason
            raise SystemExit(
                f"FATAL: could not query site configuration. {reason}\n  {exception}"
            ) from exception

    site = cast(dict[str, Any], data["site"])
    bind_id_enum = cast(str, site["permissionsUserMappingBindID"])
    config = cast(dict[str, Any], site["configuration"])
    contents_str = cast(str, config["effectiveContents"])

    # bindID comes straight from the resolved-by-the-server enum
    # (PermissionsUserMappingBindID = USERNAME | EMAIL). The remaining
    # settings aren't exposed via dedicated GraphQL fields, so we parse
    # effectiveContents for those.
    try:
        contents = cast(dict[str, Any], json5.loads(contents_str))
    except Exception as exception:
        raise SystemExit(
            f"FATAL: could not parse site config effectiveContents as JSONC: {exception}"
        ) from exception
    return bind_id_enum, contents


# Sourcegraph's `effectiveContents` resolver redacts secrets by replacing
# them with this literal sentinel string (see internal/conf/validate.go
# in sourcegraph/sourcegraph). Any field carrying this value is stripped
# from the YAML — value-based, so it stays correct if Sourcegraph adds
# more redactions in the future without us having to enumerate them.
REDACTED_SENTINEL = "REDACTED"

# SAML fields Sourcegraph does NOT redact but we still drop:
# private keys / certs / inline IdP metadata blobs are large secrets that
# don't belong in a config-discovery YAML. The URL-form
# (`identityProviderMetadataURL`) is kept — it's a reference, not a blob.
_DROPPED_PROVIDER_FIELDS: frozenset[str] = frozenset(
    {
        "serviceProviderPrivateKey",
        "serviceProviderCertificate",
        "identityProviderMetadata",
    }
)


def _strip_sensitive_provider_fields(entry: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy of an `auth.providers[*]` entry with redacted
    and explicitly-dropped fields removed."""
    return {
        field_name: value
        for field_name, value in entry.items()
        if field_name not in _DROPPED_PROVIDER_FIELDS and value != REDACTED_SENTINEL
    }


def _extract_auth_providers_by_config_id(
    contents: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """`auth.providers[*]` site-config entries keyed by explicit `configID`,
    with secrets stripped. Entries without an explicit `configID` are
    silently skipped — see `SiteConfig.auth_providers_by_config_id` for
    the rationale."""
    by_config_id: dict[str, dict[str, Any]] = {}
    raw_providers = contents.get("auth.providers")
    if not isinstance(raw_providers, list):
        return by_config_id
    for raw_entry in cast(list[Any], raw_providers):
        if not isinstance(raw_entry, dict):
            continue
        entry = cast(dict[str, Any], raw_entry)
        config_id = entry.get("configID")
        if not isinstance(config_id, str) or not config_id:
            continue
        by_config_id[config_id] = _strip_sensitive_provider_fields(entry)
    return by_config_id


def _extract_saml_groups_attribute_names(
    contents: dict[str, Any],
) -> tuple[dict[str, str], list[str]]:
    """Per-SAML-provider `groupsAttributeName` keyed by explicit `configID`.

    Returns `(overrides, errors)`:

      - `overrides` covers SAML site-config entries that set BOTH a
        non-default `groupsAttributeName` AND an explicit `configID`,
        keyed by `configID` so the consumer can join against the
        discovered `AuthProvider.configID` field.

      - `errors` is one human-readable line per SAML provider that sets
        `groupsAttributeName` but omits `configID`. Returned (rather
        than raised) so the caller can fold them into its existing
        site-config errors batch and surface every problem at once.

    We refuse the missing-`configID` case because Sourcegraph
    synthesizes the configID from a SHA-256 hash of the provider's
    JSON-marshalled struct (see saml/config.go's `providerConfigID`).
    Replicating that hash from Python is fragile (Go struct field
    order, omitempty semantics, etc.) and the hash rotates whenever
    any provider field changes, so we'd silently misattribute group
    overrides on the next config edit. Easier to make the operator
    set an explicit `configID`.
    """
    overrides: dict[str, str] = {}
    errors: list[str] = []
    raw_providers = contents.get("auth.providers")
    if not isinstance(raw_providers, list):
        return overrides, errors
    for raw_entry in cast(list[Any], raw_providers):
        if not isinstance(raw_entry, dict):
            continue
        entry = cast(dict[str, Any], raw_entry)
        if entry.get("type") != saml_groups.SAML_SERVICE_TYPE:
            continue
        attribute_name = entry.get("groupsAttributeName")
        if not isinstance(attribute_name, str) or not attribute_name:
            continue
        if attribute_name == saml_groups.DEFAULT_GROUPS_ATTRIBUTE_NAME:
            continue
        config_id = entry.get("configID")
        if not isinstance(config_id, str) or not config_id:
            errors.append(_missing_config_id_error(entry, attribute_name))
            continue
        overrides[config_id] = attribute_name
    return overrides, errors


# auth.providers SAML fields most useful for identifying which entry an
# operator needs to fix when their site config is missing `configID`.
# Includes both human-set fields (displayName) and content-addressed
# fields (issuer/metadata URL) so the entry is unambiguous in any
# realistic deployment.
_SAML_PROVIDER_IDENTITY_FIELDS: tuple[str, ...] = (
    "displayName",
    "identityProviderMetadataURL",
    "identityProviderMetadata",
    "serviceProviderIssuer",
    "serviceProviderCertificate",
)


def _missing_config_id_error(entry: dict[str, Any], attribute_name: str) -> str:
    """Multi-line error describing a SAML provider that needs `configID` set.

    Each non-leading line is indented to look right when the result is
    joined under the `\\n  - ` bullet in `validate_site_config`'s
    SystemExit. The first line carries the bullet body; subsequent lines
    sit at column 6 so they line up under that body.
    """
    identity_lines: list[str] = []
    for field_name in _SAML_PROVIDER_IDENTITY_FIELDS:
        raw_value = entry.get(field_name)
        if isinstance(raw_value, str) and raw_value:
            # Trim long values (PEM cert blobs, multi-line metadata) so
            # the error stays scannable.
            display_value = raw_value if len(raw_value) <= 80 else raw_value[:77] + "..."
            identity_lines.append(f"        {field_name}: {display_value}")
    identity_block = (
        "\n".join(identity_lines) if identity_lines else "        <no identifying fields>"
    )
    return (
        f'auth.providers SAML entry sets `groupsAttributeName: "{attribute_name}"`\n'
        "      but is missing an explicit `configID`.\n"
        "\n"
        "      Identifying fields:\n"
        f"{identity_block}\n"
        "\n"
        "      Fix: in site config, add a `configID` to that auth.providers\n"
        '      entry, e.g. `"configID": "okta-prod"`. Pick any short string\n'
        "      that uniquely names this SAML provider.\n"
        "\n"
        "      Why: this script needs a stable name to refer to your SAML\n"
        "      provider. If you don't set `configID`, Sourcegraph generates\n"
        "      one for you, but that auto-generated value silently changes\n"
        "      whenever you edit any field on the provider — which would\n"
        "      break this script the next time you re-run it after a\n"
        "      site-config edit."
    )
