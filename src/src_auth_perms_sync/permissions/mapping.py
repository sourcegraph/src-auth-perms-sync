"""Permission mapping resolution: validate rules and match users/repos.

Each mapping rule has a `users:` section and a `repos:` section, each
containing one or more matchers. Within a matcher, the supplied keys
AND together against the discovered auth-provider / external-service
entries. Across sibling matchers, results intersect. Across mapping
rules, `cmd_set` unions the per-repo user sets at apply time — see
`src/src_auth_perms_sync/permissions/types.py` for the rationale.

Adding a new matcher type:

  1. Add the TypedDict in `src/src_auth_perms_sync/permissions/types.py`.
  2. Add it as a sibling key on `UsersFilter` or `ReposFilter`.
  3. Add a branch in `resolve_users` / `resolve_repos` below.
  4. Add structural validation in `validate_mapping_rules`.
  5. Add an example rule using the new matcher to `maps-example.yaml`.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from typing import Any, cast

import json5
import src_py_lib as src

from ..shared import saml_groups
from ..shared import types as shared_types
from . import types as permission_types

log = logging.getLogger(__name__)


# Sets of allowed matcher field names, used by the structural
# validators to reject typos. The mapping from matcher key to
# discovered-entry key is hard-coded inside `_providers_matching` /
# `_services_matching` (only `authProvider.type` differs:
# matcher `type` ↔ AuthProvider `serviceType`).
# Discovered-provider fields that AND together inside `_providers_matching`.
# `samlGroup` is allowed under `authProvider:` too but is not a provider
# field — it filters within the matched provider's users (see
# `_users_matching_auth_provider`).
AUTH_PROVIDER_MATCHER_FIELDS: set[str] = {
    "type",
    "serviceID",
    "clientID",
    "displayName",
    "configID",
    "samlGroup",
}
CODE_HOST_MATCHER_FIELDS: set[str] = {"id", "kind", "displayName", "url", "config"}
AUTH_PROVIDER_VALUE_MATCHES: tuple[tuple[str, str], ...] = (
    ("type", "serviceType"),
    ("serviceID", "serviceID"),
    ("clientID", "clientID"),
    ("displayName", "displayName"),
    ("configID", "configID"),
)
CODE_HOST_VALUE_MATCHES: tuple[str, ...] = ("kind", "displayName", "url")


# ---------------------------------------------------------------------------
# Validation (structural; cheap, runs before any GraphQL call)
# ---------------------------------------------------------------------------


def validate_mapping_rules(rules: list[permission_types.MappingRule]) -> None:
    """Fail fast on structural problems in the YAML before doing any work.

    Catches operator typos that would otherwise produce confusing partial
    results (or silent matches against the wrong set of users/repos)
    only after a full instance scan. Raises SystemExit with all
    collected errors at once so the operator gets one clear diagnostic
    instead of fix-one-find-the-next.

    Semantic warnings (e.g. an authProvider matcher with no fields set,
    which would match every provider on the instance) are logged at
    apply time by the resolver, not raised here — they're not always
    bugs.
    """
    errors: list[str] = []
    for rule_index, rule in enumerate(rules, start=1):
        label = rule.get("name") or f"<unnamed rule #{rule_index}>"
        prefix = f"mapping {rule_index} ({label!r})"

        users_section = cast(dict[str, object], rule.get("users") or {})
        repos_section = cast(dict[str, object], rule.get("repos") or {})

        if not users_section:
            errors.append(f"{prefix}: `users:` section is empty (matches no users)")
        if not repos_section:
            errors.append(f"{prefix}: `repos:` section is empty (matches no repos)")

        errors.extend(_validate_users_section(users_section, prefix))
        errors.extend(_validate_repos_section(repos_section, prefix))

    if errors:
        bullet = "\n  - "
        raise SystemExit(
            f"FATAL: {len(errors)} mapping configuration error(s):" + bullet + bullet.join(errors)
        )


_KNOWN_USER_MATCHERS: set[str] = {"authProvider", "emails", "usernames"}
_KNOWN_REPO_MATCHERS: set[str] = {"codeHostConnection", "names", "regexes"}


def mapping_rules_need_user_emails(mapping_rules: list[permission_types.MappingRule]) -> bool:
    """Return whether any mapping rule filters users by verified email."""
    return any("emails" in mapping["users"] for mapping in mapping_rules)


def _validate_users_section(section: dict[str, object], prefix: str) -> list[str]:
    """Reject unknown matcher keys and validate each matcher's shape."""
    errors: list[str] = []
    for key in section:
        if key not in _KNOWN_USER_MATCHERS:
            errors.append(f"{prefix}: unknown users matcher {key!r}")
    auth_provider = cast(dict[str, object] | None, section.get("authProvider"))
    if auth_provider is not None:
        unknown = set(auth_provider) - AUTH_PROVIDER_MATCHER_FIELDS
        for field_name in sorted(unknown):
            errors.append(f"{prefix}: unknown authProvider field {field_name!r}")
        if not auth_provider:
            errors.append(
                f"{prefix}: authProvider is empty (would match every provider on the instance)"
            )
        if "samlGroup" in auth_provider:
            errors.extend(_validate_saml_group(auth_provider, prefix))
    if "emails" in section:
        errors.extend(_validate_string_list(section["emails"], prefix, "users.emails"))
    if "usernames" in section:
        errors.extend(_validate_string_list(section["usernames"], prefix, "users.usernames"))
    return errors


def _validate_saml_group(auth_provider: dict[str, object], prefix: str) -> list[str]:
    """`authProvider.samlGroup`, if present, must be a non-empty string and
    incompatible with a non-SAML `type:` (the rule could never match).
    """
    errors: list[str] = []
    value = auth_provider["samlGroup"]
    if not isinstance(value, str):
        errors.append(
            f"{prefix}: authProvider.samlGroup must be a single group-name "
            f"string (got {type(value).__name__} {value!r}); to OR multiple "
            f"groups, write multiple rules"
        )
    elif not value:
        errors.append(f"{prefix}: authProvider.samlGroup is an empty string")
    declared_type = auth_provider.get("type")
    if (
        isinstance(declared_type, str)
        and declared_type
        and declared_type != saml_groups.SAML_SERVICE_TYPE
    ):
        errors.append(
            f"{prefix}: authProvider.samlGroup is set but authProvider.type "
            f"is {declared_type!r}; only SAML providers carry group claims"
        )
    return errors


def _validate_repos_section(section: dict[str, object], prefix: str) -> list[str]:
    """Reject unknown matcher keys and validate `codeHostConnection:` shape."""
    errors: list[str] = []
    for key in section:
        if key not in _KNOWN_REPO_MATCHERS:
            errors.append(f"{prefix}: unknown repos matcher {key!r}")
    code_host_section = cast(dict[str, object] | None, section.get("codeHostConnection"))
    if code_host_section is not None:
        unknown = set(code_host_section) - CODE_HOST_MATCHER_FIELDS
        for field_name in sorted(unknown):
            errors.append(f"{prefix}: unknown codeHostConnection field {field_name!r}")
        if not (set(code_host_section) & CODE_HOST_MATCHER_FIELDS):
            errors.append(
                f"{prefix}: codeHostConnection is empty (would match every "
                f"external service on the instance); supply at least one of "
                f"{sorted(CODE_HOST_MATCHER_FIELDS)}"
            )
        if "id" in code_host_section:
            external_service_id = code_host_section["id"]
            if external_service_id is None or external_service_id == "":
                errors.append(
                    f"{prefix}: codeHostConnection.id, if supplied, must be "
                    f"a non-empty integer (e.g. `id: 5`)"
                )
            elif not isinstance(external_service_id, int) or isinstance(external_service_id, bool):
                errors.append(
                    f"{prefix}: codeHostConnection.id must be an integer "
                    f"(got {type(external_service_id).__name__} {external_service_id!r}); "
                    f"the YAML config holds the decoded DB primary key, not the "
                    f"opaque base64 GraphQL Node ID"
                )
        if "config" in code_host_section and not isinstance(code_host_section["config"], dict):
            errors.append(
                f"{prefix}: codeHostConnection.config must be a mapping of "
                f"key/value pairs to deep-subset-match against the service's "
                f"parsed config (got {type(code_host_section['config']).__name__})"
            )
    if "names" in section:
        errors.extend(_validate_string_list(section["names"], prefix, "repos.names"))
    regexes = section.get("regexes")
    if regexes is not None:
        errors.extend(_validate_regexes(regexes, prefix))
    return errors


def _validate_regexes(value: object, prefix: str) -> list[str]:
    """Validate list-based regex filters."""
    errors = _validate_string_list(value, prefix, "repos.regexes")
    if errors:
        return errors

    for index, pattern in enumerate(cast(list[str], value)):
        try:
            re.compile(pattern)
        except re.error as exception:
            errors.append(
                f"{prefix}: repos.regexes[{index}] is not a valid Python regex: {exception}"
            )
    return errors


def _validate_string_list(value: object, prefix: str, path: str) -> list[str]:
    """Validate list-based exact-match filters."""
    if not isinstance(value, list):
        return [f"{prefix}: {path} must be a list of strings (got {type(value).__name__})"]

    items = cast(list[object], value)
    errors: list[str] = []
    if not items:
        errors.append(f"{prefix}: {path} is empty (matches nothing)")
    for index, item in enumerate(items):
        if not isinstance(item, str):
            errors.append(
                f"{prefix}: {path}[{index}] must be a string (got {type(item).__name__} {item!r})"
            )
        elif not item:
            errors.append(f"{prefix}: {path}[{index}] is an empty string")
    return errors


# ---------------------------------------------------------------------------
# Users resolution
# ---------------------------------------------------------------------------


def resolve_users(
    section: dict[str, object],
    all_users: list[shared_types.User],
    all_providers: list[shared_types.AuthProvider],
    saml_groups_attribute_names: saml_groups.SamlGroupsAttributeNameByProvider | None = None,
) -> list[shared_types.User]:
    """Return users matching ALL matchers under `users:` (intersection).

    `saml_groups_attribute_names` overrides the default `"groups"` SAML
    assertion attribute name per (serviceID, clientID) — see
    `src/src_auth_perms_sync/shared/saml_groups.py`. When
    `None`, every SAML provider falls back to the default. Only
    consulted by the `authProvider.samlGroup` sub-field.

    Empty section returns an empty user set — `validate_mapping_rules`
    rejects this at config-load time, so this branch only fires for
    programmatic callers.
    """
    if not section:
        return []

    users_by_id: dict[str, shared_types.User] = {user["id"]: user for user in all_users}
    matched_ids: set[str] | None = None
    for key, matcher in section.items():
        if key == "authProvider":
            current_ids = {
                user["id"]
                for user in _users_matching_auth_provider(
                    cast(permission_types.AuthProviderMatcher, matcher),
                    all_users,
                    all_providers,
                    saml_groups_attribute_names,
                )
            }
        elif key == "emails":
            current_ids = {
                user["id"] for user in _users_matching_emails(cast(list[str], matcher), all_users)
            }
        elif key == "usernames":
            current_ids = {
                user["id"]
                for user in _users_matching_usernames(cast(list[str], matcher), all_users)
            }
        else:
            # validate_mapping_rules catches this earlier with a clearer
            # message; this only fires for programmatic callers.
            raise ValueError(f"unknown users matcher {key!r}")
        matched_ids = current_ids if matched_ids is None else matched_ids & current_ids
        if not matched_ids:
            return []
    assert matched_ids is not None
    return [users_by_id[user_id] for user_id in matched_ids]


def user_matches_users_section(
    section: dict[str, object],
    user: shared_types.User,
    all_providers: list[shared_types.AuthProvider],
    saml_groups_attribute_names: saml_groups.SamlGroupsAttributeNameByProvider | None = None,
) -> bool:
    """Return whether one user matches ALL matchers under `users:`."""
    if not section:
        return False

    for key, matcher in section.items():
        if key == "authProvider":
            if not _user_matches_auth_provider(
                cast(permission_types.AuthProviderMatcher, matcher),
                user,
                all_providers,
                saml_groups_attribute_names,
            ):
                return False
        elif key == "emails":
            if not _user_matches_emails(user, cast(list[str], matcher)):
                return False
        elif key == "usernames":
            if user["username"] not in cast(list[str], matcher):
                return False
        else:
            # validate_mapping_rules catches this earlier with a clearer
            # message; this only fires for programmatic callers.
            raise ValueError(f"unknown users matcher {key!r}")
    return True


def _users_matching_emails(
    emails: list[str], all_users: list[shared_types.User]
) -> list[shared_types.User]:
    """Return users with at least one verified email in `emails`."""
    matched = [user for user in all_users if _user_matches_emails(user, emails)]
    log.info("    emails → %d user(s) matched %d email(s)", len(matched), len(set(emails)))
    return matched


def _user_matches_emails(user: shared_types.User, emails: list[str]) -> bool:
    """Match only verified emails, mirroring Sourcegraph's `user(email:)` lookup."""
    email_set = set(emails)
    return any(
        user_email["verified"] and user_email["email"] in email_set
        for user_email in user.get("emails", [])
    )


def _users_matching_usernames(
    usernames: list[str], all_users: list[shared_types.User]
) -> list[shared_types.User]:
    """Return users whose Sourcegraph username is listed exactly."""
    username_set = set(usernames)
    matched = [user for user in all_users if user["username"] in username_set]
    log.info(
        "    usernames → %d user(s) matched %d username(s)",
        len(matched),
        len(username_set),
    )
    return matched


def _users_matching_auth_provider(
    matcher: permission_types.AuthProviderMatcher,
    all_users: list[shared_types.User],
    all_providers: list[shared_types.AuthProvider],
    saml_groups_attribute_names: saml_groups.SamlGroupsAttributeNameByProvider | None,
) -> list[shared_types.User]:
    """Resolve `authProvider:` (and its optional `samlGroup:` sub-field)
    to the users it selects.

    When `samlGroup` is present, the matched-providers set is narrowed
    to SAML providers (group claims only exist there) and each user
    must additionally have that group named in the assertion stored on
    their account in one of those providers.
    """
    saml_group = matcher.get("samlGroup")
    matching_providers = _providers_matching(all_providers, matcher)
    if saml_group:
        matching_providers = [
            provider
            for provider in matching_providers
            if provider["serviceType"] == saml_groups.SAML_SERVICE_TYPE
        ]
    if not matching_providers:
        log.warning(
            "  authProvider matcher matched zero providers (%s).",
            _format_matcher(cast(dict[str, object], matcher)),
        )
        return []
    for provider in matching_providers:
        log.info(
            "    authProvider → %s (type=%s serviceID=%s clientID=%s)",
            provider["displayName"],
            provider["serviceType"],
            provider["serviceID"],
            provider["clientID"],
        )

    matched: dict[str, shared_types.User] = {}
    for provider in matching_providers:
        if saml_group:
            attribute_name = saml_groups.attribute_name_for(
                saml_groups_attribute_names,
                provider["serviceID"],
                provider["clientID"],
            )
            for user in all_users:
                if _user_has_saml_group_in_provider(user, provider, saml_group, attribute_name):
                    matched[user["id"]] = user
        else:
            for user in all_users:
                if _user_has_account_in(user, provider):
                    matched[user["id"]] = user
    if saml_group:
        log.info(
            "    samlGroup → %d user(s) in group %r",
            len(matched),
            saml_group,
        )
    return list(matched.values())


def _user_matches_auth_provider(
    matcher: permission_types.AuthProviderMatcher,
    user: shared_types.User,
    all_providers: list[shared_types.AuthProvider],
    saml_groups_attribute_names: saml_groups.SamlGroupsAttributeNameByProvider | None,
) -> bool:
    """Return whether a single user matches an `authProvider:` matcher."""
    saml_group = matcher.get("samlGroup")
    matching_providers = _providers_matching(all_providers, matcher)
    if saml_group:
        matching_providers = [
            provider
            for provider in matching_providers
            if provider["serviceType"] == saml_groups.SAML_SERVICE_TYPE
        ]
    if not matching_providers:
        return False

    for provider in matching_providers:
        if saml_group:
            attribute_name = saml_groups.attribute_name_for(
                saml_groups_attribute_names,
                provider["serviceID"],
                provider["clientID"],
            )
            if _user_has_saml_group_in_provider(user, provider, saml_group, attribute_name):
                return True
        elif _user_has_account_in(user, provider):
            return True
    return False


def _providers_matching(
    providers: list[shared_types.AuthProvider],
    matcher: permission_types.AuthProviderMatcher,
) -> list[shared_types.AuthProvider]:
    """AND across the supplied matcher fields. The matcher's `type` key
    maps to the GraphQL `serviceType` field; everything else has the
    same name on both sides.
    """
    matched: list[shared_types.AuthProvider] = []
    matcher_values = cast(Mapping[str, object], matcher)
    for provider in providers:
        provider_values = cast(Mapping[str, object], provider)
        if not all(
            matcher_key not in matcher_values
            or matcher_values[matcher_key] == provider_values[provider_key]
            for matcher_key, provider_key in AUTH_PROVIDER_VALUE_MATCHES
        ):
            continue
        matched.append(provider)
    return matched


def _user_has_account_in(user: shared_types.User, provider: shared_types.AuthProvider) -> bool:
    """Return whether `user` has an account matching `provider`."""
    if provider["serviceType"] == "builtin":
        return bool(user.get("builtinAuth"))
    for account in user["externalAccounts"]["nodes"]:
        if (
            account["serviceType"] == provider["serviceType"]
            and account["serviceID"] == provider["serviceID"]
            and account["clientID"] == provider["clientID"]
        ):
            return True
    return False


def _user_has_saml_group_in_provider(
    user: shared_types.User,
    provider: shared_types.AuthProvider,
    saml_group: str,
    attribute_name: str,
) -> bool:
    """Return whether `user` has `saml_group` in one SAML provider account."""
    for account in user["externalAccounts"]["nodes"]:
        if (
            account["serviceType"] == saml_groups.SAML_SERVICE_TYPE
            and account["serviceID"] == provider["serviceID"]
            and account["clientID"] == provider["clientID"]
            and saml_group
            in saml_groups.extract_saml_groups(account.get("accountData"), attribute_name)
        ):
            return True
    return False


# ---------------------------------------------------------------------------
# Repos resolution
# ---------------------------------------------------------------------------


def resolve_repos(
    section: dict[str, object],
    services_by_id: dict[int, permission_types.ExternalService],
    repos_by_external_service_id: dict[int, list[permission_types.Repository]],
    all_repos_by_id: dict[str, permission_types.Repository],
) -> list[permission_types.Repository]:
    """Return repos matching ALL matchers under `repos:` (intersection).

    Empty section returns an empty repo set; `validate_mapping_rules`
    rejects this at config-load time.
    """
    if not section:
        return []

    matched_ids: set[str] | None = None
    repo_index: dict[str, permission_types.Repository] = {}
    ordered_keys = [key for key in ("codeHostConnection", "names", "regexes") if key in section]
    for key in ordered_keys:
        matcher = section[key]
        if key == "codeHostConnection":
            repos = _repos_matching_code_host_connection(
                cast(permission_types.CodeHostConnectionMatcher, matcher),
                services_by_id,
                repos_by_external_service_id,
            )
        elif key == "names":
            candidate_repos = (
                [repo_index[repo_id] for repo_id in matched_ids]
                if matched_ids is not None
                else list(all_repos_by_id.values())
            )
            repos = _repos_matching_names(cast(list[str], matcher), candidate_repos)
        elif key == "regexes":
            candidate_repos = (
                [repo_index[repo_id] for repo_id in matched_ids]
                if matched_ids is not None
                else list(all_repos_by_id.values())
            )
            repos = _repos_matching_regexes(cast(list[str], matcher), candidate_repos)
        else:
            # validate_mapping_rules catches this earlier with a clearer
            # message; this only fires for programmatic callers.
            raise ValueError(f"unknown repos matcher {key!r}")
        current_ids = {repo["id"] for repo in repos}
        for repo in repos:
            repo_index[repo["id"]] = repo
        matched_ids = current_ids if matched_ids is None else matched_ids & current_ids
        if not matched_ids:
            return []
    assert matched_ids is not None
    return [repo_index[repo_id] for repo_id in matched_ids]


def _repos_matching_names(
    names: list[str], repos: list[permission_types.Repository]
) -> list[permission_types.Repository]:
    """Return repos whose Sourcegraph name is listed exactly."""
    name_set = set(names)
    matched = [repo for repo in repos if repo["name"] in name_set]
    log.info("    names → %d repo(s) matched %d name(s)", len(matched), len(name_set))
    return matched


def _repos_matching_code_host_connection(
    matcher: permission_types.CodeHostConnectionMatcher,
    services_by_id: dict[int, permission_types.ExternalService],
    repos_by_external_service_id: dict[int, list[permission_types.Repository]],
) -> list[permission_types.Repository]:
    matching_services = _services_matching(services_by_id, matcher)
    if not matching_services:
        log.warning(
            "  codeHostConnection matcher matched zero services (%s).",
            _format_matcher(cast(dict[str, object], matcher)),
        )
        return []
    matched_repos: dict[str, permission_types.Repository] = {}
    for service in matching_services:
        log.info(
            "    codeHostConnection → %s (id=%d kind=%s)",
            service["displayName"],
            src.decode_external_service_id(service["id"]),
            service["kind"],
        )
        external_service_id = src.decode_external_service_id(service["id"])
        for repo in repos_by_external_service_id.get(external_service_id, []):
            matched_repos[repo["id"]] = repo
    return list(matched_repos.values())


def _repos_matching_regexes(
    patterns: list[str], repos: list[permission_types.Repository]
) -> list[permission_types.Repository]:
    """Return repos whose name matches any pattern using Python `re`.

    Sourcegraph repo names usually omit the URL scheme (for example
    `github.com/example/repo`). To keep URL-looking operator patterns
    useful, also test `https://<repo name>`.
    """
    compiled_patterns = [re.compile(pattern) for pattern in patterns]
    matched = [
        repo
        for repo in repos
        if any(
            compiled_pattern.search(repo["name"])
            or compiled_pattern.search(f"https://{repo['name']}")
            for compiled_pattern in compiled_patterns
        )
    ]
    log.info("    regexes → %d repo(s) matched %d pattern(s)", len(matched), len(patterns))
    return matched


def _services_matching(
    services_by_id: dict[int, permission_types.ExternalService],
    matcher: permission_types.CodeHostConnectionMatcher,
) -> list[permission_types.ExternalService]:
    """AND across the supplied matcher fields. If `id` is supplied we
    short-circuit to a single candidate; remaining fields then act as a
    defensive cross-check against an ES recreated/renamed under the
    same id. Without `id`, every other supplied field is a primary
    discriminator across the full service list.
    """
    if "id" in matcher:
        single_service = services_by_id.get(matcher["id"])
        if single_service is None:
            return []
        candidates = [single_service]
    else:
        candidates = list(services_by_id.values())

    matched: list[permission_types.ExternalService] = []
    matcher_values = cast(Mapping[str, object], matcher)
    for service in candidates:
        service_values = cast(Mapping[str, object], service)
        if not all(
            field_name not in matcher_values
            or matcher_values[field_name] == service_values[field_name]
            for field_name in CODE_HOST_VALUE_MATCHES
        ):
            continue
        if "config" in matcher and not _config_subset_matches(
            matcher["config"], _parsed_service_config(service)
        ):
            continue
        matched.append(service)
    return matched


def _parsed_service_config(service: permission_types.ExternalService) -> dict[str, Any]:
    """Best-effort parse of `ExternalService.config` (JSONC string).

    Returns an empty dict if the config is missing or unparseable —
    callers treat that as "no keys to match against", so a `config:`
    matcher against such a service simply fails to match instead of
    raising. Sourcegraph's resolver returns a JSON object string, so
    parse failures here are anomalies worth not crashing on.
    """
    raw_config = service.get("config")
    if not raw_config:
        return {}
    try:
        parsed = cast(Any, json5.loads(raw_config))
    except ValueError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    return cast(dict[str, Any], parsed)


def _config_subset_matches(matcher_config: dict[str, Any], service_config: dict[str, Any]) -> bool:
    """True iff every key in `matcher_config` is present in `service_config`
    with a matching value. Nested dicts are matched recursively
    (subset semantics); lists and scalars are matched by equality.

    Sourcegraph's `REDACTED` sentinel is left as-is on the service side:
    a matcher that names a redacted key (e.g. `token`) compares against
    the literal `"REDACTED"` string and almost certainly fails to
    match — exactly the semantics we want, since the operator can't
    have known the real secret value.
    """
    for key, expected in matcher_config.items():
        if key not in service_config:
            return False
        actual = service_config[key]
        if isinstance(expected, dict) and isinstance(actual, dict):
            if not _config_subset_matches(
                cast(dict[str, Any], expected), cast(dict[str, Any], actual)
            ):
                return False
            continue
        if expected != actual:
            return False
    return True


def referenced_external_service_ids(rules: list[permission_types.MappingRule]) -> set[int]:
    """Collect all external_service IDs referenced by the mapping rules.

    Returns integer DB primary keys (the YAML-facing form). Used by
    `cmd_set` to pre-flight-warn about any IDs that the live instance
    doesn't know about, before per-mapping resolution runs.
    """
    referenced: set[int] = set()
    for rule in rules:
        repos_section = rule.get("repos") or {}
        code_host_section = repos_section.get("codeHostConnection")
        if code_host_section and "id" in code_host_section:
            referenced.add(code_host_section["id"])
    return referenced


def _format_matcher(matcher: dict[str, object]) -> str:
    """Render a matcher dict as `key1=value1 key2=value2` for log output."""
    return " ".join(f"{key}={value!r}" for key, value in matcher.items())
