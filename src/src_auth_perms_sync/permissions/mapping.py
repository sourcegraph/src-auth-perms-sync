"""Permission mapping resolution: validate rules and match users/repos.

Each mapping rule has a `users:` section and a `repos:` section. Top-level
selectors under each section AND together to keep each rule restrictive.
Values inside each supplied selector list OR together. Across mapping rules,
`cmd_set` unions the per-repo user sets at apply time - see
`src/src_auth_perms_sync/permissions/types.py` for the rationale.

Adding a new matcher type:

  1. Add the TypedDict in `src/src_auth_perms_sync/permissions/types.py`.
  2. Add it as a sibling key on `UserSelector` or `RepositorySelector`.
  3. Add a branch in `resolve_users` / `resolve_repos` below.
  4. Add structural validation in `validate_mapping_rules`.
  5. Add an example rule using the new matcher to `examples/maps.yaml`.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Mapping, Sequence
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
# matcher `type` <-> AuthProvider `serviceType`).
# Discovered-provider fields that AND together inside `_providers_matching`.
# `samlGroup` is allowed under `authProvider:` too but is not a provider
# field - it filters within the matched provider's users (see
# `_users_matching_auth_provider`).
AUTH_PROVIDER_MATCHER_FIELDS: set[str] = {
    "type",
    "serviceID",
    "clientID",
    "displayName",
    "configID",
    "samlGroup",
}
CODE_HOST_MATCHER_FIELDS: set[str] = {"kind", "displayName", "url", "username"}
AUTH_PROVIDER_VALUE_MATCHES: tuple[tuple[str, str], ...] = (
    ("type", "serviceType"),
    ("serviceID", "serviceID"),
    ("clientID", "clientID"),
    ("displayName", "displayName"),
    ("configID", "configID"),
)
CODE_HOST_DIRECT_VALUE_MATCHES: tuple[str, ...] = ("kind", "displayName", "url")
USER_SELECTOR_FIELDS: set[str] = {
    "authProvider",
    "emails",
    "emailRegexes",
    "usernames",
    "usernameRegexes",
}
REPOSITORY_SELECTOR_FIELDS: set[str] = {"codeHostConnection", "names", "nameRegexes"}


# ---------------------------------------------------------------------------
# Validation (structural; cheap, runs before any GraphQL call)
# ---------------------------------------------------------------------------


def validate_mapping_rules(rules: Sequence[object]) -> None:
    """Fail fast on structural problems in the YAML before doing any work.

    Catches operator typos that would otherwise produce confusing partial
    results (or silent matches against the wrong set of users/repos)
    only after a full instance scan. Raises SystemExit with all
    collected errors at once so the operator gets one clear diagnostic
    instead of fix-one-find-the-next.

    Semantic warnings (e.g. an authProvider matcher with no fields set,
    which would match every provider on the instance) are logged at
    apply time by the resolver, not raised here - they're not always
    bugs.
    """
    errors: list[str] = []
    for rule_index, rule_object in enumerate(rules, start=1):
        if not isinstance(rule_object, dict):
            errors.append(
                f"mapping {rule_index}: each `maps:` entry must be a mapping "
                f"(got {type(rule_object).__name__})"
            )
            continue

        rule = cast(Mapping[str, object], rule_object)
        label = rule.get("name") or f"<unnamed rule #{rule_index}>"
        prefix = f"mapping {rule_index} ({label!r})"

        errors.extend(_validate_mapping_name(rule.get("name"), prefix))
        errors.extend(
            _validate_selector_section(
                rule.get("users"),
                prefix,
                "users",
                USER_SELECTOR_FIELDS,
                _validate_user_selector,
            )
        )
        errors.extend(
            _validate_selector_section(
                rule.get("repos"),
                prefix,
                "repos",
                REPOSITORY_SELECTOR_FIELDS,
                _validate_repository_selector,
            )
        )

    if errors:
        bullet = "\n  - "
        raise SystemExit(
            f"FATAL: {len(errors)} mapping configuration error(s):" + bullet + bullet.join(errors)
        )


def mapping_rules_need_user_emails(mapping_rules: list[permission_types.MappingRule]) -> bool:
    """Return whether any mapping rule filters users by verified email."""
    return any(
        "emails" in mapping["users"] or "emailRegexes" in mapping["users"]
        for mapping in mapping_rules
    )


def mapping_rules_need_saml_account_data(
    mapping_rules: list[permission_types.MappingRule],
) -> bool:
    """Return whether any mapping rule filters users by SAML group claims."""
    return any(
        bool(mapping["users"].get("authProvider", {}).get("samlGroup")) for mapping in mapping_rules
    )


def _validate_mapping_name(value: object, prefix: str) -> list[str]:
    """Validate the required human-readable mapping name."""
    if value is None:
        return [f"{prefix}: `name:` is missing"]
    if not isinstance(value, str):
        return [f"{prefix}: `name:` must be a string (got {type(value).__name__})"]
    if not value:
        return [f"{prefix}: `name:` is empty"]
    return []


def _validate_selector_section(
    value: object,
    prefix: str,
    section_name: str,
    known_fields: set[str],
    validate_selector: Callable[[dict[str, object], str, str], list[str]],
) -> list[str]:
    """Validate a top-level user or repo selector mapping."""
    if value is None:
        return [f"{prefix}: `{section_name}:` section is missing"]
    if not isinstance(value, dict):
        return [
            f"{prefix}: `{section_name}:` must be a selector mapping (got {type(value).__name__})"
        ]

    selector = cast(dict[str, object], value)
    errors: list[str] = []
    if not selector:
        errors.append(f"{prefix}: `{section_name}:` section is empty (matches nothing)")
        return errors

    for field_name in sorted(set(selector) - known_fields):
        errors.append(f"{prefix}: unknown {section_name} field {field_name!r}")
    errors.extend(validate_selector(selector, prefix, section_name))
    return errors


def _validate_user_selector(
    selector: dict[str, object], prefix: str, selector_path: str
) -> list[str]:
    """Validate one user selector's ANDed matcher fields."""
    errors: list[str] = []
    auth_provider = selector.get("authProvider")
    if auth_provider is not None:
        errors.extend(_validate_auth_provider_matcher(auth_provider, prefix, selector_path))
    if "emails" in selector:
        errors.extend(_validate_string_list(selector["emails"], prefix, f"{selector_path}.emails"))
    if "emailRegexes" in selector:
        errors.extend(
            _validate_regexes(selector["emailRegexes"], prefix, f"{selector_path}.emailRegexes")
        )
    if "usernames" in selector:
        errors.extend(
            _validate_string_list(selector["usernames"], prefix, f"{selector_path}.usernames")
        )
    if "usernameRegexes" in selector:
        errors.extend(
            _validate_regexes(
                selector["usernameRegexes"], prefix, f"{selector_path}.usernameRegexes"
            )
        )
    return errors


def _validate_repository_selector(
    selector: dict[str, object], prefix: str, selector_path: str
) -> list[str]:
    """Validate one repository selector's ANDed matcher fields."""
    errors: list[str] = []
    code_host_connection = selector.get("codeHostConnection")
    if code_host_connection is not None:
        errors.extend(
            _validate_code_host_connection_matcher(code_host_connection, prefix, selector_path)
        )
    if "names" in selector:
        errors.extend(_validate_string_list(selector["names"], prefix, f"{selector_path}.names"))
    if "nameRegexes" in selector:
        errors.extend(
            _validate_regexes(selector["nameRegexes"], prefix, f"{selector_path}.nameRegexes")
        )
    return errors


def _validate_auth_provider_matcher(value: object, prefix: str, selector_path: str) -> list[str]:
    """Validate an `authProvider:` matcher."""
    path = f"{selector_path}.authProvider"
    if not isinstance(value, dict):
        return [f"{prefix}: {path} must be a mapping (got {type(value).__name__})"]

    auth_provider = cast(dict[str, object], value)
    errors: list[str] = []
    for field_name in sorted(set(auth_provider) - AUTH_PROVIDER_MATCHER_FIELDS):
        errors.append(f"{prefix}: unknown {path} field {field_name!r}")
    if not auth_provider:
        errors.append(f"{prefix}: {path} is empty (would match every provider on the instance)")
    if "samlGroup" in auth_provider:
        errors.extend(_validate_saml_group(auth_provider, prefix, path))
    return errors


def _validate_saml_group(auth_provider: dict[str, object], prefix: str, path: str) -> list[str]:
    """`authProvider.samlGroup`, if present, must be a non-empty string and
    incompatible with a non-SAML `type:` (the rule could never match).
    """
    errors: list[str] = []
    value = auth_provider["samlGroup"]
    if not isinstance(value, str):
        errors.append(
            f"{prefix}: {path}.samlGroup must be a single group-name "
            f"string (got {type(value).__name__} {value!r}); to OR multiple "
            f"groups, add multiple top-level maps entries"
        )
    elif not value:
        errors.append(f"{prefix}: {path}.samlGroup is an empty string")
    declared_type = auth_provider.get("type")
    if (
        isinstance(declared_type, str)
        and declared_type
        and declared_type != saml_groups.SAML_SERVICE_TYPE
    ):
        errors.append(
            f"{prefix}: {path}.samlGroup is set but {path}.type "
            f"is {declared_type!r}; only SAML providers carry group claims"
        )
    return errors


def _validate_code_host_connection_matcher(
    value: object, prefix: str, selector_path: str
) -> list[str]:
    """Validate a `codeHostConnection:` matcher."""
    path = f"{selector_path}.codeHostConnection"
    if not isinstance(value, dict):
        return [f"{prefix}: {path} must be a mapping (got {type(value).__name__})"]

    code_host_section = cast(dict[str, object], value)
    errors: list[str] = []
    for field_name in sorted(set(code_host_section) - CODE_HOST_MATCHER_FIELDS):
        errors.append(f"{prefix}: unknown {path} field {field_name!r}")
    if not code_host_section:
        errors.append(
            f"{prefix}: {path} is empty (would match every external service on "
            f"the instance); supply at least one of {sorted(CODE_HOST_MATCHER_FIELDS)}"
        )
    for field_name in sorted(CODE_HOST_MATCHER_FIELDS & set(code_host_section)):
        field_value = code_host_section[field_name]
        if not isinstance(field_value, str):
            errors.append(
                f"{prefix}: {path}.{field_name} must be a string "
                f"(got {type(field_value).__name__} {field_value!r})"
            )
        elif not field_value:
            errors.append(f"{prefix}: {path}.{field_name} is an empty string")
    return errors


def _validate_regexes(value: object, prefix: str, path: str) -> list[str]:
    """Validate list-based regex filters."""
    errors = _validate_string_list(value, prefix, path)
    if errors:
        return errors

    for index, pattern in enumerate(cast(list[str], value)):
        try:
            re.compile(pattern)
        except re.error as exception:
            errors.append(f"{prefix}: {path}[{index}] is not a valid Python regex: {exception}")
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
    selector: permission_types.UserSelector,
    all_users: list[shared_types.User],
    all_providers: list[shared_types.AuthProvider],
    saml_groups_attribute_names: saml_groups.SamlGroupsAttributeNameByProvider | None = None,
) -> list[shared_types.User]:
    """Return users matching ALL top-level selectors under `users:`.

    `saml_groups_attribute_names` overrides the default `"groups"` SAML
    assertion attribute name per (serviceID, clientID) - see
    `src/src_auth_perms_sync/shared/saml_groups.py`. When
    `None`, every SAML provider falls back to the default. Only
    consulted by the `authProvider.samlGroup` sub-field.

    Empty sections return an empty user set - `validate_mapping_rules`
    rejects this at config-load time, so this branch only fires for
    programmatic callers.
    """
    if not selector:
        return []

    selector_matches: list[set[str]] = []
    auth_provider = selector.get("authProvider")
    if auth_provider is not None:
        selector_matches.append(
            {
                user["id"]
                for user in _users_matching_auth_provider(
                    auth_provider,
                    all_users,
                    all_providers,
                    saml_groups_attribute_names,
                )
            }
        )

    emails = selector.get("emails")
    if emails is not None:
        selector_matches.append(
            {user["id"] for user in _users_matching_email_values(emails, all_users)}
        )

    email_regexes = selector.get("emailRegexes")
    if email_regexes is not None:
        selector_matches.append(
            {user["id"] for user in _users_matching_email_regexes(email_regexes, all_users)}
        )

    usernames = selector.get("usernames")
    if usernames is not None:
        selector_matches.append(
            {user["id"] for user in _users_matching_username_values(usernames, all_users)}
        )

    username_regexes = selector.get("usernameRegexes")
    if username_regexes is not None:
        selector_matches.append(
            {user["id"] for user in _users_matching_username_regexes(username_regexes, all_users)}
        )

    if not selector_matches:
        return []

    matched_ids = selector_matches[0]
    for current_ids in selector_matches[1:]:
        matched_ids &= current_ids
        if not matched_ids:
            return []
    return [user for user in all_users if user["id"] in matched_ids]


def user_matches_user_selector(
    selector: permission_types.UserSelector,
    user: shared_types.User,
    all_providers: list[shared_types.AuthProvider],
    saml_groups_attribute_names: saml_groups.SamlGroupsAttributeNameByProvider | None = None,
) -> bool:
    """Return whether one user matches ALL top-level selectors under `users:`."""
    if not selector:
        return False

    auth_provider = selector.get("authProvider")
    if auth_provider is not None and not _user_matches_auth_provider(
        auth_provider,
        user,
        all_providers,
        saml_groups_attribute_names,
    ):
        return False

    emails = selector.get("emails")
    if emails is not None and not _user_matches_email(user, set(emails), []):
        return False

    email_regexes = selector.get("emailRegexes")
    if email_regexes is not None and not _user_matches_email(
        user, set(), _compiled_regexes(email_regexes)
    ):
        return False

    usernames = selector.get("usernames")
    if usernames is not None and not _text_matches(user["username"], set(usernames), []):
        return False

    username_regexes = selector.get("usernameRegexes")
    if username_regexes is None:
        return True
    return _text_matches(user["username"], set(), _compiled_regexes(username_regexes))


def _users_matching_email_values(
    emails: list[str], all_users: list[shared_types.User]
) -> list[shared_types.User]:
    """Return users with at least one verified email equal to a listed email."""
    exact_values = set(emails)
    matched = [user for user in all_users if _user_matches_email(user, exact_values, [])]
    log.info(
        "    emails -> %d user(s) matched %d email selector(s)",
        len(matched),
        len(exact_values),
    )
    return matched


def _users_matching_email_regexes(
    email_regexes: list[str], all_users: list[shared_types.User]
) -> list[shared_types.User]:
    """Return users with at least one verified email matching a listed regex."""
    patterns = _compiled_regexes(email_regexes)
    matched = [user for user in all_users if _user_matches_email(user, set(), patterns)]
    log.info(
        "    emailRegexes -> %d user(s) matched %d email regex selector(s)",
        len(matched),
        len(set(email_regexes)),
    )
    return matched


def _user_matches_email(
    user: shared_types.User, exact_values: set[str], patterns: list[re.Pattern[str]]
) -> bool:
    """Match only verified emails, mirroring Sourcegraph's `user(email:)` lookup."""
    return any(
        user_email["verified"] and _text_matches(user_email["email"], exact_values, patterns)
        for user_email in user.get("emails", [])
    )


def _users_matching_username_values(
    usernames: list[str], all_users: list[shared_types.User]
) -> list[shared_types.User]:
    """Return users whose Sourcegraph username equals a listed username."""
    exact_values = set(usernames)
    matched = [user for user in all_users if _text_matches(user["username"], exact_values, [])]
    log.info(
        "    usernames -> %d user(s) matched %d username selector(s)",
        len(matched),
        len(exact_values),
    )
    return matched


def _users_matching_username_regexes(
    username_regexes: list[str], all_users: list[shared_types.User]
) -> list[shared_types.User]:
    """Return users whose Sourcegraph username matches a listed regex."""
    patterns = _compiled_regexes(username_regexes)
    matched = [user for user in all_users if _text_matches(user["username"], set(), patterns)]
    log.info(
        "    usernameRegexes -> %d user(s) matched %d username regex selector(s)",
        len(matched),
        len(set(username_regexes)),
    )
    return matched


def _compiled_regexes(regexes: list[str]) -> list[re.Pattern[str]]:
    """Return compiled regexes."""
    return [re.compile(pattern) for pattern in regexes]


def _text_matches(value: str, exact_values: set[str], patterns: list[re.Pattern[str]]) -> bool:
    """Return whether text matches exact values or any regex."""
    if value in exact_values:
        return True
    return any(pattern.search(value) for pattern in patterns)


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
            "    authProvider -> %s (type=%s serviceID=%s clientID=%s)",
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
            "    samlGroup -> %d user(s) in group %r",
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
    selector: permission_types.RepositorySelector,
    services_by_id: dict[int, permission_types.ExternalService],
    repos_by_external_service_id: dict[int, list[permission_types.Repository]],
    all_repos_by_id: dict[str, permission_types.Repository],
) -> list[permission_types.Repository]:
    """Return repos matching ALL top-level selectors under `repos:`.

    Empty sections return an empty repo set; `validate_mapping_rules`
    rejects this at config-load time.
    """
    if not selector:
        return []

    selector_matches: list[set[str]] = []
    repo_index = dict(all_repos_by_id)
    candidate_repos = list(all_repos_by_id.values())
    code_host_connection = selector.get("codeHostConnection")
    if code_host_connection is not None:
        repos = _repos_matching_code_host_connection(
            code_host_connection,
            services_by_id,
            repos_by_external_service_id,
        )
        repo_index.update({repo["id"]: repo for repo in repos})
        candidate_repos = repos
        selector_matches.append({repo["id"] for repo in repos})

    names = selector.get("names")
    if names is not None:
        selector_matches.append(_repo_ids_matching_names(names, candidate_repos))

    name_regexes = selector.get("nameRegexes")
    if name_regexes is not None:
        selector_matches.append(_repo_ids_matching_name_regexes(name_regexes, candidate_repos))

    if not selector_matches:
        return []

    matched_ids = selector_matches[0]
    for current_ids in selector_matches[1:]:
        matched_ids &= current_ids
        if not matched_ids:
            return []
    return [repo for repo in repo_index.values() if repo["id"] in matched_ids]


def _repo_ids_matching_names(
    names: list[str], repos: list[permission_types.Repository]
) -> set[str]:
    """Return repo IDs whose Sourcegraph name equals a listed name."""
    exact_values = set(names)
    matched = {repo["id"] for repo in repos if _repo_name_matches(repo["name"], exact_values, [])}
    log.info(
        "    names -> %d repo(s) matched %d name selector(s)",
        len(matched),
        len(exact_values),
    )
    return matched


def _repo_ids_matching_name_regexes(
    name_regexes: list[str], repos: list[permission_types.Repository]
) -> set[str]:
    """Return repo IDs whose Sourcegraph name matches a listed regex."""
    patterns = _compiled_regexes(name_regexes)
    matched = {repo["id"] for repo in repos if _repo_name_matches(repo["name"], set(), patterns)}
    log.info(
        "    nameRegexes -> %d repo(s) matched %d name regex selector(s)",
        len(matched),
        len(set(name_regexes)),
    )
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
            "    codeHostConnection -> %s (id=%d kind=%s)",
            service["displayName"],
            src.decode_external_service_id(service["id"]),
            service["kind"],
        )
        external_service_id = src.decode_external_service_id(service["id"])
        for repo in repos_by_external_service_id.get(external_service_id, []):
            matched_repos[repo["id"]] = repo
    return list(matched_repos.values())


def service_ids_required_by_repository_selectors(
    services_by_id: dict[int, permission_types.ExternalService],
    selectors: Sequence[permission_types.RepositorySelector],
) -> set[int]:
    """Return code-host service IDs whose repos may match the selectors.

    A selector without `codeHostConnection` can match any code host, so the
    caller must load every service. Selectors with `codeHostConnection` narrow
    the repo scan to only services matching that matcher.
    """
    required_service_ids: set[int] = set()
    for selector in selectors:
        matcher = selector.get("codeHostConnection")
        if matcher is None:
            return set(services_by_id)
        for service in _services_matching(services_by_id, matcher):
            required_service_ids.add(src.decode_external_service_id(service["id"]))
    return required_service_ids


def _repo_name_matches(
    repository_name: str, exact_values: set[str], patterns: list[re.Pattern[str]]
) -> bool:
    """Return whether a repo name matches exact values or regexes.

    Sourcegraph repo names usually omit the URL scheme (for example
    `github.com/example/repo`). To keep URL-looking operator regexes useful,
    also test `https://<repo name>` for regex matches. Exact matches remain
    exact Sourcegraph repo names.
    """
    if repository_name in exact_values:
        return True
    return any(
        pattern.search(repository_name) or pattern.search(f"https://{repository_name}")
        for pattern in patterns
    )


def _services_matching(
    services_by_id: dict[int, permission_types.ExternalService],
    matcher: permission_types.CodeHostConnectionMatcher,
) -> list[permission_types.ExternalService]:
    """AND across the supplied human-readable code-host matcher fields."""
    matched: list[permission_types.ExternalService] = []
    matcher_values = cast(Mapping[str, object], matcher)
    for service in services_by_id.values():
        service_values = cast(Mapping[str, object], service)
        if not all(
            field_name not in matcher_values
            or matcher_values[field_name] == service_values[field_name]
            for field_name in CODE_HOST_DIRECT_VALUE_MATCHES
        ):
            continue
        if "username" in matcher and matcher["username"] != _service_username(service):
            continue
        matched.append(service)
    return matched


def _parsed_service_config(service: permission_types.ExternalService) -> dict[str, Any]:
    """Best-effort parse of `ExternalService.config` (JSONC string)."""
    raw_config = service.get("config")
    if not raw_config:
        return {}
    try:
        parsed = json5.loads(raw_config)
    except ValueError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    return cast(dict[str, Any], parsed)


def _service_username(service: permission_types.ExternalService) -> str | None:
    """Return the code-host username from `ExternalService.config`, if present."""
    username = _parsed_service_config(service).get("username")
    return username if isinstance(username, str) else None


def _format_matcher(matcher: dict[str, object]) -> str:
    """Render a matcher dict as `key1=value1 key2=value2` for log output."""
    return " ".join(f"{key}={value!r}" for key, value in matcher.items())
