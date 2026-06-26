"""Shared helpers for repo permission command workflows."""

from __future__ import annotations

import datetime
import logging
from collections.abc import Iterator
from pathlib import Path

import src_py_lib as src

from ..shared import backups, saml_groups
from ..shared import sourcegraph as shared_sourcegraph
from ..shared import types as shared_types
from . import mapping as permissions_mapping
from . import maps as permissions_maps
from . import snapshot as permission_snapshot
from . import sourcegraph as permissions_sourcegraph
from . import types as permission_types

log = logging.getLogger(__name__)


def load_discovery(
    client: src.SourcegraphClient,
    saml_groups_attribute_name_by_config_id: dict[str, str],
) -> tuple[
    list[shared_types.AuthProvider],
    list[permission_types.ExternalService],
    dict[tuple[str, str], str],
]:
    """Fetch auth providers + code hosts and resolve the SAML attribute
    names map, with consistent logging. Shared by get and set; returns the
    raw lists so each caller can transform them as needed (YAML form for get,
    keyed-by-id dict for set).

    Both commands need exactly the same instance state to do their work, so
    centralizing this avoids drift in which providers/services are considered
    authoritative or how the per-provider SAML attribute override map is
    resolved.
    """
    log.info("Querying auth providers from %s ...", client.endpoint)
    providers = shared_sourcegraph.list_auth_providers(client)
    log.info("Received %d auth providers.", len(providers))

    log.info("Querying code hosts from %s ...", client.endpoint)
    services = permissions_sourcegraph.list_external_services(client)
    log.info("Received %d code hosts.", len(services))

    saml_attribute_names = saml_groups.attribute_names_by_provider_key(
        providers, saml_groups_attribute_name_by_config_id
    )
    return providers, services, saml_attribute_names


def load_repos_by_external_service(
    client: src.SourcegraphClient,
    services_by_id: dict[int, permission_types.ExternalService],
) -> dict[int, list[permission_types.Repository]]:
    """Fetch repos once per discovered code host connection."""
    with src.span(
        "load_repos_by_external_service",
        external_service_count=len(services_by_id),
    ) as load_event:
        expected_repo_count = sum(service["repoCount"] for service in services_by_id.values())
        load_event["expected_repo_count"] = expected_repo_count
        log.info(
            "Loading about %d repo(s) across %d code host connection(s) ...",
            expected_repo_count,
            len(services_by_id),
        )

        repos_by_external_service_id: dict[int, list[permission_types.Repository]] = {}
        total_repos = 0
        for external_service_id in sorted(services_by_id):
            service = services_by_id[external_service_id]
            repos = permissions_sourcegraph.list_repos_for_external_service(client, service["id"])
            repos_by_external_service_id[external_service_id] = repos
            total_repos += len(repos)
            log.info(
                "Received %d repo(s) for code host connection %s (id=%d).",
                len(repos),
                service["displayName"],
                external_service_id,
            )
        load_event["repo_count"] = total_repos
        return repos_by_external_service_id


def index_repos_by_id(
    repos_by_external_service_id: dict[int, list[permission_types.Repository]],
) -> dict[str, permission_types.Repository]:
    repos_by_id: dict[str, permission_types.Repository] = {}
    for repos in repos_by_external_service_id.values():
        for repo in repos:
            repos_by_id[repo["id"]] = repo
    return repos_by_id


def load_mapping_rules(input_path: Path) -> list[permission_types.MappingRule]:
    """Load and structurally validate mapping rules from YAML."""
    config = permissions_maps.load_maps_yaml(input_path)
    mapping_rules = config.get("maps") or []
    if mapping_rules:
        permissions_mapping.validate_mapping_rules(mapping_rules)
    return mapping_rules


def resolve_mapping_rules(
    provided_rules: list[permission_types.MappingRule] | None,
    maps_path: Path,
) -> list[permission_types.MappingRule]:
    """Return validated in-memory mapping rules, or load them from the maps file.

    In-memory rules go through the same structural validation as rules read
    from YAML, so module callers and CLI operators share one contract.
    """
    if provided_rules is None:
        return load_mapping_rules(maps_path)
    if provided_rules:
        permissions_mapping.validate_mapping_rules(provided_rules)
    return provided_rules


def load_mapping_context(
    client: src.SourcegraphClient,
    input_path: Path,
    saml_groups_attribute_name_by_config_id: dict[str, str],
) -> permission_types.MappingContext | None:
    """Load maps, providers, services, and repos for permission planning."""
    mapping_rules = load_mapping_rules(input_path)
    if not mapping_rules:
        log.warning("No maps defined in %s - nothing to do.", input_path)
        return None

    return load_mapping_context_for_rules(
        client,
        mapping_rules,
        saml_groups_attribute_name_by_config_id,
    )


def load_mapping_context_for_rules(
    client: src.SourcegraphClient,
    mapping_rules: list[permission_types.MappingRule],
    saml_groups_attribute_name_by_config_id: dict[str, str],
) -> permission_types.MappingContext:
    """Load providers, services, repos, and warning context for mapping rules."""
    providers, services, saml_groups_attribute_names = load_discovery(
        client, saml_groups_attribute_name_by_config_id
    )
    services_by_id: dict[int, permission_types.ExternalService] = {
        src.decode_external_service_id(service["id"]): service for service in services
    }
    repos_by_external_service_id = load_repos_by_external_service(client, services_by_id)
    all_repos_by_id = index_repos_by_id(repos_by_external_service_id)
    log.info(
        "Received %d unique repo(s) across %d code host connection(s).",
        len(all_repos_by_id),
        len(services_by_id),
    )
    return permission_types.MappingContext(
        mapping_rules=mapping_rules,
        providers=providers,
        saml_groups_attribute_names=saml_groups_attribute_names,
        services_by_id=services_by_id,
        repos_by_external_service_id=repos_by_external_service_id,
        all_repos_by_id=all_repos_by_id,
    )


def load_mapping_context_discovery(
    client: src.SourcegraphClient,
    mapping_rules: list[permission_types.MappingRule],
    saml_groups_attribute_name_by_config_id: dict[str, str],
) -> permission_types.MappingContext:
    """Load provider and code-host metadata without scanning repos."""
    providers, services, saml_groups_attribute_names = load_discovery(
        client, saml_groups_attribute_name_by_config_id
    )
    services_by_id: dict[int, permission_types.ExternalService] = {
        src.decode_external_service_id(service["id"]): service for service in services
    }
    return permission_types.MappingContext(
        mapping_rules=mapping_rules,
        providers=providers,
        saml_groups_attribute_names=saml_groups_attribute_names,
        services_by_id=services_by_id,
        repos_by_external_service_id={},
        all_repos_by_id={},
    )


def load_repos_for_mapping_context(
    client: src.SourcegraphClient,
    context: permission_types.MappingContext,
    service_ids: set[int] | None = None,
) -> permission_types.MappingContext:
    """Return context with repos loaded for all or selected code hosts."""
    services_by_id = (
        context.services_by_id
        if service_ids is None
        else {
            service_id: context.services_by_id[service_id]
            for service_id in sorted(service_ids)
            if service_id in context.services_by_id
        }
    )
    repos_by_external_service_id = {
        **context.repos_by_external_service_id,
        **load_repos_by_external_service(client, services_by_id),
    }
    all_repos_by_id = index_repos_by_id(repos_by_external_service_id)
    log.info(
        "Received %d unique repo(s) across %d loaded code host connection(s).",
        len(all_repos_by_id),
        len(repos_by_external_service_id),
    )
    return permission_types.MappingContext(
        mapping_rules=context.mapping_rules,
        providers=context.providers,
        saml_groups_attribute_names=context.saml_groups_attribute_names,
        services_by_id=context.services_by_id,
        repos_by_external_service_id=repos_by_external_service_id,
        all_repos_by_id=all_repos_by_id,
    )


def mapping_context_with_repository_candidates(
    context: permission_types.MappingContext,
    candidates: list[permissions_sourcegraph.RepositoryCandidate],
) -> permission_types.MappingContext:
    """Return context limited to selected repository candidates."""
    repos_by_external_service_id: dict[int, list[permission_types.Repository]] = {}
    all_repos_by_id: dict[str, permission_types.Repository] = {}
    for candidate in candidates:
        repository = candidate.repository
        all_repos_by_id[repository["id"]] = repository
        for external_service_id in candidate.external_service_ids:
            decoded_service_id = src.decode_external_service_id(external_service_id)
            if decoded_service_id not in context.services_by_id:
                continue
            repos_by_external_service_id.setdefault(decoded_service_id, []).append(repository)
    log.info(
        "Selected %d repo(s) across %d code host connection(s).",
        len(all_repos_by_id),
        len(repos_by_external_service_id),
    )
    return permission_types.MappingContext(
        mapping_rules=context.mapping_rules,
        providers=context.providers,
        saml_groups_attribute_names=context.saml_groups_attribute_names,
        services_by_id=context.services_by_id,
        repos_by_external_service_id=repos_by_external_service_id,
        all_repos_by_id=all_repos_by_id,
    )


def load_repository_candidates_by_names(
    client: src.SourcegraphClient,
    repository_names: tuple[str, ...],
) -> list[permissions_sourcegraph.RepositoryCandidate]:
    """Load exact repository-name matches or exit with missing names."""
    candidates = permissions_sourcegraph.list_repository_candidates_by_names(
        client,
        repository_names,
    )
    found_names = {candidate.repository["name"] for candidate in candidates}
    missing_names = [name for name in repository_names if name not in found_names]
    if missing_names:
        raise SystemExit("No Sourcegraph repo found for: " + ", ".join(sorted(missing_names)))
    log.info("Selected %d repo(s) by exact name.", len(candidates))
    return candidates


def load_repository_candidates_created_on_or_after(
    client: src.SourcegraphClient,
    value: str,
    flag_name: str,
) -> list[permissions_sourcegraph.RepositoryCandidate]:
    """Load repositories whose Sourcegraph row was created on or after a CLI date."""
    filter_value = sourcegraph_datetime_filter(parse_cli_date(value, flag_name))
    candidates = permissions_sourcegraph.list_repository_candidates_created_on_or_after(
        client,
        filter_value,
    )
    log.info(
        "Selected %d Sourcegraph repo(s) created on or after %s.",
        len(candidates),
        value,
    )
    return candidates


def write_snapshot_pair(
    run_paths: backups.RunPaths,
    before_snapshot: permission_snapshot.Snapshot,
    after_snapshot: permission_snapshot.Snapshot,
) -> tuple[Path, Path, Path]:
    before_path = run_paths.artifact_path("before")
    after_path = run_paths.artifact_path("after")
    permission_snapshot.write_snapshot(before_path, before_snapshot)
    permission_snapshot.write_snapshot(after_path, after_snapshot)
    diff_path = write_snapshot_diff_file(run_paths, before_snapshot, after_snapshot)
    return before_path, after_path, diff_path


def write_snapshot_diff_file(
    run_paths: backups.RunPaths,
    before_snapshot: permission_snapshot.Snapshot,
    after_snapshot: permission_snapshot.Snapshot,
) -> Path:
    diff_path = run_paths.artifact_path("diff")
    permission_snapshot.write_snapshot_diff_from_snapshots(
        diff_path,
        before_snapshot,
        after_snapshot,
    )
    return diff_path


def write_user_scoped_snapshot_diff_file(
    run_paths: backups.RunPaths,
    before_snapshot: permission_snapshot.UserScopedSnapshot,
    after_snapshot: permission_snapshot.UserScopedSnapshot,
) -> Path:
    diff_path = run_paths.artifact_path("diff")
    permission_snapshot.write_user_scoped_snapshot_diff(
        diff_path,
        permission_snapshot.build_user_scoped_snapshot_diff(before_snapshot, after_snapshot),
    )
    return diff_path


def write_maps_backup(input_path: Path, run_paths: backups.RunPaths) -> Path | None:
    """Copy the run's input file next to the JSON snapshots for auditability."""
    if not run_paths.write_files:
        return None
    if not input_path.exists():
        log.warning("Could not back up maps file %s because it does not exist.", input_path)
        return None

    output_path = run_paths.input_copy_path(input_path.name)
    with src.span(
        "disk_io",
        level="DEBUG",
        op="write",
        path=str(output_path),
        file_kind="yaml",
    ) as disk_event:
        contents = input_path.read_bytes()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(contents)
        disk_event["bytes"] = len(contents)
    log.info("Wrote maps backup: %s", output_path)
    return output_path


def projected_snapshot_repo_ids(
    before_snapshot: permission_snapshot.Snapshot,
    expected_users: dict[str, tuple[str, ...]],
) -> list[str]:
    """Return repo IDs that may appear in a projected full-set after snapshot."""
    return sorted(set(before_snapshot["repos"]) | set(expected_users))


def projected_snapshot_repo_for_id(
    before_snapshot: permission_snapshot.Snapshot,
    expected_users: dict[str, tuple[str, ...]],
    repo_names: dict[str, str],
    repo_id: str,
) -> permission_snapshot.RepoSnapshot | None:
    """Return one projected repo snapshot without cloning the whole snapshot."""
    if repo_id in expected_users:
        usernames = expected_users[repo_id]
        if not usernames:
            return None
        return {
            "name": repo_names[repo_id],
            "users": list(usernames),
        }
    return before_snapshot["repos"].get(repo_id)


def projected_snapshot_repos(
    before_snapshot: permission_snapshot.Snapshot,
    expected_users: dict[str, tuple[str, ...]],
    repo_names: dict[str, str],
) -> Iterator[tuple[str, permission_snapshot.RepoSnapshot]]:
    """Return projected repo entries one repo at a time in stable order."""
    for repo_id in projected_snapshot_repo_ids(before_snapshot, expected_users):
        repo = projected_snapshot_repo_for_id(
            before_snapshot,
            expected_users,
            repo_names,
            repo_id,
        )
        if repo is not None:
            yield repo_id, repo


def projected_snapshot_stats(
    before_snapshot: permission_snapshot.Snapshot,
    expected_users: dict[str, tuple[str, ...]],
) -> permission_snapshot.SnapshotStats:
    """Compute projected stats without materializing the projected snapshot."""
    users_with_explicit_grants: set[str] = set()
    total_grants = 0
    repo_count = 0
    for repo_id, repo in before_snapshot["repos"].items():
        if repo_id in expected_users:
            continue
        repo_count += 1
        usernames = repo["users"]
        users_with_explicit_grants.update(usernames)
        total_grants += len(usernames)
    for usernames in expected_users.values():
        if not usernames:
            continue
        repo_count += 1
        users_with_explicit_grants.update(usernames)
        total_grants += len(usernames)
    return {
        "total_users_scanned": before_snapshot["stats"]["total_users_scanned"],
        "users_with_explicit_grants": len(users_with_explicit_grants),
        "repos_with_explicit_grants": repo_count,
        "total_grants": total_grants,
    }


def projected_snapshot_shell(
    before_snapshot: permission_snapshot.Snapshot,
    expected_users: dict[str, tuple[str, ...]],
) -> permission_snapshot.Snapshot:
    """Return projected snapshot metadata; repo entries are streamed separately."""
    return {
        "schema_version": before_snapshot["schema_version"],
        "captured_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "endpoint": before_snapshot["endpoint"],
        "bindID_mode": before_snapshot["bindID_mode"],
        "config_file": before_snapshot["config_file"],
        "config_sha256": before_snapshot["config_sha256"],
        # Full-set overwrites preserve pending grants, so the projection
        # carries them through unchanged.
        "pending_users": dict(before_snapshot["pending_users"]),
        "stats": projected_snapshot_stats(before_snapshot, expected_users),
        "repos": {},
    }


def write_projected_snapshot(
    path: Path,
    before_snapshot: permission_snapshot.Snapshot,
    expected_users: dict[str, tuple[str, ...]],
    repo_names: dict[str, str],
) -> permission_snapshot.Snapshot:
    """Write a projected full-set after snapshot without holding it in memory."""
    after_snapshot = projected_snapshot_shell(before_snapshot, expected_users)
    permission_snapshot.write_snapshot_with_repos(
        path,
        after_snapshot,
        projected_snapshot_repos(before_snapshot, expected_users, repo_names),
    )
    return after_snapshot


def write_projected_snapshot_diff_file(
    run_paths: backups.RunPaths,
    before_snapshot: permission_snapshot.Snapshot,
    after_snapshot: permission_snapshot.Snapshot,
    expected_users: dict[str, tuple[str, ...]],
    repo_names: dict[str, str],
) -> Path:
    """Write a diff for a projected full-set after snapshot."""
    diff_path = run_paths.artifact_path("diff")
    repo_ids = projected_snapshot_repo_ids(before_snapshot, expected_users)
    permission_snapshot.write_snapshot_diff_from_snapshot_parts(
        diff_path,
        before_snapshot,
        after_snapshot,
        repo_ids,
        lambda repo_id: projected_snapshot_repo_for_id(
            before_snapshot,
            expected_users,
            repo_names,
            repo_id,
        ),
    )
    return diff_path


def render_projected_snapshot_diff(
    before_snapshot: permission_snapshot.Snapshot,
    after_snapshot: permission_snapshot.Snapshot,
    expected_users: dict[str, tuple[str, ...]],
    repo_names: dict[str, str],
) -> str:
    """Render a capped diff for a projected full-set after snapshot."""
    repo_ids = projected_snapshot_repo_ids(before_snapshot, expected_users)
    return permission_snapshot.render_snapshot_diff_from_snapshot_parts(
        before_snapshot,
        after_snapshot,
        repo_ids,
        lambda repo_id: projected_snapshot_repo_for_id(
            before_snapshot,
            expected_users,
            repo_names,
            repo_id,
        ),
    )


def validate_post_apply(
    after: permission_snapshot.Snapshot,
    expected_users: dict[str, tuple[str, ...]],
    mutated_repo_ids: set[str],
    expected_pending_users: dict[str, list[permission_types.Repository]] | None = None,
) -> None:
    """Post-apply sanity gates. Each failure WARNs/ERRORs but does not raise.

    1. Pending bindIDs: any username we just wrote that didn't resolve to a
       real User now appears in `usersWithPendingPermissions`. In our use
       case this should never happen - we enumerate users via the users
       query before mutating - but it's a cheap safety net.

    2. Per-repo expected vs. actual: for every repo we touched, the
       after-snapshot's explicit-user list must equal the union we asked
       for. Disagreement means a partial write, a concurrent mutation by
       another tool, or a server-side bug.

    3. Pending preservation: overwrites resend each repo's pending bindIDs,
       so the after-state's pending grants must match
       `expected_pending_users` (when supplied). A pending bindID may
       legitimately vanish by becoming a real user mid-run.
    """
    requested_usernames: set[str] = set()
    for usernames in expected_users.values():
        requested_usernames.update(usernames)
    pending = set(after["pending_users"])
    stuck = sorted(requested_usernames & pending)
    if stuck:
        log.error(
            "VALIDATION: %d bindID(s) we just wrote did NOT resolve to "
            "real users (now pending): %s",
            len(stuck),
            ", ".join(stuck),
        )

    if expected_pending_users is not None:
        _warn_on_pending_grant_drift(expected_pending_users, after["pending_users"])

    mismatches = 0
    for repo_id in mutated_repo_ids:
        expected = list(expected_users.get(repo_id, ()))
        actual_repo = after["repos"].get(repo_id)
        actual = actual_repo["users"] if actual_repo else []
        if expected == actual:
            continue
        expected_set = set(expected)
        actual_set = set(actual)
        mismatches += 1
        only_expected = sorted(expected_set - actual_set)
        only_actual = sorted(actual_set - expected_set)
        log.warning(
            "VALIDATION MISMATCH on repo id=%d: expected %d users, got %d.  "
            "Expected-but-missing: %s.  Actual-but-unexpected: %s.",
            src.decode_repository_id(repo_id),
            len(expected),
            len(actual),
            only_expected or "(none)",
            only_actual or "(none)",
        )
    if mismatches:
        log.warning(
            "VALIDATION: %d / %d mutated repo(s) do not reflect the requested state.",
            mismatches,
            len(mutated_repo_ids),
        )
    else:
        log.info(
            "VALIDATION OK: all %d mutated repo(s) match the requested explicit-permissions state.",
            len(mutated_repo_ids),
        )


def _warn_on_pending_grant_drift(
    expected_pending_users: dict[str, list[permission_types.Repository]],
    actual_pending_users: dict[str, list[permission_types.Repository]],
) -> None:
    """Warn when pending grants were not preserved exactly as expected."""
    drifted: list[str] = []
    for bind_id in sorted(set(expected_pending_users) | set(actual_pending_users)):
        expected_repo_ids = {
            repository["id"] for repository in expected_pending_users.get(bind_id, [])
        }
        actual_repo_ids = {repository["id"] for repository in actual_pending_users.get(bind_id, [])}
        if expected_repo_ids != actual_repo_ids:
            drifted.append(bind_id)
    if drifted:
        log.warning(
            "VALIDATION: pending grants for %d bindID(s) do not match the "
            "expected preserved state (a pending user signing in mid-run "
            "also causes this): %s",
            len(drifted),
            ", ".join(drifted),
        )


def parse_cli_date(value: str, flag_name: str) -> datetime.datetime:
    """Parse and validate a CLI date argument, returning UTC midnight."""
    if len(value) != 10 or value[4] != "-" or value[7] != "-":
        raise SystemExit(f"{flag_name} must use YYYY-MM-DD, got {value!r}.")
    try:
        parsed_date = datetime.date.fromisoformat(value)
    except ValueError as error:
        raise SystemExit(f"{flag_name} must use YYYY-MM-DD, got {value!r}.") from error
    return datetime.datetime.combine(parsed_date, datetime.time(), tzinfo=datetime.UTC)


def sourcegraph_datetime_filter(value: datetime.datetime) -> str:
    """Return a Sourcegraph DateTime filter string for a UTC datetime."""
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def user_ids_created_on_or_after(client: src.SourcegraphClient, value: str) -> set[str]:
    """Return Sourcegraph user IDs created on or after the given CLI date."""
    filter_value = sourcegraph_datetime_filter(parse_cli_date(value, "--users-created-after"))
    candidates = permissions_sourcegraph.list_site_user_candidates(client, filter_value)
    log.info(
        "Restricting to %d Sourcegraph user(s) created on or after %s.",
        len(candidates),
        value,
    )
    return {candidate["id"] for candidate in candidates}
