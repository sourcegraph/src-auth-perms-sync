#!/usr/bin/env python3
"""Generate and optionally run maps.yaml files for memory-model sweeps.

The generated maps use exact `users.usernames` and `repos.names` filters so
each case has a known planned grant count: `users * repos`.

By default this script only generates the maps. Pass `--run` to execute the
CLI in dry-run mode. Pass `--mode apply-no-backup --allow-apply` only on a
scratch instance; that mode mutates explicit permissions.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import json
import os
import re
import shlex
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import urlsplit

import src_py_lib as src
import yaml
from src_py_lib.utils.config import load_config

QUERY_EXTERNAL_SERVICES = """
query MemoryModelExternalServices($first: Int!, $after: String) {
  externalServices(first: $first, after: $after) {
    nodes {
      id
      kind
      displayName
      repoCount
      url
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""

QUERY_USERNAMES = """
query MemoryModelUsers($first: Int!, $after: String) {
  users(first: $first, after: $after) {
    nodes { username }
    pageInfo { hasNextPage endCursor }
  }
}
"""

QUERY_USER_COUNT = """
query MemoryModelUserCount {
  users(first: 1) { totalCount }
}
"""

QUERY_REPOS_BY_EXTERNAL_SERVICE = """
query MemoryModelRepos($externalService: ID!, $first: Int!, $after: String) {
  repositories(
    first: $first
    after: $after
    externalService: $externalService
    cloned: true
    notCloned: true
  ) {
    nodes { name }
    pageInfo { hasNextPage endCursor }
  }
}
"""

DEFAULT_CASES = "auto"
DEFAULT_USER_POINTS = (1, 10, 100, 1000, 10000)
DEFAULT_REPO_POINTS = (1, 10, 100, 1000)
DEFAULT_COMMAND = "uv run src-auth-perms-sync"
LOG_PATH_PATTERN = re.compile(r"Writing log events to (.+?/log\.json)\.")
RunMode = Literal["dry-run", "apply-no-backup"]


class SweepSourcegraphConfig(src.SourcegraphClientConfig):
    """Sourcegraph connection config for discovery queries."""


@dataclass(frozen=True)
class SweepCase:
    """One users x repos planned-permissions case."""

    users: int
    repos: int

    @property
    def grants(self) -> int:
        return self.users * self.repos

    @property
    def name(self) -> str:
        return f"u{self.users:05d}-r{self.repos:05d}-g{self.grants:010d}"


@dataclass(frozen=True)
class ExternalServiceChoice:
    """Code host connection selected for repo sampling."""

    graphql_id: str
    database_id: int
    display_name: str
    kind: str
    url: str
    repo_count: int


@dataclass(frozen=True)
class GeneratedMap:
    """One generated maps.yaml file and its workload dimensions."""

    case: SweepCase
    path: Path


@dataclass(frozen=True)
class CommandRunResult:
    """One CLI execution result written in analyze-memory.py-compatible shape."""

    generated_map: GeneratedMap
    return_code: int
    elapsed_seconds: float
    output_path: Path
    log_path: Path | None
    run_record: dict[str, Any] | None


def main() -> int:
    parser = build_parser()
    arguments = parser.parse_args()
    mode = cast(RunMode, arguments.mode)
    if mode == "apply-no-backup" and not arguments.allow_apply:
        parser.error("--mode apply-no-backup requires --allow-apply")

    config = sourcegraph_config(arguments)
    output_dir = arguments.output_dir or default_output_dir(config.src_endpoint)
    maps_dir = output_dir / "maps"
    output_dir.mkdir(parents=True, exist_ok=True)
    maps_dir.mkdir(parents=True, exist_ok=True)

    requested_cases = parse_cases(arguments.cases)

    client = src.SourcegraphClient(
        endpoint=config.src_endpoint,
        token=config.src_access_token,
        http=src.HTTPClient(
            timeout=arguments.http_timeout_seconds,
            max_connections=max(4, arguments.parallelism),
        ),
    )
    try:
        external_services = list_external_services(client)
        inventory_repo_count = sum(service.repo_count for service in external_services)
        service = choose_external_service(external_services, arguments.external_service_id)
        total_user_count = count_users(client)
        cases = requested_cases or default_cases_for_inventory(
            total_user_count,
            service.repo_count,
        )
        max_users = max(sweep_case.users for sweep_case in cases)
        max_repos = max(sweep_case.repos for sweep_case in cases)
        usernames = list_usernames(client, max_users, arguments.page_size)
        repo_names = list_repo_names(client, service, max_repos, arguments.page_size)
    finally:
        client.http.close()

    generated_maps = write_maps(maps_dir, cases, usernames, repo_names, service)
    write_manifest(output_dir, generated_maps, service, config.src_endpoint, inventory_repo_count)
    print(f"Generated {len(generated_maps)} maps.yaml file(s) under {maps_dir}")
    print(
        f"Selected code host: {service.display_name} id={service.database_id} "
        f"repos={service.repo_count}; instance repoCount sum={inventory_repo_count}"
    )

    if not arguments.run:
        print("Generation only. Re-run with --run to execute the sweep.")
        return 0

    run_results = run_sweep(
        generated_maps,
        endpoint=config.src_endpoint,
        access_token=config.src_access_token,
        output_dir=output_dir,
        command=arguments.command,
        mode=mode,
        parallelism=arguments.parallelism,
        explicit_permissions_batch_size=arguments.explicit_permissions_batch_size,
        http_timeout_seconds=arguments.http_timeout_seconds,
        sample_interval=arguments.sample_interval,
        trace=arguments.trace,
        sourcegraph_user_count=total_user_count,
        sourcegraph_inventory_repo_count=inventory_repo_count,
    )
    write_results(output_dir, run_results, inventory_repo_count, total_user_count)
    return 0 if all(result.return_code == 0 for result in run_results) else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate and optionally run maps.yaml memory-model sweep cases.",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=Path(".env"),
        help="Environment file with SRC_ENDPOINT and SRC_ACCESS_TOKEN (default: .env).",
    )
    parser.add_argument("--src-endpoint", help="Override SRC_ENDPOINT for discovery and runs.")
    parser.add_argument("--src-access-token", help="Override SRC_ACCESS_TOKEN.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        help=(
            "Directory for generated maps and result files. "
            "Defaults under src-auth-perms-sync-runs/."
        ),
    )
    parser.add_argument(
        "--cases",
        default=DEFAULT_CASES,
        help=(
            "Comma-separated users x repos cases, e.g. '100x10,1000x25', "
            "or 'auto' for a gentle inventory-aware sweep. Default: auto."
        ),
    )
    parser.add_argument(
        "--external-service-id",
        type=int,
        help="Decoded external service DB id to sample repos from. Defaults to largest repoCount.",
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=1000,
        help="GraphQL page size for discovery queries (default: 1000).",
    )
    parser.add_argument(
        "--run",
        action="store_true",
        help="Run src-auth-perms-sync for each generated maps.yaml file.",
    )
    parser.add_argument(
        "--mode",
        choices=("dry-run", "apply-no-backup"),
        default="dry-run",
        help="Run mode when --run is set. Default is dry-run.",
    )
    parser.add_argument(
        "--allow-apply",
        action="store_true",
        help="Required safety acknowledgement for --mode apply-no-backup.",
    )
    parser.add_argument(
        "--command",
        default=DEFAULT_COMMAND,
        help=f"Command used to invoke the CLI (default: {DEFAULT_COMMAND!r}).",
    )
    parser.add_argument(
        "--parallelism",
        type=int,
        default=1,
        help="CLI --parallelism for sweep runs. Default 1 is gentle on pgsql.",
    )
    parser.add_argument(
        "--explicit-permissions-batch-size",
        type=int,
        default=25,
        help="CLI --explicit-permissions-batch-size for sweep runs (default: 25).",
    )
    parser.add_argument(
        "--http-timeout-seconds",
        type=float,
        default=120.0,
        help="HTTP timeout for discovery and CLI runs (default: 120).",
    )
    parser.add_argument(
        "--sample-interval",
        type=float,
        default=1.0,
        help="CLI --sample-interval for resource samples (default: 1).",
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Pass --trace to src-auth-perms-sync sweep runs.",
    )
    return parser


def sourcegraph_config(arguments: argparse.Namespace) -> SweepSourcegraphConfig:
    overrides: dict[str, object] = {}
    if arguments.src_endpoint:
        overrides["src_endpoint"] = arguments.src_endpoint
    if arguments.src_access_token:
        overrides["src_access_token"] = arguments.src_access_token
    return load_config(
        SweepSourcegraphConfig,
        env_file=arguments.env_file,
        cli_overrides=overrides,
        base_dir=Path.cwd(),
        resolve_op_refs=True,
        require=("src_access_token",),
    )


def parse_cases(raw_cases: str) -> list[SweepCase] | None:
    if raw_cases.strip().lower() == "auto":
        return None
    cases: list[SweepCase] = []
    for raw_case in raw_cases.split(","):
        case = raw_case.strip().lower()
        if not case:
            continue
        users_text, separator, repos_text = case.partition("x")
        if not separator:
            raise SystemExit(f"Invalid case {raw_case!r}; expected USERSxREPOS")
        try:
            users = int(users_text)
            repos = int(repos_text)
        except ValueError as error:
            raise SystemExit(f"Invalid case {raw_case!r}; counts must be integers") from error
        if users < 1 or repos < 1:
            raise SystemExit(f"Invalid case {raw_case!r}; counts must be >= 1")
        cases.append(SweepCase(users=users, repos=repos))
    if not cases:
        raise SystemExit("At least one --cases entry is required")
    return cases


def default_cases_for_inventory(user_count: int, repo_count: int) -> list[SweepCase]:
    """Return a safe default sweep that covers user, repo, and grant axes."""
    if user_count < 1:
        raise SystemExit("Need at least one Sourcegraph user for an auto sweep")
    if repo_count < 1:
        raise SystemExit("Need at least one Sourcegraph repo for an auto sweep")

    user_points = bounded_points(user_count, DEFAULT_USER_POINTS)
    repo_points = bounded_points(repo_count, DEFAULT_REPO_POINTS)
    cases: list[SweepCase] = [SweepCase(users=users, repos=1) for users in user_points]
    cases.extend(SweepCase(users=1, repos=repos) for repos in repo_points if repos != 1)

    for users, repos in (
        (1000, 10),
        (10000, 10),
        (1000, 100),
        (100, 1000),
    ):
        if users <= user_count and repos <= repo_count:
            cases.append(SweepCase(users=users, repos=repos))

    return unique_cases(cases)


def bounded_points(available_count: int, candidate_points: Sequence[int]) -> list[int]:
    """Return candidate points that fit, plus the exact inventory cap if useful."""
    points = [point for point in candidate_points if point <= available_count]
    if available_count not in points and available_count < candidate_points[-1]:
        points.append(available_count)
    return sorted(set(points))


def unique_cases(cases: Sequence[SweepCase]) -> list[SweepCase]:
    """Preserve case order while removing duplicates."""
    seen: set[tuple[int, int]] = set()
    unique: list[SweepCase] = []
    for sweep_case in cases:
        key = (sweep_case.users, sweep_case.repos)
        if key in seen:
            continue
        seen.add(key)
        unique.append(sweep_case)
    return unique


def list_external_services(client: src.SourcegraphClient) -> list[ExternalServiceChoice]:
    services: list[ExternalServiceChoice] = []
    for node in client.stream_connection_nodes(
        QUERY_EXTERNAL_SERVICES,
        variables={"first": 100, "after": None},
        connection_path=("externalServices",),
        page_size=100,
    ):
        service = cast(dict[str, Any], node)
        graphql_id = str(service["id"])
        services.append(
            ExternalServiceChoice(
                graphql_id=graphql_id,
                database_id=src.decode_external_service_id(graphql_id),
                display_name=str(service.get("displayName") or ""),
                kind=str(service.get("kind") or ""),
                url=str(service.get("url") or ""),
                repo_count=int(service.get("repoCount") or 0),
            )
        )
    if not services:
        raise SystemExit("No external services found on the Sourcegraph instance")
    return services


def choose_external_service(
    services: list[ExternalServiceChoice], requested_id: int | None
) -> ExternalServiceChoice:
    if requested_id is not None:
        for service in services:
            if service.database_id == requested_id:
                return service
        raise SystemExit(f"External service id {requested_id} was not found")
    return max(services, key=lambda service: service.repo_count)


def list_usernames(client: src.SourcegraphClient, count: int, page_size: int) -> list[str]:
    usernames: list[str] = []
    for node in client.stream_connection_nodes(
        QUERY_USERNAMES,
        connection_path=("users",),
        page_size=page_size,
    ):
        username = node.get("username")
        if isinstance(username, str) and username:
            usernames.append(username)
        if len(usernames) >= count:
            break
    if len(usernames) < count:
        raise SystemExit(f"Need {count} users but discovered only {len(usernames)}")
    return usernames


def count_users(client: src.SourcegraphClient) -> int:
    """Return total users on the Sourcegraph instance."""
    data = client.graphql(QUERY_USER_COUNT)
    users = cast(dict[str, Any], data.get("users") or {})
    total_count = users.get("totalCount")
    if not isinstance(total_count, int):
        raise SystemExit("CountUsers response did not include users.totalCount")
    return total_count


def list_repo_names(
    client: src.SourcegraphClient,
    service: ExternalServiceChoice,
    count: int,
    page_size: int,
) -> list[str]:
    repo_names: list[str] = []
    for node in client.stream_connection_nodes(
        QUERY_REPOS_BY_EXTERNAL_SERVICE,
        variables={"externalService": service.graphql_id},
        connection_path=("repositories",),
        page_size=page_size,
    ):
        name = node.get("name")
        if isinstance(name, str) and name:
            repo_names.append(name)
        if len(repo_names) >= count:
            break
    if len(repo_names) < count:
        raise SystemExit(
            f"Need {count} repos from external service id={service.database_id} "
            f"but discovered only {len(repo_names)}"
        )
    return repo_names


def write_maps(
    maps_dir: Path,
    cases: Sequence[SweepCase],
    usernames: Sequence[str],
    repo_names: Sequence[str],
    service: ExternalServiceChoice,
) -> list[GeneratedMap]:
    generated: list[GeneratedMap] = []
    for sweep_case in cases:
        map_path = maps_dir / f"maps-{sweep_case.name}.yaml"
        payload = {
            "maps": [
                {
                    "name": (
                        "memory model "
                        f"users={sweep_case.users} repos={sweep_case.repos} "
                        f"grants={sweep_case.grants}"
                    ),
                    "users": {"usernames": list(usernames[: sweep_case.users])},
                    "repos": {
                        "codeHostConnection": {"id": service.database_id},
                        "names": list(repo_names[: sweep_case.repos]),
                    },
                }
            ]
        }
        with map_path.open("w", encoding="utf-8") as output_file:
            output_file.write(
                "# Generated by dev/run-memory-model-sweep.py; safe to delete/regenerate.\n"
            )
            output_file.write(
                f"# users={sweep_case.users} repos={sweep_case.repos} "
                f"planned_grants={sweep_case.grants}\n"
            )
            yaml.safe_dump(payload, output_file, sort_keys=False, allow_unicode=True)
        generated.append(GeneratedMap(case=sweep_case, path=map_path))
    return generated


def write_manifest(
    output_dir: Path,
    generated_maps: Sequence[GeneratedMap],
    service: ExternalServiceChoice,
    endpoint: str,
    inventory_repo_count: int,
) -> None:
    manifest = {
        "generated_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "endpoint": endpoint,
        "external_service": service_to_json(service),
        "sourcegraph_inventory_repo_count": inventory_repo_count,
        "maps": [
            {
                "case": generated_map.case.name,
                "users": generated_map.case.users,
                "repos": generated_map.case.repos,
                "grants": generated_map.case.grants,
                "path": str(generated_map.path),
            }
            for generated_map in generated_maps
        ],
    }
    write_json(output_dir / "manifest.json", manifest)


def run_sweep(
    generated_maps: Sequence[GeneratedMap],
    *,
    endpoint: str,
    access_token: str,
    output_dir: Path,
    command: str,
    mode: RunMode,
    parallelism: int,
    explicit_permissions_batch_size: int,
    http_timeout_seconds: float,
    sample_interval: float,
    trace: bool,
    sourcegraph_user_count: int,
    sourcegraph_inventory_repo_count: int,
) -> list[CommandRunResult]:
    results: list[CommandRunResult] = []
    for generated_map in generated_maps:
        print(f"Running {generated_map.case.name} ...", flush=True)
        started = time.monotonic()
        process_output_path = output_dir / f"{generated_map.case.name}.out"
        arguments = command_arguments(
            command,
            generated_map.path,
            mode=mode,
            parallelism=parallelism,
            explicit_permissions_batch_size=explicit_permissions_batch_size,
            http_timeout_seconds=http_timeout_seconds,
            sample_interval=sample_interval,
            trace=trace,
        )
        environment = command_environment(endpoint, access_token)
        process = subprocess.run(
            arguments,
            cwd=Path.cwd(),
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        elapsed_seconds = time.monotonic() - started
        process_output_path.write_text(process.stdout, encoding="utf-8")
        log_path = log_path_from_output(process.stdout)
        run_record = read_run_record(log_path)
        result = CommandRunResult(
            generated_map=generated_map,
            return_code=process.returncode,
            elapsed_seconds=elapsed_seconds,
            output_path=process_output_path,
            log_path=log_path,
            run_record=run_record,
        )
        results.append(result)
        write_results(
            output_dir,
            results,
            inventory_repo_count=sourcegraph_inventory_repo_count,
            sourcegraph_user_count=sourcegraph_user_count,
        )
        print(
            f"  return_code={process.returncode} "
            f"peak_rss_mb={memory_peak(result.run_record)} "
            f"output={process_output_path}",
            flush=True,
        )
        if process.returncode != 0:
            print("Stopping after first failed case.", file=sys.stderr)
            break
    return results


def command_arguments(
    command: str,
    map_path: Path,
    *,
    mode: RunMode,
    parallelism: int,
    explicit_permissions_batch_size: int,
    http_timeout_seconds: float,
    sample_interval: float,
    trace: bool,
) -> list[str]:
    arguments = [
        *shlex.split(command),
        "--set",
        str(map_path.resolve()),
        "--full",
        "--parallelism",
        str(parallelism),
        "--explicit-permissions-batch-size",
        str(explicit_permissions_batch_size),
        "--http-timeout-seconds",
        f"{http_timeout_seconds:g}",
        "--sample-interval",
        f"{sample_interval:g}",
    ]
    if mode == "apply-no-backup":
        arguments.extend(("--apply", "--no-backup"))
    if trace:
        arguments.append("--trace")
    return arguments


def command_environment(endpoint: str, access_token: str) -> dict[str, str]:
    environment = dict(os.environ)
    environment["SRC_ENDPOINT"] = endpoint
    environment["SRC_ACCESS_TOKEN"] = access_token
    return environment


def log_path_from_output(output: str) -> Path | None:
    match = LOG_PATH_PATTERN.search(output)
    return Path(match.group(1)) if match else None


def read_run_record(log_path: Path | None) -> dict[str, Any] | None:
    if log_path is None or not log_path.exists():
        return None
    run_record: dict[str, Any] | None = None
    with log_path.open(encoding="utf-8") as input_file:
        for line in input_file:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            record_mapping = cast(dict[str, object], record)
            if record_mapping.get("event") == "run" and record_mapping.get("phase") == "end":
                run_record = cast(dict[str, Any], record_mapping)
    return run_record


def write_results(
    output_dir: Path,
    results: Sequence[CommandRunResult],
    inventory_repo_count: int,
    sourcegraph_user_count: int,
) -> None:
    result_payload = {
        "generated_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "results": [
            result_to_json(result, inventory_repo_count, sourcegraph_user_count)
            for result in results
        ],
        "comparisons": [],
    }
    write_json(output_dir / "results.json", result_payload)
    write_results_csv(
        output_dir / "results.csv",
        results,
        inventory_repo_count,
        sourcegraph_user_count,
    )


def result_to_json(
    result: CommandRunResult, inventory_repo_count: int, sourcegraph_user_count: int
) -> dict[str, Any]:
    run_record = result.run_record or {}
    peak_rss_mb = memory_peak(result.run_record)
    case = result.generated_map.case
    return {
        "variant": "candidate",
        "iteration": 1,
        "case": case.name,
        "arguments": ["--set", str(result.generated_map.path), "--full"],
        "return_code": result.return_code,
        "elapsed_seconds": round(result.elapsed_seconds, 3),
        "log_path": str(result.log_path) if result.log_path else None,
        "run_directory": str(result.log_path.parent) if result.log_path else None,
        "command": run_record.get("command") or "set_full",
        "status": run_record.get("status"),
        "jaeger_traces": [],
        "memory": {
            "peak_rss_mb": peak_rss_mb,
            "sampled_peak_rss_mb": None,
            "external_peak_rss_mb": None,
            "resource_sample_count": 0,
            "external_sample_count": 0,
            "max_num_fds": run_record.get("num_fds"),
            "max_num_threads": run_record.get("num_threads"),
            "max_process_cpu_percent": None,
        },
        "phase_memory": [],
        "artifact_sizes": {},
        "workload": workload_json(case, inventory_repo_count, sourcegraph_user_count),
    }


def workload_json(
    sweep_case: SweepCase, inventory_repo_count: int, sourcegraph_user_count: int
) -> dict[str, int]:
    return {
        "selected_user_count": sweep_case.users,
        "selected_repo_count": sweep_case.repos,
        "selected_total_grants": sweep_case.grants,
        "memory_model_user_count": sweep_case.users,
        "memory_model_repo_count": sweep_case.repos,
        "memory_model_grant_count": sweep_case.grants,
        "sourcegraph_user_count": sourcegraph_user_count,
        "sourcegraph_inventory_repo_count": inventory_repo_count,
    }


def write_results_csv(
    path: Path,
    results: Sequence[CommandRunResult],
    inventory_repo_count: int,
    sourcegraph_user_count: int,
) -> None:
    fieldnames = [
        "case",
        "users",
        "repos",
        "grants",
        "sourcegraph_users_discovered",
        "sourcegraph_inventory_repo_count",
        "return_code",
        "elapsed_seconds",
        "peak_rss_mb",
        "log_path",
        "map_path",
        "output_path",
    ]
    with path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            case = result.generated_map.case
            writer.writerow(
                {
                    "case": case.name,
                    "users": case.users,
                    "repos": case.repos,
                    "grants": case.grants,
                    "sourcegraph_users_discovered": sourcegraph_user_count,
                    "sourcegraph_inventory_repo_count": inventory_repo_count,
                    "return_code": result.return_code,
                    "elapsed_seconds": f"{result.elapsed_seconds:.3f}",
                    "peak_rss_mb": memory_peak(result.run_record) or "",
                    "log_path": str(result.log_path) if result.log_path else "",
                    "map_path": str(result.generated_map.path),
                    "output_path": str(result.output_path),
                }
            )


def memory_peak(run_record: Mapping[str, Any] | None) -> float | None:
    if run_record is None:
        return None
    value = run_record.get("peak_rss_mb")
    return float(value) if isinstance(value, int | float) else None


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as output_file:
        json.dump(payload, output_file, indent=2, sort_keys=True)
        output_file.write("\n")


def service_to_json(service: ExternalServiceChoice) -> dict[str, object]:
    return {
        "graphql_id": service.graphql_id,
        "database_id": service.database_id,
        "display_name": service.display_name,
        "kind": service.kind,
        "url": service.url,
        "repo_count": service.repo_count,
    }


def default_output_dir(endpoint: str) -> Path:
    host = urlsplit(endpoint).hostname or "sourcegraph"
    safe_host = re.sub(r"[^A-Za-z0-9_.-]+", "-", host)
    timestamp = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d-%H-%M-%S")
    return Path("src-auth-perms-sync-runs") / safe_host / "memory-model-sweep" / timestamp


if __name__ == "__main__":
    raise SystemExit(main())
