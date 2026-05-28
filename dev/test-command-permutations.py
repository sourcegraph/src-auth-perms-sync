#!/usr/bin/env python3
"""Run auth-perms-sync command permutations and assert expected outcomes.

This is an integration smoke runner for a real Sourcegraph test instance. It
uses the same CLI entrypoint an operator uses (`uv run auth-perms-sync`) and
checks both process exit codes and structured `run` log records.

The script runs every case: read-only, dry-run, invalid-argument, no-op apply,
mutating apply, and full overwrite/restore. Mutating cases are refused outside
test-looking endpoints unless explicitly allowed.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import json
import os
import re
import shlex
import statistics
import subprocess
import sys
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

LOG_PATH_PATTERN = re.compile(r"Writing log events to (.+?/log\.json)\.")
DEFAULT_FUTURE_DATE = "2099-01-01"
REMOVED_AUTH_PERMS_SYNC_ENVIRONMENT_PREFIX = "AUTH_PERMS_SYNC_"
DEFAULT_SAMPLE_INTERVAL_SECONDS = 1.0
DEFAULT_REPEAT_COUNT = 1
WORKLOAD_FIELDS = (
    "user_count",
    "total_users",
    "total_users_scanned",
    "repo_count",
    "repos_with_explicit_grants",
    "total_grants",
    "mapping_count",
    "plan_size",
    "payload_count",
    "target_organizations",
    "desired_memberships",
    "mutations_succeeded",
    "mutations_failed",
    "mutations_canceled",
)


@dataclass(frozen=True)
class CommandCase:
    """One CLI invocation and the conditions it must satisfy."""

    name: str
    arguments: tuple[str, ...]
    expected_exit_code: int = 0
    expected_log_command: str | None = None
    expected_log_status: str | None = "ok"
    must_contain: tuple[str, ...] = ()
    must_contain_one_of: tuple[str, ...] = ()
    must_not_contain: tuple[str, ...] = ()


@dataclass(frozen=True)
class CommandResult:
    """Captured result for one CLI invocation."""

    variant: str
    iteration: int
    case: CommandCase
    return_code: int
    output: str
    log_path: Path | None
    run_directory: Path | None
    run_record: dict[str, Any] | None
    memory: MemorySummary | None
    phase_memory: list[PhaseMemorySummary]
    artifact_sizes: dict[str, int]
    workload: dict[str, int | float | str]
    elapsed_seconds: float


@dataclass(frozen=True)
class MemorySummary:
    """Resource usage extracted from structured run logs."""

    peak_rss_mb: float | None
    sampled_peak_rss_mb: float | None
    external_peak_rss_mb: float | None
    resource_sample_count: int
    external_sample_count: int
    max_num_fds: int | None
    max_num_threads: int | None
    max_process_cpu_percent: float | None


@dataclass(frozen=True)
class PhaseMemorySummary:
    """Peak RSS observed while one structured event span was active."""

    event: str
    stage: str | None
    peak_rss_mb: float
    sample_count: int
    total_duration_ms: int


@dataclass(frozen=True)
class RunVariant:
    """One executable variant to run through the matrix."""

    name: str
    executable: tuple[str, ...]


@dataclass(frozen=True)
class SpanInterval:
    """One structured event span reconstructed from log start/end records."""

    event: str
    stage: str | None
    started_at: datetime.datetime
    ended_at: datetime.datetime
    duration_ms: int


@dataclass(frozen=True)
class CaseComparison:
    """Median baseline/candidate measurements for one command case."""

    case_name: str
    baseline_count: int
    candidate_count: int
    baseline_peak_rss_mb: float | None
    candidate_peak_rss_mb: float | None
    peak_rss_delta_mb: float | None
    peak_rss_delta_percent: float | None
    baseline_external_peak_rss_mb: float | None
    candidate_external_peak_rss_mb: float | None
    external_peak_rss_delta_mb: float | None
    external_peak_rss_delta_percent: float | None
    baseline_elapsed_seconds: float | None
    candidate_elapsed_seconds: float | None
    elapsed_delta_seconds: float | None
    elapsed_delta_percent: float | None


class CommandPermutationFailure(RuntimeError):
    """Raised when a command permutation does not meet its assertion."""


class ExternalProcessSampler:
    """Sample RSS for the child process tree from outside the CLI process."""

    def __init__(self, root_process_identifier: int, interval_seconds: float) -> None:
        self.root_process_identifier = root_process_identifier
        self.interval_seconds = interval_seconds
        self.peak_rss_mb: float | None = None
        self.sample_count = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self.interval_seconds <= 0:
            return
        self._thread = threading.Thread(target=self._loop, name="ExternalProcessSampler")
        self._thread.daemon = True
        self._thread.start()
        self.sample_once()

    def stop(self) -> None:
        if self.interval_seconds <= 0:
            return
        self.sample_once()
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def _loop(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            self.sample_once()

    def sample_once(self) -> None:
        rss_mb = process_tree_rss_mb(self.root_process_identifier)
        if rss_mb is None:
            return
        self.sample_count += 1
        self.peak_rss_mb = max_optional_float(self.peak_rss_mb, rss_mb)


class CommandPermutationRunner:
    """Run command cases and assert CLI/log outcomes."""

    def __init__(
        self,
        variant: RunVariant,
        environment: dict[str, str],
        *,
        iteration: int,
        keep_going: bool,
        sample_interval: float,
        external_sample_interval: float,
    ) -> None:
        self.variant = variant
        self.environment = environment
        self.iteration = iteration
        self.keep_going = keep_going
        self.sample_interval = sample_interval
        self.external_sample_interval = external_sample_interval
        self.results: list[CommandResult] = []
        self.failures: list[str] = []

    def run(self, case: CommandCase) -> CommandResult:
        """Run one case, assert it, and return the captured result."""
        result = self._run_process(case)
        try:
            self._assert_result(result)
        except CommandPermutationFailure as failure:
            self.failures.append(str(failure))
            print(f"\n✗ {case.name}: {failure}", file=sys.stderr)
            if not self.keep_going:
                raise
        else:
            self.results.append(result)
            print(f"✓ {case.name} ({result.elapsed_seconds:.1f}s{_memory_suffix(result.memory)})")
        return result

    def _run_process(self, case: CommandCase) -> CommandResult:
        full_command = [
            *self.variant.executable,
            *case.arguments,
            "--sample-interval",
            str(self.sample_interval),
        ]
        print("\n" + "=" * 100)
        print(f"VARIANT {self.variant.name} ITERATION {self.iteration} CASE {case.name}")
        print("$ " + shlex.join(full_command))
        print("=" * 100)

        started_at = time.monotonic()
        process = subprocess.Popen(
            full_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=self.environment,
        )
        external_sampler = ExternalProcessSampler(process.pid, self.external_sample_interval)
        external_sampler.start()
        output_lines: list[str] = []
        assert process.stdout is not None
        for line in process.stdout:
            output_lines.append(line)
            print(line, end="")
        return_code = process.wait()
        external_sampler.stop()
        output = "".join(output_lines)
        elapsed_seconds = time.monotonic() - started_at
        log_path = _extract_log_path(output)
        run_record: dict[str, Any] | None = None
        memory: MemorySummary | None = None
        phase_memory: list[PhaseMemorySummary] = []
        artifact_sizes: dict[str, int] = {}
        workload: dict[str, int | float | str] = {}
        if log_path is not None and log_path.is_file():
            run_record, memory, phase_memory, workload = _read_run_log_summary(log_path)
            artifact_sizes = artifact_sizes_for_run(log_path)
        if memory is not None:
            memory = MemorySummary(
                peak_rss_mb=memory.peak_rss_mb,
                sampled_peak_rss_mb=memory.sampled_peak_rss_mb,
                external_peak_rss_mb=external_sampler.peak_rss_mb,
                resource_sample_count=memory.resource_sample_count,
                external_sample_count=external_sampler.sample_count,
                max_num_fds=memory.max_num_fds,
                max_num_threads=memory.max_num_threads,
                max_process_cpu_percent=memory.max_process_cpu_percent,
            )
        elif external_sampler.peak_rss_mb is not None:
            memory = MemorySummary(
                peak_rss_mb=None,
                sampled_peak_rss_mb=None,
                external_peak_rss_mb=external_sampler.peak_rss_mb,
                resource_sample_count=0,
                external_sample_count=external_sampler.sample_count,
                max_num_fds=None,
                max_num_threads=None,
                max_process_cpu_percent=None,
            )
        return CommandResult(
            variant=self.variant.name,
            iteration=self.iteration,
            case=case,
            return_code=return_code,
            output=output,
            log_path=log_path,
            run_directory=log_path.parent if log_path is not None else None,
            run_record=run_record,
            memory=memory,
            phase_memory=phase_memory,
            artifact_sizes=artifact_sizes,
            workload=workload,
            elapsed_seconds=elapsed_seconds,
        )

    def _assert_result(self, result: CommandResult) -> None:
        case = result.case
        if result.return_code != case.expected_exit_code:
            raise CommandPermutationFailure(
                f"expected exit {case.expected_exit_code}, got {result.return_code}"
            )
        for substring in case.must_contain:
            if substring not in result.output:
                raise CommandPermutationFailure(f"output did not contain {substring!r}")
        if case.must_contain_one_of and not any(
            substring in result.output for substring in case.must_contain_one_of
        ):
            expected = ", ".join(repr(substring) for substring in case.must_contain_one_of)
            raise CommandPermutationFailure(f"output did not contain any of: {expected}")
        for substring in case.must_not_contain:
            if substring in result.output:
                raise CommandPermutationFailure(f"output unexpectedly contained {substring!r}")
        if case.expected_log_command is None:
            return
        if result.log_path is None:
            raise CommandPermutationFailure("command did not print a structured log path")
        if result.run_record is None:
            raise CommandPermutationFailure(f"{result.log_path} did not contain a run end record")
        if result.run_record.get("command") != case.expected_log_command:
            raise CommandPermutationFailure(
                "structured log command mismatch: "
                f"expected {case.expected_log_command!r}, got {result.run_record.get('command')!r}"
            )
        if (
            case.expected_log_status is not None
            and result.run_record.get("status") != case.expected_log_status
        ):
            raise CommandPermutationFailure(
                "structured log status mismatch: "
                f"expected {case.expected_log_status!r}, got {result.run_record.get('status')!r}"
            )
        if result.run_record.get("exit_code") != case.expected_exit_code:
            raise CommandPermutationFailure(
                "structured log exit_code mismatch: "
                f"expected {case.expected_exit_code!r}, got {result.run_record.get('exit_code')!r}"
            )


def main() -> None:
    arguments = parse_arguments()
    validate_date(arguments.future_date, "--future-date")
    variants = run_variants(arguments)
    if arguments.sample_interval < 0:
        raise SystemExit("--sample-interval must be >= 0")
    if arguments.external_sample_interval < 0:
        raise SystemExit("--external-sample-interval must be >= 0")

    environment = command_environment(arguments)
    if not arguments.user:
        arguments.user = environment.get("AUTH_PERMS_SYNC_TEST_USER") or environment.get("USER")
    if not arguments.user:
        raise SystemExit("--user is required when AUTH_PERMS_SYNC_TEST_USER and USER are unset")
    endpoint = environment.get("SRC_ENDPOINT")
    access_token = environment.get("SRC_ACCESS_TOKEN")
    if not endpoint:
        raise SystemExit("SRC_ENDPOINT must be set, or pass --endpoint")
    if not access_token:
        raise SystemExit("SRC_ACCESS_TOKEN must be set, or pass --access-token")
    if not arguments.allow_non_test_endpoint:
        assert_test_endpoint(endpoint)

    all_results: list[CommandResult] = []
    all_failures: list[str] = []
    latest_baseline_repositories: set[str] = set()
    for iteration in range(1, arguments.repeat + 1):
        for variant in variants:
            runner = CommandPermutationRunner(
                variant,
                environment,
                iteration=iteration,
                keep_going=arguments.keep_going,
                sample_interval=arguments.sample_interval,
                external_sample_interval=arguments.external_sample_interval,
            )
            try:
                latest_baseline_repositories = run_matrix(arguments, runner)
            finally:
                all_results.extend(runner.results)
                all_failures.extend(f"{variant.name}: {failure}" for failure in runner.failures)
    if all_failures:
        print("\nFailures:", file=sys.stderr)
        for failure in all_failures:
            print(f"- {failure}", file=sys.stderr)
        raise SystemExit(1)

    print("\nAll command permutations passed.")
    print(f"Cases passed: {len(all_results)}")
    print(f"Baseline repositories for {arguments.user}: {len(latest_baseline_repositories)}")
    print_memory_summary(all_results, arguments.memory_summary_limit)
    print_phase_memory_summary(all_results, arguments.memory_summary_limit)
    comparisons = compare_variants(all_results)
    print_comparison_summary(comparisons)
    write_results_files(all_results, comparisons, arguments)
    raise_for_memory_regressions(comparisons, arguments)


def run_variants(arguments: argparse.Namespace) -> list[RunVariant]:
    """Return the executable variants to measure."""
    candidate_command = arguments.candidate_command or arguments.auth_perms_sync_command
    candidate = RunVariant("candidate", tuple(shlex.split(candidate_command)))
    if not candidate.executable:
        raise SystemExit("candidate command cannot be empty")
    if not arguments.baseline_command:
        return [candidate]
    baseline = RunVariant("baseline", tuple(shlex.split(arguments.baseline_command)))
    if not baseline.executable:
        raise SystemExit("--baseline-command cannot be empty")
    return [baseline, candidate]


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run auth-perms-sync command permutations against a test instance.",
    )
    parser.add_argument(
        "--auth-perms-sync-command",
        default="uv run auth-perms-sync",
        help="Candidate command used to invoke the CLI (default: %(default)s)",
    )
    parser.add_argument(
        "--candidate-command",
        help="Candidate command to compare; overrides --auth-perms-sync-command",
    )
    parser.add_argument(
        "--baseline-command",
        help="Optional baseline command. When set, baseline and candidate results are compared.",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=DEFAULT_REPEAT_COUNT,
        help="Number of times to run each command for each variant (default: %(default)s)",
    )
    parser.add_argument(
        "--endpoint",
        help="Override SRC_ENDPOINT for the child commands",
    )
    parser.add_argument(
        "--access-token",
        help="Override SRC_ACCESS_TOKEN for the child commands",
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        help="Env file to load for runner checks when variables are not already exported",
    )
    parser.add_argument(
        "--user",
        help=(
            "Sourcegraph user for user-scoped get/set/restore permutations "
            "(default: AUTH_PERMS_SYNC_TEST_USER or USER)"
        ),
    )
    parser.add_argument(
        "--future-date",
        default=DEFAULT_FUTURE_DATE,
        help="YYYY-MM-DD date expected to match no users (default: %(default)s)",
    )
    parser.add_argument(
        "--parallelism",
        type=int,
        default=4,
        help="Parallelism for light mutation/no-op apply cases (default: %(default)s)",
    )
    parser.add_argument(
        "--full-restore-parallelism",
        type=int,
        default=1,
        help="Parallelism for the expensive full restore cleanup (default: %(default)s)",
    )
    parser.add_argument(
        "--allow-non-test-endpoint",
        action="store_true",
        help="Allow mutating cases outside localhost/sgdev endpoints",
    )
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="Continue after assertion failures where it is safe to do so",
    )
    parser.add_argument(
        "--sample-interval",
        type=float,
        default=DEFAULT_SAMPLE_INTERVAL_SECONDS,
        help=(
            "Seconds between child resource_sample log events. "
            "The run end record always includes peak_rss_mb; set 0 to disable samples. "
            "Default: %(default)s"
        ),
    )
    parser.add_argument(
        "--external-sample-interval",
        type=float,
        default=DEFAULT_SAMPLE_INTERVAL_SECONDS,
        help=(
            "Seconds between external child process-tree RSS samples; "
            "set 0 to disable (default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--memory-summary-limit",
        type=int,
        default=20,
        help="Number of highest-RSS cases to print in the final memory summary",
    )
    parser.add_argument(
        "--results-json",
        type=Path,
        help="Optional path to write machine-readable run and comparison results as JSON",
    )
    parser.add_argument(
        "--results-csv",
        type=Path,
        help=(
            "Optional path to write per-command memory results as CSV; "
            "phase rows are written beside it as *-phases.csv"
        ),
    )
    parser.add_argument(
        "--fail-on-memory-regression-percent",
        type=float,
        help="Fail if candidate median peak RSS regresses by more than this percent",
    )
    parser.add_argument(
        "--fail-on-memory-regression-mib",
        type=float,
        help="Fail if candidate median peak RSS regresses by more than this many MiB",
    )
    parsed_arguments = parser.parse_args()
    if parsed_arguments.repeat < 1:
        parser.error("--repeat must be >= 1")
    if parsed_arguments.parallelism < 1:
        parser.error("--parallelism must be >= 1")
    if parsed_arguments.full_restore_parallelism < 1:
        parser.error("--full-restore-parallelism must be >= 1")
    if parsed_arguments.memory_summary_limit < 1:
        parser.error("--memory-summary-limit must be >= 1")
    if (
        parsed_arguments.fail_on_memory_regression_percent is not None
        and parsed_arguments.fail_on_memory_regression_percent < 0
    ):
        parser.error("--fail-on-memory-regression-percent must be >= 0")
    if (
        parsed_arguments.fail_on_memory_regression_mib is not None
        and parsed_arguments.fail_on_memory_regression_mib < 0
    ):
        parser.error("--fail-on-memory-regression-mib must be >= 0")
    return parsed_arguments


def command_environment(arguments: argparse.Namespace) -> dict[str, str]:
    """Return a deterministic child environment for CLI config parsing."""
    environment = {**dotenv_values(Path(arguments.env_file)), **os.environ}
    for name in list(environment):
        if name.startswith(REMOVED_AUTH_PERMS_SYNC_ENVIRONMENT_PREFIX):
            del environment[name]
    if arguments.endpoint:
        environment["SRC_ENDPOINT"] = arguments.endpoint
    if arguments.access_token:
        environment["SRC_ACCESS_TOKEN"] = arguments.access_token
    return environment


def dotenv_values(path: Path) -> dict[str, str]:
    """Parse simple KEY=VALUE entries from an env file without logging secrets."""
    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line.removeprefix("export ").strip()
        name, separator, raw_value = line.partition("=")
        if not separator:
            continue
        name = name.strip()
        if not name:
            continue
        values[name] = dotenv_value(raw_value)
    return values


def dotenv_value(raw_value: str) -> str:
    """Return one shell-like dotenv value."""
    value = raw_value.strip()
    if not value:
        return ""
    try:
        parsed_values = shlex.split(value, comments=True, posix=True)
    except ValueError:
        return value.strip("'\"")
    if not parsed_values:
        return ""
    return parsed_values[0]


def assert_test_endpoint(endpoint: str) -> None:
    """Refuse mutating cases unless the endpoint looks like a test instance."""
    hostname = (urlsplit(endpoint).hostname or "").lower()
    if hostname in {"localhost", "127.0.0.1", "::1"}:
        return
    if hostname.endswith(".sgdev.org") or ".sgdev." in hostname:
        return
    raise SystemExit(
        "Refusing mutating tests against non-test-looking endpoint "
        f"{endpoint!r}. Pass --allow-non-test-endpoint if this is intentional."
    )


def validate_date(value: str, flag_name: str) -> None:
    try:
        datetime.date.fromisoformat(value)
    except ValueError as error:
        raise SystemExit(f"{flag_name} must be YYYY-MM-DD, got {value!r}") from error


def run_matrix(
    arguments: argparse.Namespace,
    runner: CommandPermutationRunner,
) -> set[str]:
    for case in invalid_configuration_cases(arguments):
        runner.run(case)

    baseline_result: CommandResult | None = None
    for case in read_only_cases(arguments):
        result = runner.run(case)
        if case.name == "implicit-get-user":
            baseline_result = result
    assert baseline_result is not None
    baseline_repositories = repositories_for_user(snapshot_path(baseline_result), arguments.user)

    run_safe_set_cases(arguments, runner)
    run_full_apply_cases(arguments, runner)

    set_user_dry_run = runner.run(set_user_dry_run_case(arguments))
    runner.run(restore_scoped_dry_run_case(snapshot_path(set_user_dry_run), arguments))
    set_user_apply = runner.run(set_user_apply_case(arguments))
    try:
        runner.run(restore_scoped_apply_case(snapshot_path(set_user_apply), arguments))
    finally:
        final_result = runner.run(final_get_user_case(arguments))
        final_repositories = repositories_for_user(snapshot_path(final_result), arguments.user)
        if final_repositories != baseline_repositories:
            added = sorted(final_repositories - baseline_repositories)
            removed = sorted(baseline_repositories - final_repositories)
            raise CommandPermutationFailure(
                f"final user baseline differs after cleanup; added={added}, removed={removed}"
            )

    runner.run(users_without_explicit_permissions_no_op_case(arguments))
    runner.run(sync_saml_dry_run_case())
    runner.run(sync_saml_apply_case())
    return baseline_repositories


def invalid_configuration_cases(arguments: argparse.Namespace) -> list[CommandCase]:
    restore_placeholder = "definitely-missing-before.json"
    missing_maps = "definitely-missing-command-permutation-maps.yaml"
    command_pairs = [
        ("get-set", ("--get", "--set", "maps.yaml")),
        ("get-restore", ("--get", "--restore", restore_placeholder)),
        ("set-restore", ("--set", "maps.yaml", "--restore", restore_placeholder)),
    ]
    cases = [
        CommandCase(
            name=f"invalid-multiple-commands-{name}",
            arguments=command_arguments,
            expected_exit_code=2,
            must_contain=("choose only one",),
        )
        for name, command_arguments in command_pairs
    ]
    cases.append(
        CommandCase(
            name="invalid-restore-sync-saml-orgs",
            arguments=("--restore", restore_placeholder, "--sync-saml-orgs"),
            expected_exit_code=2,
            must_contain=("with --get or --set",),
        )
    )
    cases.extend(
        [
            CommandCase(
                name="invalid-full-without-set",
                arguments=("--full",),
                expected_exit_code=2,
                must_contain=("--full requires --set",),
            ),
            CommandCase(
                name="invalid-set-full-and-user",
                arguments=("--set", "maps.yaml", "--full", "--user", arguments.user),
                expected_exit_code=2,
                must_contain=("choose at most one",),
            ),
            CommandCase(
                name="invalid-set-full-and-users-without-explicit-perms",
                arguments=("--set", "maps.yaml", "--full", "--users-without-explicit-perms"),
                expected_exit_code=2,
                must_contain=("choose at most one",),
            ),
            CommandCase(
                name="invalid-user-filter-conflict",
                arguments=("--get", "--user", arguments.user, "--users-without-explicit-perms"),
                expected_exit_code=2,
                must_contain=("choose only one of --user or --users-without-explicit-perms",),
            ),
            CommandCase(
                name="invalid-restore-user-filter",
                arguments=("--restore", restore_placeholder, "--user", arguments.user),
                expected_exit_code=2,
                must_contain=("require --get or --set",),
            ),
            CommandCase(
                name="invalid-sync-created-after-filter",
                arguments=("--sync-saml-orgs", "--created-after", arguments.future_date),
                expected_exit_code=2,
                must_contain=("require --get or --set",),
            ),
            CommandCase(
                name="invalid-date-shape",
                arguments=("--get", "--created-after", "2026-1-01"),
                expected_exit_code=2,
            ),
            CommandCase(
                name="invalid-date-value",
                arguments=("--get", "--created-after", "2026-02-31"),
                expected_exit_code=1,
                must_contain=("--created-after must use YYYY-MM-DD",),
            ),
            CommandCase(
                name="invalid-missing-set-file",
                arguments=("--set", missing_maps),
                expected_exit_code=1,
                expected_log_command="set_full",
                expected_log_status="error",
                must_contain=("--set input file does not exist",),
            ),
            CommandCase(
                name="invalid-removed-repositories-created-after-flag",
                arguments=("--repositories-created-after", arguments.future_date),
                expected_exit_code=2,
                must_contain=("unrecognized arguments",),
            ),
            CommandCase(
                name="invalid-removed-get-schema-flag",
                arguments=("--get-schema", "definitely-missing-schema.gql"),
                expected_exit_code=2,
                must_contain=("unrecognized arguments",),
            ),
        ]
    )
    return cases


def read_only_cases(arguments: argparse.Namespace) -> list[CommandCase]:
    cases = [
        CommandCase(
            name="help",
            arguments=("--help",),
            must_contain=("usage: auth-perms-sync", "--set [FILE]"),
            must_not_contain=("--repositories-created-after", "--get-schema"),
        ),
        CommandCase(
            name="implicit-get-user",
            arguments=("--user", arguments.user),
            expected_log_command="get",
            must_contain=("Wrote before-snapshot",),
        ),
        CommandCase(
            name="explicit-get-user",
            arguments=("--get", "--user", arguments.user),
            expected_log_command="get",
            must_contain=("Wrote before-snapshot",),
        ),
        CommandCase(
            name="get-created-after-future",
            arguments=("--get", "--created-after", arguments.future_date),
            expected_log_command="get",
            must_contain=("Selected 0 user(s) for get output",),
        ),
        CommandCase(
            name="get-user-created-after-future",
            arguments=("--get", "--user", arguments.user, "--created-after", arguments.future_date),
            expected_log_command="get",
            must_contain_one_of=(
                "Selected 0 user(s) for get output",
                "Wrote before-snapshot",
            ),
        ),
        CommandCase(
            name="get-users-without-explicit-perms-created-after-future",
            arguments=(
                "--get",
                "--users-without-explicit-perms",
                "--created-after",
                arguments.future_date,
            ),
            expected_log_command="get",
            must_contain=("Selected 0 user(s) for get output",),
        ),
        CommandCase(
            name="explicit-get-all-users",
            arguments=("--get",),
            expected_log_command="get",
            must_contain=("Wrote before-snapshot",),
        ),
        CommandCase(
            name="get-sync-saml-orgs-dry-run",
            arguments=("--get", "--sync-saml-orgs"),
            expected_log_command="get_sync_saml_orgs",
            must_contain=("Wrote before-snapshot", "Dry run complete"),
        ),
    ]
    return cases


def run_safe_set_cases(arguments: argparse.Namespace, runner: CommandPermutationRunner) -> None:
    runner.run(
        CommandCase(
            name="set-default-full-no-op-apply",
            arguments=(
                "--set",
                "--created-after",
                arguments.future_date,
                "--apply",
                "--no-backup",
                "--parallelism",
                str(arguments.parallelism),
            ),
            expected_log_command="set_full",
            must_contain=("No repos resolved across any mapping",),
        )
    )
    runner.run(
        CommandCase(
            name="set-explicit-full-no-op-apply",
            arguments=(
                "--set",
                "maps.yaml",
                "--full",
                "--created-after",
                arguments.future_date,
                "--apply",
                "--no-backup",
                "--parallelism",
                str(arguments.parallelism),
            ),
            expected_log_command="set_full",
            must_contain=("No repos resolved across any mapping",),
        )
    )


def set_user_dry_run_case(arguments: argparse.Namespace) -> CommandCase:
    return CommandCase(
        name="set-user-dry-run",
        arguments=("--set", "maps.yaml", "--user", arguments.user),
        expected_log_command="set_user",
        must_contain=("Dry run complete",),
    )


def set_user_apply_case(arguments: argparse.Namespace) -> CommandCase:
    return CommandCase(
        name="set-user-apply",
        arguments=(
            "--set",
            "maps.yaml",
            "--user",
            arguments.user,
            "--apply",
            "--parallelism",
            str(arguments.parallelism),
        ),
        expected_log_command="set_user",
        must_contain_one_of=(
            "VALIDATION OK: all",
            "All selected users already have the mapped explicit grants",
        ),
    )


def users_without_explicit_permissions_no_op_case(arguments: argparse.Namespace) -> CommandCase:
    return CommandCase(
        name="set-users-without-explicit-perms-no-op-apply",
        arguments=(
            "--set",
            "maps.yaml",
            "--users-without-explicit-perms",
            "--created-after",
            arguments.future_date,
            "--apply",
            "--no-backup",
            "--parallelism",
            str(arguments.parallelism),
        ),
        expected_log_command="set_users_without_explicit_perms",
        must_contain=("No users selected",),
    )


def restore_scoped_dry_run_case(snapshot: Path, arguments: argparse.Namespace) -> CommandCase:
    return CommandCase(
        name="restore-scoped-dry-run",
        arguments=(
            "--restore",
            str(snapshot),
            "--parallelism",
            str(arguments.parallelism),
        ),
        expected_log_command="restore",
        must_contain=("Dry run complete",),
    )


def restore_scoped_apply_case(snapshot: Path, arguments: argparse.Namespace) -> CommandCase:
    return CommandCase(
        name="restore-scoped-apply-cleanup",
        arguments=(
            "--restore",
            str(snapshot),
            "--apply",
            "--parallelism",
            str(arguments.parallelism),
        ),
        expected_log_command="restore",
        must_contain_one_of=(
            "VALIDATION OK: scoped restore matches the target snapshot",
            "Scoped restore target already matches current state",
        ),
    )


def sync_saml_dry_run_case() -> CommandCase:
    return CommandCase(
        name="sync-saml-orgs-dry-run",
        arguments=("--sync-saml-orgs",),
        expected_log_command="sync_saml_orgs",
        must_contain=("Dry run complete",),
    )


def sync_saml_apply_case() -> CommandCase:
    return CommandCase(
        name="sync-saml-orgs-apply",
        arguments=("--sync-saml-orgs", "--apply"),
        expected_log_command="sync_saml_orgs",
        must_contain=("VALIDATION OK: all target org memberships match",),
    )


def final_get_user_case(arguments: argparse.Namespace) -> CommandCase:
    return CommandCase(
        name="final-get-user-baseline-check",
        arguments=("--get", "--user", arguments.user),
        expected_log_command="get",
        must_contain=("Wrote before-snapshot",),
    )


def run_full_apply_cases(arguments: argparse.Namespace, runner: CommandPermutationRunner) -> None:
    dry_run_result = runner.run(
        CommandCase(
            name="set-full-dry-run",
            arguments=("--set",),
            expected_log_command="set_full",
            must_contain=("Dry run complete",),
        )
    )
    baseline_snapshot = snapshot_path(dry_run_result)

    try:
        runner.run(
            CommandCase(
                name="set-full-apply",
                arguments=(
                    "--set",
                    "--apply",
                    "--parallelism",
                    str(arguments.parallelism),
                ),
                expected_log_command="set_full",
                must_contain=("VALIDATION OK",),
            )
        )
        runner.run(restore_full_dry_run_case("restore-full-dry-run", baseline_snapshot, arguments))
    finally:
        runner.run(
            restore_full_apply_case(
                "restore-full-apply-cleanup",
                baseline_snapshot,
                arguments,
                no_backup=False,
            )
        )

    try:
        runner.run(
            CommandCase(
                name="set-full-no-backup-apply",
                arguments=(
                    "--set",
                    "--apply",
                    "--no-backup",
                    "--parallelism",
                    str(arguments.parallelism),
                ),
                expected_log_command="set_full",
                must_contain=("Apply done",),
            )
        )
    finally:
        runner.run(
            restore_full_apply_case(
                "restore-full-no-backup-cleanup",
                baseline_snapshot,
                arguments,
                no_backup=True,
            )
        )

    runner.run(
        CommandCase(
            name="set-full-sync-saml-orgs-dry-run",
            arguments=("--set", "--sync-saml-orgs"),
            expected_log_command="set_full_sync_saml_orgs",
            must_contain=("Dry run complete",),
        )
    )
    try:
        runner.run(
            CommandCase(
                name="set-full-sync-saml-orgs-apply",
                arguments=(
                    "--set",
                    "--sync-saml-orgs",
                    "--apply",
                    "--parallelism",
                    str(arguments.parallelism),
                ),
                expected_log_command="set_full_sync_saml_orgs",
                must_contain=("VALIDATION OK",),
            )
        )
    finally:
        runner.run(
            restore_full_apply_case(
                "restore-full-after-sync-cleanup",
                baseline_snapshot,
                arguments,
                no_backup=False,
            )
        )


def restore_full_dry_run_case(
    name: str, snapshot: Path, arguments: argparse.Namespace
) -> CommandCase:
    return CommandCase(
        name=name,
        arguments=(
            "--restore",
            str(snapshot),
            "--parallelism",
            str(arguments.full_restore_parallelism),
        ),
        expected_log_command="restore",
        must_contain_one_of=("Dry run complete", "Nothing to restore"),
    )


def restore_full_apply_case(
    name: str,
    snapshot: Path,
    arguments: argparse.Namespace,
    *,
    no_backup: bool,
) -> CommandCase:
    restore_arguments = [
        "--restore",
        str(snapshot),
        "--apply",
        "--parallelism",
        str(arguments.full_restore_parallelism),
    ]
    if no_backup:
        restore_arguments.append("--no-backup")
    return CommandCase(
        name=name,
        arguments=tuple(restore_arguments),
        expected_log_command="restore",
        must_contain_one_of=(
            "VALIDATION OK: post-restore state matches",
            "Restore done",
            "Nothing to restore",
        ),
    )


def _extract_log_path(output: str) -> Path | None:
    matches = LOG_PATH_PATTERN.findall(output)
    if not matches:
        return None
    return Path(matches[-1])


def _read_run_log_summary(
    log_path: Path,
) -> tuple[
    dict[str, Any] | None,
    MemorySummary | None,
    list[PhaseMemorySummary],
    dict[str, int | float | str],
]:
    if not log_path.is_file():
        raise CommandPermutationFailure(f"structured log file does not exist: {log_path}")
    run_record: dict[str, Any] | None = None
    sample_count = 0
    sampled_peak_rss_mb: float | None = None
    max_num_fds: int | None = None
    max_num_threads: int | None = None
    max_process_cpu_percent: float | None = None
    records: list[dict[str, Any]] = []
    with log_path.open(encoding="utf-8") as log_file:
        for line in log_file:
            if not line.strip():
                continue
            record = json.loads(line)
            records.append(record)
            if record.get("event") == "resource_sample":
                sample_count += 1
                sampled_peak_rss_mb = max_optional_float(
                    sampled_peak_rss_mb,
                    float_field(record, "peak_rss_mb", "rss_mb", "process_rss_mb"),
                )
                max_num_fds = max_optional_int(max_num_fds, int_field(record, "num_fds"))
                max_num_threads = max_optional_int(
                    max_num_threads, int_field(record, "num_threads")
                )
                max_process_cpu_percent = max_optional_float(
                    max_process_cpu_percent,
                    float_field(record, "process_cpu_percent", "cpu_percent"),
                )
            if record.get("event") == "run" and record.get("phase") == "end":
                run_record = record
    if run_record is None:
        return None, None, phase_memory_from_records(records), workload_from_records(records)
    memory = MemorySummary(
        peak_rss_mb=float_field(run_record, "peak_rss_mb"),
        sampled_peak_rss_mb=sampled_peak_rss_mb,
        external_peak_rss_mb=None,
        resource_sample_count=sample_count,
        external_sample_count=0,
        max_num_fds=max_optional_int(max_num_fds, int_field(run_record, "num_fds")),
        max_num_threads=max_optional_int(max_num_threads, int_field(run_record, "num_threads")),
        max_process_cpu_percent=max_process_cpu_percent,
    )
    return run_record, memory, phase_memory_from_records(records), workload_from_records(records)


def phase_memory_from_records(records: list[dict[str, Any]]) -> list[PhaseMemorySummary]:
    """Attribute resource samples to every active structured span."""
    spans = span_intervals_from_records(records)
    if not spans:
        return []
    duration_by_phase: dict[tuple[str, str | None], int] = {}
    for span in spans:
        key = (span.event, span.stage)
        duration_by_phase[key] = duration_by_phase.get(key, 0) + span.duration_ms
    phase_stats: dict[tuple[str, str | None], dict[str, int | float]] = {}
    for record in records:
        if record.get("event") != "resource_sample":
            continue
        timestamp = parse_log_timestamp(record.get("ts"))
        rss_mb = float_field(record, "peak_rss_mb", "rss_mb", "process_rss_mb")
        if timestamp is None or rss_mb is None:
            continue
        active_spans = [span for span in spans if span.started_at <= timestamp <= span.ended_at]
        if not active_spans:
            continue
        for active_span in active_spans:
            key = (active_span.event, active_span.stage)
            stats = phase_stats.setdefault(
                key,
                {"peak_rss_mb": 0.0, "sample_count": 0},
            )
            stats["peak_rss_mb"] = max(float(stats["peak_rss_mb"]), rss_mb)
            stats["sample_count"] = int(stats["sample_count"]) + 1
    phase_memory = [
        PhaseMemorySummary(
            event=event,
            stage=stage,
            peak_rss_mb=float(stats["peak_rss_mb"]),
            sample_count=int(stats["sample_count"]),
            total_duration_ms=duration_by_phase.get((event, stage), 0),
        )
        for (event, stage), stats in phase_stats.items()
    ]
    phase_memory.sort(key=phase_memory_sort_key)
    return phase_memory


def phase_memory_sort_key(phase: PhaseMemorySummary) -> tuple[bool, float, str, str]:
    return (phase.event == "run", -phase.peak_rss_mb, phase.stage or "", phase.event)


def span_intervals_from_records(records: list[dict[str, Any]]) -> list[SpanInterval]:
    starts_by_span: dict[str, dict[str, Any]] = {}
    spans: list[SpanInterval] = []
    run_start_record: dict[str, Any] | None = None
    run_end_record: dict[str, Any] | None = None
    for record in records:
        if record.get("event") == "run":
            if record.get("phase") == "start":
                run_start_record = record
            elif record.get("phase") == "end":
                run_end_record = record
        span = record.get("span")
        if not isinstance(span, str):
            continue
        phase = record.get("phase")
        if phase == "start":
            starts_by_span[span] = record
            continue
        if phase != "end":
            continue
        ended_at = parse_log_timestamp(record.get("ts"))
        if ended_at is None:
            continue
        duration_ms = int_field(record, "duration_ms") or 0
        start_record = starts_by_span.get(span)
        started_at = parse_log_timestamp(start_record.get("ts")) if start_record else None
        if started_at is None:
            started_at = ended_at - datetime.timedelta(milliseconds=duration_ms)
        event = record.get("event")
        if not isinstance(event, str):
            continue
        stage = record.get("stage")
        if not isinstance(stage, str):
            stage = None
        spans.append(
            SpanInterval(
                event=event,
                stage=stage,
                started_at=started_at,
                ended_at=ended_at,
                duration_ms=duration_ms,
            )
        )
    run_span = run_span_interval(run_start_record, run_end_record)
    if run_span is not None:
        spans.append(run_span)
    return spans


def run_span_interval(
    start_record: dict[str, Any] | None, end_record: dict[str, Any] | None
) -> SpanInterval | None:
    if end_record is None:
        return None
    ended_at = parse_log_timestamp(end_record.get("ts"))
    if ended_at is None:
        return None
    duration_ms = int_field(end_record, "duration_ms") or 0
    started_at = parse_log_timestamp(start_record.get("ts")) if start_record else None
    if started_at is None:
        started_at = ended_at - datetime.timedelta(milliseconds=duration_ms)
    return SpanInterval(
        event="run",
        stage=None,
        started_at=started_at,
        ended_at=ended_at,
        duration_ms=duration_ms,
    )


def parse_log_timestamp(value: object) -> datetime.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def workload_from_records(records: list[dict[str, Any]]) -> dict[str, int | float | str]:
    """Collect stable workload-size fields so memory can be normalized."""
    workload: dict[str, int | float | str] = {}
    for record in records:
        for field_name in WORKLOAD_FIELDS:
            value = record.get(field_name)
            if isinstance(value, int | float):
                old_value = workload.get(field_name)
                if not isinstance(old_value, int | float) or value > old_value:
                    workload[field_name] = value
            elif isinstance(value, str) and field_name not in workload:
                workload[field_name] = value
    return workload


def artifact_sizes_for_run(log_path: Path) -> dict[str, int]:
    """Return sizes of JSON artifacts in the same run directory as the log."""
    run_directory = log_path.parent
    sizes = {
        path.name: path.stat().st_size
        for path in sorted(run_directory.glob("*.json"))
        if path.is_file()
    }
    sizes["__total_json_bytes"] = sum(sizes.values())
    return sizes


def process_tree_rss_mb(root_process_identifier: int) -> float | None:
    """Return current RSS for the process and descendants, in MiB."""
    try:
        process_result = subprocess.run(
            ["ps", "-axo", "pid=,ppid=,rss="],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if process_result.returncode != 0:
        return None
    parent_by_process: dict[int, int] = {}
    resident_kib_by_process: dict[int, int] = {}
    for raw_line in process_result.stdout.splitlines():
        fields = raw_line.split()
        if len(fields) != 3:
            continue
        try:
            process_identifier = int(fields[0])
            parent_process_identifier = int(fields[1])
            resident_kib = int(fields[2])
        except ValueError:
            continue
        parent_by_process[process_identifier] = parent_process_identifier
        resident_kib_by_process[process_identifier] = resident_kib
    if root_process_identifier not in resident_kib_by_process:
        return None
    descendants = {root_process_identifier}
    changed = True
    while changed:
        changed = False
        for process_identifier, parent_process_identifier in parent_by_process.items():
            if parent_process_identifier in descendants and process_identifier not in descendants:
                descendants.add(process_identifier)
                changed = True
    total_resident_kib = sum(
        resident_kib_by_process[process_identifier]
        for process_identifier in descendants
        if process_identifier in resident_kib_by_process
    )
    return total_resident_kib / 1024.0


def float_field(record: dict[str, Any], *names: str) -> float | None:
    for name in names:
        value = record.get(name)
        if isinstance(value, int | float):
            return float(value)
    return None


def int_field(record: dict[str, Any], name: str) -> int | None:
    value = record.get(name)
    if isinstance(value, int):
        return value
    return None


def max_optional_float(current: float | None, new: float | None) -> float | None:
    if new is None:
        return current
    if current is None:
        return new
    return max(current, new)


def max_optional_int(current: int | None, new: int | None) -> int | None:
    if new is None:
        return current
    if current is None:
        return new
    return max(current, new)


def _memory_suffix(memory: MemorySummary | None) -> str:
    if memory is None or memory.peak_rss_mb is None:
        return ""
    return f", peak RSS {memory.peak_rss_mb:.1f} MiB"


def print_memory_summary(results: list[CommandResult], limit: int) -> None:
    rows = [result for result in results if result.memory and result.memory.peak_rss_mb is not None]
    if not rows:
        print("\nMemory summary: no structured peak_rss_mb records found.")
        return
    rows.sort(key=lambda result: result.memory.peak_rss_mb if result.memory else 0.0, reverse=True)
    print("\nMemory summary (highest peak RSS first):")
    print(
        "variant,iteration,case,peak_rss_mib,sampled_peak_rss_mib,"
        "external_peak_rss_mib,resource_samples,external_samples,max_fds,"
        "max_threads,artifact_json_bytes,seconds"
    )
    for result in rows[:limit]:
        assert result.memory is not None
        sampled_peak = format_optional_float(result.memory.sampled_peak_rss_mb)
        external_peak = format_optional_float(result.memory.external_peak_rss_mb)
        max_fds = format_optional_int(result.memory.max_num_fds)
        max_threads = format_optional_int(result.memory.max_num_threads)
        artifact_bytes = result.artifact_sizes.get("__total_json_bytes", 0)
        print(
            ",".join(
                [
                    result.variant,
                    str(result.iteration),
                    result.case.name,
                    format_optional_float(result.memory.peak_rss_mb),
                    sampled_peak,
                    external_peak,
                    str(result.memory.resource_sample_count),
                    str(result.memory.external_sample_count),
                    max_fds,
                    max_threads,
                    str(artifact_bytes),
                    f"{result.elapsed_seconds:.1f}",
                ]
            )
        )


def print_phase_memory_summary(results: list[CommandResult], limit: int) -> None:
    rows = [
        (result, phase)
        for result in results
        for phase in result.phase_memory
        if phase.sample_count > 0
    ]
    if not rows:
        print("\nPhase memory summary: no attributed resource samples found.")
        return
    rows.sort(key=lambda row: phase_memory_sort_key(row[1]))
    print("\nPhase memory summary (highest attributed RSS first):")
    print("variant,iteration,case,stage,event,peak_rss_mib,samples,duration_seconds")
    for result, phase in rows[:limit]:
        print(
            ",".join(
                [
                    result.variant,
                    str(result.iteration),
                    result.case.name,
                    phase.stage or "",
                    phase.event,
                    f"{phase.peak_rss_mb:.2f}",
                    str(phase.sample_count),
                    f"{phase.total_duration_ms / 1000.0:.1f}",
                ]
            )
        )


def compare_variants(results: list[CommandResult]) -> list[CaseComparison]:
    variants = {result.variant for result in results}
    if not {"baseline", "candidate"}.issubset(variants):
        return []
    comparisons: list[CaseComparison] = []
    case_names = sorted({result.case.name for result in results})
    for case_name in case_names:
        baseline_results = [
            result
            for result in results
            if result.variant == "baseline" and result.case.name == case_name
        ]
        candidate_results = [
            result
            for result in results
            if result.variant == "candidate" and result.case.name == case_name
        ]
        baseline_peak = median_optional(result_peak_rss_mb(result) for result in baseline_results)
        candidate_peak = median_optional(result_peak_rss_mb(result) for result in candidate_results)
        baseline_external_peak = median_optional(
            result_external_peak_rss_mb(result) for result in baseline_results
        )
        candidate_external_peak = median_optional(
            result_external_peak_rss_mb(result) for result in candidate_results
        )
        baseline_elapsed = median_optional(result.elapsed_seconds for result in baseline_results)
        candidate_elapsed = median_optional(result.elapsed_seconds for result in candidate_results)
        comparisons.append(
            CaseComparison(
                case_name=case_name,
                baseline_count=len(baseline_results),
                candidate_count=len(candidate_results),
                baseline_peak_rss_mb=baseline_peak,
                candidate_peak_rss_mb=candidate_peak,
                peak_rss_delta_mb=delta(candidate_peak, baseline_peak),
                peak_rss_delta_percent=percent_delta(candidate_peak, baseline_peak),
                baseline_external_peak_rss_mb=baseline_external_peak,
                candidate_external_peak_rss_mb=candidate_external_peak,
                external_peak_rss_delta_mb=delta(candidate_external_peak, baseline_external_peak),
                external_peak_rss_delta_percent=percent_delta(
                    candidate_external_peak, baseline_external_peak
                ),
                baseline_elapsed_seconds=baseline_elapsed,
                candidate_elapsed_seconds=candidate_elapsed,
                elapsed_delta_seconds=delta(candidate_elapsed, baseline_elapsed),
                elapsed_delta_percent=percent_delta(candidate_elapsed, baseline_elapsed),
            )
        )
    comparisons.sort(
        key=lambda comparison: (
            comparison.peak_rss_delta_mb
            if comparison.peak_rss_delta_mb is not None
            else float("-inf")
        ),
        reverse=True,
    )
    return comparisons


def print_comparison_summary(comparisons: list[CaseComparison]) -> None:
    if not comparisons:
        return
    print("\nCandidate vs baseline median comparison:")
    print(
        "case,baseline_peak_rss_mib,candidate_peak_rss_mib,delta_mib,delta_percent,"
        "baseline_seconds,candidate_seconds,seconds_delta_percent"
    )
    for comparison in comparisons:
        print(
            ",".join(
                [
                    comparison.case_name,
                    format_optional_float(comparison.baseline_peak_rss_mb),
                    format_optional_float(comparison.candidate_peak_rss_mb),
                    format_signed_optional_float(comparison.peak_rss_delta_mb),
                    format_signed_optional_float(comparison.peak_rss_delta_percent),
                    format_optional_float(comparison.baseline_elapsed_seconds),
                    format_optional_float(comparison.candidate_elapsed_seconds),
                    format_signed_optional_float(comparison.elapsed_delta_percent),
                ]
            )
        )


def write_results_files(
    results: list[CommandResult],
    comparisons: list[CaseComparison],
    arguments: argparse.Namespace,
) -> None:
    if arguments.results_json is not None:
        write_results_json(arguments.results_json, results, comparisons)
    if arguments.results_csv is not None:
        write_results_csv(arguments.results_csv, results)
        phase_csv = phase_results_csv_path(arguments.results_csv)
        write_phase_results_csv(phase_csv, results)


def write_results_json(
    path: Path,
    results: list[CommandResult],
    comparisons: list[CaseComparison],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as output_file:
        json.dump(
            {
                "generated_at": datetime.datetime.now(datetime.UTC).isoformat(),
                "results": [result_to_json(result) for result in results],
                "comparisons": [comparison_to_json(comparison) for comparison in comparisons],
            },
            output_file,
            indent=2,
            sort_keys=True,
        )
        output_file.write("\n")
    print(f"Wrote JSON results to {path}")


def write_results_csv(path: Path, results: list[CommandResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    workload_fields = sorted({field_name for result in results for field_name in result.workload})
    artifact_fields = sorted(
        {field_name for result in results for field_name in result.artifact_sizes}
    )
    fieldnames = [
        "variant",
        "iteration",
        "case",
        "return_code",
        "elapsed_seconds",
        "peak_rss_mb",
        "sampled_peak_rss_mb",
        "external_peak_rss_mb",
        "resource_sample_count",
        "external_sample_count",
        "max_num_fds",
        "max_num_threads",
        "max_process_cpu_percent",
        *[f"artifact_{field_name}" for field_name in artifact_fields],
        *[f"workload_{field_name}" for field_name in workload_fields],
    ]
    with path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result_to_csv_row(result, artifact_fields, workload_fields))
    print(f"Wrote CSV results to {path}")


def write_phase_results_csv(path: Path, results: list[CommandResult]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "variant",
        "iteration",
        "case",
        "stage",
        "event",
        "peak_rss_mb",
        "sample_count",
        "total_duration_ms",
    ]
    with path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            for phase in result.phase_memory:
                writer.writerow(
                    {
                        "variant": result.variant,
                        "iteration": result.iteration,
                        "case": result.case.name,
                        "stage": phase.stage or "",
                        "event": phase.event,
                        "peak_rss_mb": f"{phase.peak_rss_mb:.2f}",
                        "sample_count": phase.sample_count,
                        "total_duration_ms": phase.total_duration_ms,
                    }
                )
    print(f"Wrote phase CSV results to {path}")


def phase_results_csv_path(path: Path) -> Path:
    return path.with_name(f"{path.stem}-phases{path.suffix}")


def raise_for_memory_regressions(
    comparisons: list[CaseComparison], arguments: argparse.Namespace
) -> None:
    percent_limit = arguments.fail_on_memory_regression_percent
    mib_limit = arguments.fail_on_memory_regression_mib
    if percent_limit is None and mib_limit is None:
        return
    failures: list[str] = []
    for comparison in comparisons:
        if (
            mib_limit is not None
            and comparison.peak_rss_delta_mb is not None
            and comparison.peak_rss_delta_mb > mib_limit
        ):
            failures.append(
                f"{comparison.case_name}: peak RSS regressed "
                f"{comparison.peak_rss_delta_mb:.2f} MiB > {mib_limit:.2f} MiB"
            )
        if (
            percent_limit is not None
            and comparison.peak_rss_delta_percent is not None
            and comparison.peak_rss_delta_percent > percent_limit
        ):
            failures.append(
                f"{comparison.case_name}: peak RSS regressed "
                f"{comparison.peak_rss_delta_percent:.2f}% > {percent_limit:.2f}%"
            )
    if failures:
        raise SystemExit("Memory regression threshold exceeded: " + "; ".join(failures))


def result_to_json(result: CommandResult) -> dict[str, Any]:
    return {
        "variant": result.variant,
        "iteration": result.iteration,
        "case": result.case.name,
        "arguments": list(result.case.arguments),
        "return_code": result.return_code,
        "elapsed_seconds": round(result.elapsed_seconds, 3),
        "log_path": str(result.log_path) if result.log_path is not None else None,
        "run_directory": str(result.run_directory) if result.run_directory is not None else None,
        "command": result.run_record.get("command") if result.run_record else None,
        "status": result.run_record.get("status") if result.run_record else None,
        "memory": memory_to_json(result.memory),
        "phase_memory": [phase_to_json(phase) for phase in result.phase_memory],
        "artifact_sizes": result.artifact_sizes,
        "workload": result.workload,
        "normalized_memory": normalized_memory(result),
    }


def memory_to_json(memory: MemorySummary | None) -> dict[str, Any] | None:
    if memory is None:
        return None
    return {
        "peak_rss_mb": memory.peak_rss_mb,
        "sampled_peak_rss_mb": memory.sampled_peak_rss_mb,
        "external_peak_rss_mb": memory.external_peak_rss_mb,
        "resource_sample_count": memory.resource_sample_count,
        "external_sample_count": memory.external_sample_count,
        "max_num_fds": memory.max_num_fds,
        "max_num_threads": memory.max_num_threads,
        "max_process_cpu_percent": memory.max_process_cpu_percent,
    }


def phase_to_json(phase: PhaseMemorySummary) -> dict[str, Any]:
    return {
        "event": phase.event,
        "stage": phase.stage,
        "peak_rss_mb": phase.peak_rss_mb,
        "sample_count": phase.sample_count,
        "total_duration_ms": phase.total_duration_ms,
    }


def comparison_to_json(comparison: CaseComparison) -> dict[str, Any]:
    return {
        "case": comparison.case_name,
        "baseline_count": comparison.baseline_count,
        "candidate_count": comparison.candidate_count,
        "baseline_peak_rss_mb": comparison.baseline_peak_rss_mb,
        "candidate_peak_rss_mb": comparison.candidate_peak_rss_mb,
        "peak_rss_delta_mb": comparison.peak_rss_delta_mb,
        "peak_rss_delta_percent": comparison.peak_rss_delta_percent,
        "baseline_external_peak_rss_mb": comparison.baseline_external_peak_rss_mb,
        "candidate_external_peak_rss_mb": comparison.candidate_external_peak_rss_mb,
        "external_peak_rss_delta_mb": comparison.external_peak_rss_delta_mb,
        "external_peak_rss_delta_percent": comparison.external_peak_rss_delta_percent,
        "baseline_elapsed_seconds": comparison.baseline_elapsed_seconds,
        "candidate_elapsed_seconds": comparison.candidate_elapsed_seconds,
        "elapsed_delta_seconds": comparison.elapsed_delta_seconds,
        "elapsed_delta_percent": comparison.elapsed_delta_percent,
    }


def result_to_csv_row(
    result: CommandResult, artifact_fields: list[str], workload_fields: list[str]
) -> dict[str, object]:
    memory = result.memory
    row: dict[str, object] = {
        "variant": result.variant,
        "iteration": result.iteration,
        "case": result.case.name,
        "return_code": result.return_code,
        "elapsed_seconds": f"{result.elapsed_seconds:.3f}",
        "peak_rss_mb": format_optional_float(result_peak_rss_mb(result)),
        "sampled_peak_rss_mb": format_optional_float(
            memory.sampled_peak_rss_mb if memory is not None else None
        ),
        "external_peak_rss_mb": format_optional_float(result_external_peak_rss_mb(result)),
        "resource_sample_count": memory.resource_sample_count if memory is not None else 0,
        "external_sample_count": memory.external_sample_count if memory is not None else 0,
        "max_num_fds": format_optional_int(memory.max_num_fds if memory is not None else None),
        "max_num_threads": format_optional_int(
            memory.max_num_threads if memory is not None else None
        ),
        "max_process_cpu_percent": format_optional_float(
            memory.max_process_cpu_percent if memory is not None else None
        ),
    }
    for field_name in artifact_fields:
        row[f"artifact_{field_name}"] = result.artifact_sizes.get(field_name, "")
    for field_name in workload_fields:
        row[f"workload_{field_name}"] = result.workload.get(field_name, "")
    return row


def normalized_memory(result: CommandResult) -> dict[str, float]:
    peak_rss_mb = result_peak_rss_mb(result)
    if peak_rss_mb is None:
        return {}
    normalized: dict[str, float] = {}
    for field_name in ("user_count", "total_users", "repo_count", "total_grants"):
        value = result.workload.get(field_name)
        if isinstance(value, int | float) and value > 0:
            normalized[f"peak_rss_mb_per_{field_name}"] = peak_rss_mb / float(value)
    return normalized


def result_peak_rss_mb(result: CommandResult) -> float | None:
    if result.memory is None:
        return None
    return result.memory.peak_rss_mb


def result_external_peak_rss_mb(result: CommandResult) -> float | None:
    if result.memory is None:
        return None
    return result.memory.external_peak_rss_mb


def median_optional(values: Iterable[object]) -> float | None:
    numbers = [float(value) for value in values if isinstance(value, int | float)]
    if not numbers:
        return None
    return float(statistics.median(numbers))


def delta(new: float | None, old: float | None) -> float | None:
    if new is None or old is None:
        return None
    return new - old


def percent_delta(new: float | None, old: float | None) -> float | None:
    if new is None or old is None or old == 0:
        return None
    return (new - old) / old * 100.0


def format_optional_float(value: float | None) -> str:
    if value is None:
        return ""
    return f"{value:.2f}"


def format_signed_optional_float(value: float | None) -> str:
    if value is None:
        return ""
    return f"{value:+.2f}"


def format_optional_int(value: int | None) -> str:
    if value is None:
        return ""
    return str(value)


def snapshot_path(result: CommandResult) -> Path:
    if result.run_directory is None:
        raise CommandPermutationFailure(f"{result.case.name} did not produce a run directory")
    path = result.run_directory / "before.json"
    if not path.is_file():
        raise CommandPermutationFailure(f"{result.case.name} did not write {path}")
    return path


def repositories_for_user(path: Path, username: str) -> set[str]:
    snapshot = json.loads(path.read_text())
    repositories: set[str] = set()
    for repository in snapshot.get("repos", {}).values():
        explicit_users = repository.get("explicit_permissions_users", [])
        if username in explicit_users:
            repositories.add(repository["name"])
    return repositories


if __name__ == "__main__":
    main()
