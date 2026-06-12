#!/usr/bin/env python3
"""Single entrypoint for all src-auth-perms-sync testing.

Levels (each level runs only its own checks):

  --local        Fast, no network. Lint, format, types, unit + fixture-case
                 tests, CLI argument rejection matrix, and randomized
                 permission-invariant checks. Suitable for a pre-commit hook.
  --live         End-to-end runs against the Sourcegraph test instance
                 configured in .env, with independent GraphQL read-back
                 verification of the actual permission state, and a
                 pip-install smoke test of the wheel.
  --performance  Repeated timed runs of the expensive paths against the test
                 instance, with Sourcegraph trace retention and resource
                 sampling, reported as a TSV and median summary.
  --install      PyPI install smoke test: pip-install the published package
                 (default: latest src-auth-perms-sync) into a clean venv and
                 run every --help command. Needs network to pypi.org only.

--live and --performance optionally take a comma-delimited list of test
names (substring match) to run a subset, e.g. --live full-overwrite-unions.
The summary reports how many checks the filter skipped; a filter that
matches no checks fails the run.

Other commands:

  --update-golden  Re-run every fixture case in tests/e2e/fixtures/ and
                   rewrite its after.json from the actual result. Review the
                   diff carefully before committing: after.json is the
                   assertion.

Examples:

  uv run tests/run.py
  uv run tests/run.py --live
  uv run tests/run.py --performance --repeat 3
  uv run tests/run.py --install
  uv run tests/run.py --update-golden
"""

from __future__ import annotations

import argparse
import base64
import datetime
import json
import logging
import os
import random
import re
import shlex
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

if TYPE_CHECKING:
    from tests.e2e.case_runner import FixtureRunResult, FixtureState

FIXTURES_DIR = ROOT / "tests" / "e2e" / "fixtures"
TEST_LOGS_DIR = ROOT / "logs"
LOG_PATH_PATTERN = re.compile(r"Writing log events to (.+?/log\.json)\.")
STRUCTURED_EVENT_LINE_PATTERN = re.compile(r"^[.]*event=\S+\s*$")
# Leading "YYYY-MM-DD HH:MM:SS,mmm" timestamp on relayed subprocess lines;
# logged as just "HH:MM:SS" (the date is in the log file name).
SUBPROCESS_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2} (\d{2}:\d{2}:\d{2}),\d{3} ")
READ_BACK_PAGE_SIZE = 100
FULL_APPLY_READ_BACK_USER_SAMPLE = 5
DEFAULT_PROPERTY_ITERATIONS = 25
DEFAULT_PROPERTY_SEED = 20260610
DEFAULT_PERFORMANCE_REPEAT = 1

EXPLICIT_REPOS_READ_BACK_QUERY = """
query TestExplicitRepoReadBack($username: String!, $first: Int!, $after: String) {
  user(username: $username) {
    id
    permissionsInfo {
      repositories(source: API, first: $first, after: $after) {
        nodes { repository { name } }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}
"""

REPOSITORY_USERS_READ_BACK_QUERY = """
query TestRepositoryUsersReadBack($name: String!, $first: Int!, $after: String) {
  repository(name: $name) {
    id
    permissionsInfo {
      users(first: $first, after: $after) {
        nodes { reasons user { username } }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}
"""

SET_REPOSITORY_PERMISSIONS_MUTATION = """
mutation TestSetRepositoryPermissions($repository: ID!, $userPermissions: [UserPermissionInput!]!) {
  setRepositoryPermissionsForUsers(repository: $repository, userPermissions: $userPermissions) {
    alwaysNil
  }
}
"""

PENDING_REPOS_READ_BACK_QUERY = """
query TestPendingRepos($bindID: String!, $first: Int!, $after: String) {
  authorizedUserRepositories(username: $bindID, first: $first, after: $after) {
    nodes { name }
    pageInfo { hasNextPage endCursor }
  }
}
"""

# Pending bindIDs seeded by live fixture cases match this prefix, so leftovers
# from an interrupted run are recognizable and `tests/setup.py --apply` can
# clear them without touching pending grants of unknown origin.
SYNTHETIC_PENDING_BINDID_PREFIX = "perms-sync-test-pending-"

SAML_AUTH_PROVIDERS_QUERY = """
query TestSamlAuthProviders {
  site {
    authProviders {
      nodes { serviceType serviceID clientID configID }
    }
  }
}
"""

ORGANIZATION_LOOKUP_QUERY = """
query TestOrganizationLookup($query: String!, $first: Int!) {
  organizations(first: $first, query: $query) {
    nodes { id name }
  }
}
"""

ORGANIZATION_MEMBERS_READ_BACK_QUERY = """
query TestOrganizationMembers($id: ID!, $first: Int!, $after: String) {
  node(id: $id) {
    ... on Org {
      members(first: $first, after: $after) {
        nodes { id username }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}
"""

CREATE_ORGANIZATION_MUTATION = """
mutation TestCreateOrganization($name: String!) {
  createOrganization(name: $name) { id name }
}
"""

ADD_ORGANIZATION_MEMBER_MUTATION = """
mutation TestAddOrganizationMember($organization: ID!, $username: String!) {
  addUserToOrganization(organization: $organization, username: $username) { alwaysNil }
}
"""

REMOVE_ORGANIZATION_MEMBER_MUTATION = """
mutation TestRemoveOrganizationMember($organization: ID!, $user: ID!) {
  removeUserFromOrganization(organization: $organization, user: $user) { alwaysNil }
}
"""

EXPLICIT_API_PERMISSION_REASON = "Explicit API"
SITE_ADMIN_PERMISSION_REASON = "Site Admin"
ORGANIZATION_SYNC_VALIDATION_OK = "VALIDATION OK: all target org memberships match"
SETUP_CONFIG_PATH = ROOT / "tests" / "setup.yaml"
# The live SAML-group-change check reuses this registry case's maps.yaml,
# so the mapping it exercises is the exact one saml-group-live pins.
SAML_GROUP_CHANGE_CASE = "saml-group-live"

log = logging.getLogger("test")
command_output_log = logging.getLogger("test.command_output")


# ---------------------------------------------------------------------------
# Logging: everything goes to the console and to one log file per run
# ---------------------------------------------------------------------------


# During the randomized invariant checks, the package emits thousands of
# identical structured records; this flag drops them from BOTH handlers.
SUPPRESS_PACKAGE_LOGS = threading.Event()

# With --quiet, package chatter stays out of the console entirely — including
# the expected warnings produced by intentionally-failing cases. Runner
# failures are still shown (they log at ERROR), and the file keeps everything.
CONSOLE_QUIET = threading.Event()


def is_structured_event(record: logging.LogRecord) -> bool:
    """src_py_lib structured span records (emitted on the root logger).

    Their message is just "event=<name>"; the payload lives in record
    attributes that a text formatter never renders, so the rendered line
    carries no information. CLI subprocess runs write the full JSON versions
    to their own log.json.
    """
    return isinstance(record.msg, str) and record.msg.startswith("event=")


class PackageNoiseFilter(logging.Filter):
    """Drop unrenderable structured events; keep package chatter in the file.

    Console: hide package chatter below WARNING (entirely with --quiet).
    While SUPPRESS_PACKAGE_LOGS is set, hide package chatter below ERROR
    everywhere (including the log file).
    """

    def __init__(self, for_console: bool) -> None:
        super().__init__()
        self.for_console = for_console

    def filter(self, record: logging.LogRecord) -> bool:
        if is_structured_event(record):
            return False
        if not record.name.startswith(("src_auth_perms_sync", "src_py_lib")):
            return True
        if self.for_console and CONSOLE_QUIET.is_set():
            return False
        if SUPPRESS_PACKAGE_LOGS.is_set():
            return record.levelno >= logging.ERROR
        if self.for_console:
            return record.levelno >= logging.WARNING
        return True


class FileLogFormatter(logging.Formatter):
    """Time-of-day prefix only — the date is in the log file name.

    Command output lines pass through verbatim: the subprocess already
    timestamps its own lines, so run.py's prefix would just repeat it.
    """

    def __init__(self) -> None:
        super().__init__("%(asctime)s [%(levelname)s] %(name)s %(message)s", datefmt="%H:%M:%S")

    def format(self, record: logging.LogRecord) -> str:
        if record.name == command_output_log.name:
            return record.getMessage()
        return super().format(record)


def configure_logging(log_file: Path, quiet: bool = False) -> None:
    """Send output to the console and the log file.

    With `quiet`, the console only shows warnings, errors, and failed checks;
    the log file always gets everything.
    """
    log_file.parent.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(logging.INFO)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter("%(message)s"))
    console_handler.addFilter(PackageNoiseFilter(for_console=True))
    if quiet:
        CONSOLE_QUIET.set()
        console_handler.setLevel(logging.WARNING)
    root.addHandler(console_handler)

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(FileLogFormatter())
    file_handler.addFilter(PackageNoiseFilter(for_console=False))
    root.addHandler(file_handler)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TestArguments:
    """Parsed command-line options for this test run."""

    level: str  # "local" | "live" | "performance" | "install"
    test_filter: tuple[str, ...]  # empty = run everything in the level
    quiet: bool
    update_golden: bool
    env_file: Path
    user: str | None
    repeat: int
    seed: int
    property_iterations: int
    allow_non_test_endpoint: bool
    candidate_command: str
    baseline_command: str | None
    fail_on_memory_regression_percent: float | None
    fail_on_memory_regression_mib: float | None
    jaeger_trace_limit: int
    external_sample_interval: float
    monitor_sourcegraph_load: bool
    monitor_namespace: str
    monitor_frontend_target: str
    monitor_postgres_target: str
    monitor_psql_command: str
    monitor_interval_seconds: int
    monitor_postgres_interval_seconds: int
    monitor_statements_interval_seconds: int
    install_python: str
    install_package: str


def parse_arguments(argv: Sequence[str] | None = None) -> TestArguments:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    level_group = parser.add_mutually_exclusive_group()
    level_group.add_argument(
        "--local", action="store_true", help="Fast checks with no network (default)"
    )
    level_group.add_argument(
        "--live",
        nargs="?",
        const="",
        default=None,
        metavar="TESTS",
        help="Tests against the .env instance. Optionally pass a comma-delimited "
        "list of test names (substring match) to run only those, "
        "e.g. --live full-overwrite-unions or --live wheel,baseline",
    )
    level_group.add_argument(
        "--performance",
        nargs="?",
        const="",
        default=None,
        metavar="TESTS",
        help="Repeated timed runs against the .env instance with traces and resource "
        "sampling. Optionally pass a comma-delimited list of test names (substring match)",
    )
    level_group.add_argument(
        "--install",
        action="store_true",
        help="PyPI install smoke test: pip-install the published package into a "
        "clean venv and run every --help command. Needs network to pypi.org only",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Console shows only the log file path and any warnings, errors, or "
        "failed checks; the log file still gets everything",
    )
    parser.add_argument(
        "--update-golden",
        action="store_true",
        help="Rewrite tests/e2e/fixtures/*/after.json from actual results, then exit",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=ROOT / ".env",
        help="Env file providing SRC_ENDPOINT and SRC_ACCESS_TOKEN for live runs (default: .env)",
    )
    parser.add_argument(
        "--user",
        default=None,
        help="Sourcegraph username for user-scoped live cases "
        "(default: $SRC_AUTH_PERMS_SYNC_TEST_USER or $USER)",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=DEFAULT_PERFORMANCE_REPEAT,
        help=f"Repetitions per performance case (default: {DEFAULT_PERFORMANCE_REPEAT})",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_PROPERTY_SEED,
        help=f"Random seed for invariant checks (default: {DEFAULT_PROPERTY_SEED})",
    )
    parser.add_argument(
        "--property-iterations",
        type=int,
        default=DEFAULT_PROPERTY_ITERATIONS,
        help=f"Random worlds per invariant check (default: {DEFAULT_PROPERTY_ITERATIONS})",
    )
    parser.add_argument(
        "--allow-non-test-endpoint",
        action="store_true",
        help="Allow live runs against endpoints that do not look like test instances",
    )
    performance_group = parser.add_argument_group("performance")
    performance_group.add_argument(
        "--candidate-command",
        default="uv run src-auth-perms-sync",
        help="Command used to invoke the CLI (default: uv run src-auth-perms-sync)",
    )
    performance_group.add_argument(
        "--baseline-command",
        default=None,
        help="Optional baseline CLI command; when set, performance cases run for both "
        "variants and medians are compared",
    )
    performance_group.add_argument(
        "--fail-on-memory-regression-percent",
        type=float,
        default=None,
        help="Fail if candidate median peak RSS regresses by more than this percent",
    )
    performance_group.add_argument(
        "--fail-on-memory-regression-mib",
        type=float,
        default=None,
        help="Fail if candidate median peak RSS regresses by more than this many MiB",
    )
    performance_group.add_argument(
        "--jaeger-trace-limit",
        type=int,
        default=10,
        help="Fetch up to this many slowest Sourcegraph Jaeger traces per performance case; "
        "0 disables trace fetching (default: 10)",
    )
    performance_group.add_argument(
        "--external-sample-interval",
        type=float,
        default=1.0,
        help="Seconds between external process-tree RSS samples during performance cases; "
        "0 disables (default: 1.0)",
    )
    monitor_group = parser.add_argument_group("sourcegraph load monitor")
    monitor_group.add_argument(
        "--monitor-sourcegraph-load",
        action="store_true",
        help="Sample Sourcegraph pod and Postgres load via kubectl during performance cases",
    )
    monitor_group.add_argument("--monitor-namespace", default="m")
    monitor_group.add_argument(
        "--monitor-frontend-target", default="deployment/sourcegraph-frontend"
    )
    monitor_group.add_argument("--monitor-postgres-target", default="pod/pgsql-0")
    monitor_group.add_argument("--monitor-psql-command", default="psql -X -U sg -d sg")
    monitor_group.add_argument("--monitor-interval-seconds", type=int, default=5)
    monitor_group.add_argument("--monitor-postgres-interval-seconds", type=int, default=10)
    monitor_group.add_argument("--monitor-statements-interval-seconds", type=int, default=30)
    install_group = parser.add_argument_group("install smoke test")
    install_group.add_argument(
        "--install-python",
        default="python3.13",
        help="Python interpreter used to create the clean venv (default: python3.13)",
    )
    install_group.add_argument(
        "--install-package",
        default="src-auth-perms-sync",
        help="pip requirement to install, e.g. 'src-auth-perms-sync==1.2.3' or a "
        "wheel path (default: src-auth-perms-sync, the latest from PyPI)",
    )
    options = parser.parse_args(argv)
    level = "local"
    test_filter: tuple[str, ...] = ()
    if options.live is not None:
        level = "live"
        test_filter = parse_test_filter(cast(str, options.live))
    if options.performance is not None:
        level = "performance"
        test_filter = parse_test_filter(cast(str, options.performance))
    if options.install:
        level = "install"
    return TestArguments(
        level=level,
        test_filter=test_filter,
        quiet=bool(options.quiet),
        update_golden=bool(options.update_golden),
        env_file=cast(Path, options.env_file),
        user=cast("str | None", options.user),
        repeat=int(options.repeat),
        seed=int(options.seed),
        property_iterations=int(options.property_iterations),
        allow_non_test_endpoint=bool(options.allow_non_test_endpoint),
        candidate_command=str(options.candidate_command),
        baseline_command=cast("str | None", options.baseline_command),
        fail_on_memory_regression_percent=cast(
            "float | None", options.fail_on_memory_regression_percent
        ),
        fail_on_memory_regression_mib=cast("float | None", options.fail_on_memory_regression_mib),
        jaeger_trace_limit=int(options.jaeger_trace_limit),
        external_sample_interval=float(options.external_sample_interval),
        monitor_sourcegraph_load=bool(options.monitor_sourcegraph_load),
        monitor_namespace=str(options.monitor_namespace),
        monitor_frontend_target=str(options.monitor_frontend_target),
        monitor_postgres_target=str(options.monitor_postgres_target),
        monitor_psql_command=str(options.monitor_psql_command),
        monitor_interval_seconds=int(options.monitor_interval_seconds),
        monitor_postgres_interval_seconds=int(options.monitor_postgres_interval_seconds),
        monitor_statements_interval_seconds=int(options.monitor_statements_interval_seconds),
        install_python=str(options.install_python),
        install_package=str(options.install_package),
    )


def parse_test_filter(value: str) -> tuple[str, ...]:
    return tuple(token.strip() for token in value.split(",") if token.strip())


def with_suffix_name(prefix: Path, suffix: str) -> Path:
    """Return the prefix path with a suffix appended to its file name."""
    return prefix.with_name(prefix.name + suffix)


def read_env_file(path: Path) -> dict[str, str]:
    """Parse KEY=VALUE lines from an env file, ignoring comments and blanks."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export ") :]
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key.strip()] = value
    return values


def resolve_secret_reference(value: str) -> str:
    """Resolve 1Password op:// references so the read-back client gets a real token."""
    if not value.startswith("op://"):
        return value
    completed = subprocess.run(
        ["op", "read", value],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(f"Failed to resolve {value!r} via `op read`: {completed.stderr.strip()}")
    return completed.stdout.strip()


def assert_test_endpoint(endpoint: str, allow_non_test_endpoint: bool) -> None:
    """Refuse mutating live runs against endpoints that do not look like test instances."""
    if allow_non_test_endpoint:
        return
    hostname = (urlsplit(endpoint).hostname or "").lower()
    if hostname in {"localhost", "127.0.0.1", "::1"}:
        return
    if hostname.endswith(".sgdev.org") or ".sgdev." in hostname:
        return
    raise SystemExit(
        f"Refusing live tests against non-test-looking endpoint {endpoint!r}. "
        "Pass --allow-non-test-endpoint if this is intentional."
    )


# ---------------------------------------------------------------------------
# Check bookkeeping
# ---------------------------------------------------------------------------


@dataclass
class CheckResult:
    name: str
    level: str
    passed: bool
    seconds: float
    detail: str = ""


@dataclass(frozen=True)
class CliCase:
    """One real CLI invocation and the conditions it must satisfy."""

    name: str
    arguments: tuple[str, ...]
    expected_exit_code: int = 0
    must_contain: tuple[str, ...] = ()
    must_contain_one_of: tuple[str, ...] = ()


@dataclass
class CliResult:
    case: CliCase
    return_code: int
    output: str
    elapsed_seconds: float
    log_path: Path | None
    run_directory: Path | None
    external_peak_rss_mb: float | None = None
    external_sample_count: int = 0

    def assertion_failure(self) -> str | None:
        if self.return_code != self.case.expected_exit_code:
            return f"expected exit {self.case.expected_exit_code}, got {self.return_code}"
        for substring in self.case.must_contain:
            if substring not in self.output:
                return f"output did not contain {substring!r}"
        if self.case.must_contain_one_of and not any(
            substring in self.output for substring in self.case.must_contain_one_of
        ):
            expected = ", ".join(repr(substring) for substring in self.case.must_contain_one_of)
            return f"output did not contain any of: {expected}"
        return None


class LiveAbort(RuntimeError):
    """Raised when a live prerequisite fails and dependent checks must be skipped."""


@dataclass(frozen=True)
class CommandExecution:
    """Captured result of one streamed subprocess."""

    return_code: int
    output: str
    external_peak_rss_mb: float | None = None
    external_sample_count: int = 0


def process_tree_rss_mb(root_process_identifier: int) -> float | None:
    """Return current RSS for the process and its descendants, in MiB."""
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
    children_by_parent: dict[int, list[int]] = {}
    for process_identifier, parent_process_identifier in parent_by_process.items():
        children_by_parent.setdefault(parent_process_identifier, []).append(process_identifier)
    total_kib = 0
    pending = [root_process_identifier]
    seen: set[int] = set()
    while pending:
        process_identifier = pending.pop()
        if process_identifier in seen:
            continue
        seen.add(process_identifier)
        total_kib += resident_kib_by_process.get(process_identifier, 0)
        pending.extend(children_by_parent.get(process_identifier, []))
    return total_kib / 1024.0


class ExternalProcessSampler:
    """Sample RSS for a child process tree from outside the child process."""

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
        self._thread = threading.Thread(
            target=self._loop, name="ExternalProcessSampler", daemon=True
        )
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
        if self.peak_rss_mb is None or rss_mb > self.peak_rss_mb:
            self.peak_rss_mb = rss_mb


@dataclass(frozen=True)
class RunLogSummary:
    """Resource usage and the run end record from one CLI run's structured log."""

    run_record: dict[str, Any] | None
    sampled_peak_rss_mb: float | None
    resource_sample_count: int
    max_num_fds: int | None
    max_num_threads: int | None
    max_process_cpu_percent: float | None


def float_field(record: dict[str, Any], *names: str) -> float | None:
    for name in names:
        value = record.get(name)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value)
    return None


def int_field(record: dict[str, Any], name: str) -> int | None:
    value = record.get(name)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def read_run_log_summary(log_path: Path | None) -> RunLogSummary:
    """Parse a CLI run's log.json for the run end record and resource samples."""
    empty = RunLogSummary(None, None, 0, None, None, None)
    if log_path is None or not log_path.is_file():
        return empty
    run_record: dict[str, Any] | None = None
    sampled_peak_rss_mb: float | None = None
    resource_sample_count = 0
    max_num_fds: int | None = None
    max_num_threads: int | None = None
    max_process_cpu_percent: float | None = None
    with log_path.open(encoding="utf-8") as log_file:
        for line in log_file:
            if not line.strip():
                continue
            try:
                record = cast("dict[str, Any]", json.loads(line))
            except json.JSONDecodeError:
                continue
            if record.get("event") == "resource_sample":
                resource_sample_count += 1
                sample_rss = float_field(record, "peak_rss_mb", "rss_mb", "process_rss_mb")
                if sample_rss is not None and (
                    sampled_peak_rss_mb is None or sample_rss > sampled_peak_rss_mb
                ):
                    sampled_peak_rss_mb = sample_rss
                sample_fds = int_field(record, "num_fds")
                if sample_fds is not None and (max_num_fds is None or sample_fds > max_num_fds):
                    max_num_fds = sample_fds
                sample_threads = int_field(record, "num_threads")
                if sample_threads is not None and (
                    max_num_threads is None or sample_threads > max_num_threads
                ):
                    max_num_threads = sample_threads
                sample_cpu = float_field(record, "process_cpu_percent", "cpu_percent")
                if sample_cpu is not None and (
                    max_process_cpu_percent is None or sample_cpu > max_process_cpu_percent
                ):
                    max_process_cpu_percent = sample_cpu
            if record.get("event") == "run" and record.get("phase") == "end":
                run_record = record
    return RunLogSummary(
        run_record=run_record,
        sampled_peak_rss_mb=sampled_peak_rss_mb,
        resource_sample_count=resource_sample_count,
        max_num_fds=max_num_fds,
        max_num_threads=max_num_threads,
        max_process_cpu_percent=max_process_cpu_percent,
    )


# ---------------------------------------------------------------------------
# The suite
# ---------------------------------------------------------------------------


@dataclass
class TestSuite:
    arguments: TestArguments
    # Path stem for this run's outputs: <stem>.log, and for performance runs
    # <stem>-results.tsv, <stem>-jaeger-traces[.jsonl], <stem>-sourcegraph-load.
    artifact_prefix: Path
    results: list[CheckResult] = field(default_factory=list[CheckResult])
    endpoint: str = ""
    access_token: str = ""
    test_user: str = ""
    skipped_check_names: list[str] = field(default_factory=list[str])
    filter_matched_count: int = 0

    # -- bookkeeping --------------------------------------------------------

    def record(self, name: str, level: str, passed: bool, seconds: float, detail: str = "") -> None:
        self.results.append(CheckResult(name, level, passed, seconds, detail))
        marker = "✓" if passed else "✗"
        suffix = f" — {detail}" if detail and not passed else ""
        log.log(
            logging.INFO if passed else logging.ERROR,
            "%s [%s] %s (%.1fs)%s",
            marker,
            level,
            name,
            seconds,
            suffix,
        )

    @property
    def failed(self) -> bool:
        return any(not result.passed for result in self.results)

    def test_selected(self, *names: str) -> bool:
        """Return whether any given name matches the --live/--performance filter.

        With no filter, everything is selected. Filter tokens match
        case-insensitively as substrings, so `--live full-overwrite-unions`
        runs one fixture case and `--live wheel,baseline` runs two checks.
        """
        if not self.arguments.test_filter:
            return True
        return self.explicitly_selected(*names)

    def explicitly_selected(self, *names: str) -> bool:
        """Return whether a filter token names one of `names`.

        Unlike `test_selected`, returns False when no filter was given —
        for checks that must be opt-in (instance-wide stress runs).
        """
        if not self.arguments.test_filter:
            return False
        return any(
            token.lower() in name.lower() for token in self.arguments.test_filter for name in names
        )

    def select(self, *names: str) -> bool:
        """`test_selected`, plus bookkeeping so filtering stays visible.

        Gates every optional check: matches are counted (a filter matching
        nothing fails the run) and skips are tallied for the summary.
        `names[0]` is the check's canonical name.
        """
        if self.test_selected(*names):
            if self.arguments.test_filter:
                self.filter_matched_count += 1
            return True
        if names[0] not in self.skipped_check_names:
            self.skipped_check_names.append(names[0])
        return False

    def log_test_filter(self) -> None:
        if self.arguments.test_filter:
            log.info(
                "Test filter (substring match): %s",
                ", ".join(repr(token) for token in self.arguments.test_filter),
            )

    # -- subprocess helpers --------------------------------------------------

    def stream_command(
        self,
        command: Sequence[str],
        environment: dict[str, str] | None = None,
        external_sample_interval: float = 0.0,
    ) -> CommandExecution:
        """Run a command, mirroring its output to the console and log file.

        When `external_sample_interval` is positive, the child's process-tree
        RSS is sampled from outside while it runs.
        """
        command_output_log.info("$ %s", shlex.join(command))
        process = subprocess.Popen(
            list(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=environment,
            cwd=str(ROOT),
        )
        sampler = ExternalProcessSampler(process.pid, external_sample_interval)
        sampler.start()
        output_lines: list[str] = []
        assert process.stdout is not None
        for line in process.stdout:
            output_lines.append(line)
            # Bare structured-event records leaking from in-process test runs
            # carry no information once rendered; keep them in the captured
            # output for assertions, but not in our logs.
            if not STRUCTURED_EVENT_LINE_PATTERN.match(line):
                command_output_log.info(
                    "%s", SUBPROCESS_TIMESTAMP_PATTERN.sub(r"\1 ", line.rstrip("\n"))
                )
        return_code = process.wait()
        sampler.stop()
        return CommandExecution(
            return_code=return_code,
            output="".join(output_lines),
            external_peak_rss_mb=sampler.peak_rss_mb,
            external_sample_count=sampler.sample_count,
        )

    def gate(self, name: str, command: Sequence[str], level: str = "local") -> bool:
        started = time.monotonic()
        execution = self.stream_command(command)
        passed = execution.return_code == 0
        self.record(
            name, level, passed, time.monotonic() - started, f"exit {execution.return_code}"
        )
        return passed

    # -- local: toolchain gates ----------------------------------------------

    def run_toolchain_gates(self) -> None:
        log.info("\n=== Local: toolchain gates ===")
        self.gate("ruff check", ["uv", "run", "ruff", "check", "."])
        self.gate("ruff format --check", ["uv", "run", "ruff", "format", "--check", "."])
        self.gate("pyright", ["uv", "run", "pyright"])
        self.gate(
            "unit + fixture tests",
            ["uv", "run", "python", "-m", "unittest", "discover", "-s", "tests"],
        )

    # -- local: fixture cases -------------------------------------------------

    def run_fixture_checks(self, update_golden: bool) -> None:
        from tests.e2e.case_runner import (
            case_modes,
            case_runners,
            is_replay_case,
            load_e2e_cases,
            run_fixture_case,
            run_local_replay_case,
        )

        log.info("\n=== Local: tests.yaml cases ===")
        for case_name, case in load_e2e_cases().items():
            if "local" not in case_modes(case):
                continue
            if is_replay_case(case):
                if update_golden:
                    continue
                log.info("— %s (parse) —", case_name)
                started = time.monotonic()
                failure = run_local_replay_case(case_name)
                self.record(
                    f"fixture: {case_name} (parse)",
                    "local",
                    not failure,
                    time.monotonic() - started,
                    failure,
                )
                continue
            runners = case_runners(case)
            if update_golden:
                result = run_fixture_case(case_name, runners[0])
                self._update_golden_after(FIXTURES_DIR / case_name, result)
                continue
            for runner in runners:
                log.info("— %s (%s) —", case_name, runner)
                started = time.monotonic()
                result = run_fixture_case(case_name, runner)
                self.record(
                    f"fixture: {case_name} ({runner})",
                    "local",
                    result.passed,
                    time.monotonic() - started,
                    result.failure or "",
                )

    def _update_golden_after(self, case_directory: Path, result: FixtureRunResult) -> None:
        from tests.e2e.case_runner import FakeSourcegraphClient, load_state

        if result.expected_errors:
            log.info("golden: %s expects errors; no after.json needed", case_directory.name)
            return
        if result.command_failure is not None:
            log.error(
                "golden: %s command FAILED (%s); not writing after.json",
                case_directory.name,
                result.command_failure,
            )
            self.record(f"golden: {case_directory.name}", "local", False, 0.0)
            return
        before_state = FakeSourcegraphClient(
            load_state(case_directory / "before.json")
        ).export_state()
        after_path = case_directory / "after.json"
        if result.actual_state == before_state and not after_path.is_file():
            log.info("golden: %s is a no-op case; after.json stays omitted", case_directory.name)
            return
        if after_path.is_file():
            existing_state = FakeSourcegraphClient(load_state(after_path)).export_state()
            if existing_state == result.actual_state:
                log.info("golden: %s after.json unchanged", case_directory.name)
                return
        after_path.write_text(json.dumps(result.actual_state, indent=2) + "\n", encoding="utf-8")
        log.info(
            "golden: %s after.json updated — review the diff before committing",
            case_directory.name,
        )

    # -- local: randomized permission invariants -------------------------------

    def run_property_checks(self) -> None:
        log.info(
            "\n=== Local: randomized permission invariants (seed=%d, iterations=%d) ===",
            self.arguments.seed,
            self.arguments.property_iterations,
        )
        SUPPRESS_PACKAGE_LOGS.set()
        try:
            self._run_property_checks_quietly()
        finally:
            SUPPRESS_PACKAGE_LOGS.clear()

    def _run_property_checks_quietly(self) -> None:
        for outcome in run_property_checks(
            seed=self.arguments.seed,
            iterations=self.arguments.property_iterations,
        ):
            self.record(
                f"invariant: {outcome.name}",
                "local",
                outcome.passed,
                outcome.seconds,
                outcome.detail,
            )

    # -- live helpers ----------------------------------------------------------

    def cli_environment(self, endpoint: str, token: str) -> dict[str, str]:
        environment = {
            name: value
            for name, value in os.environ.items()
            if not name.startswith("SRC_AUTH_PERMS_SYNC_")
        }
        environment["SRC_ENDPOINT"] = endpoint
        environment["SRC_ACCESS_TOKEN"] = token
        return environment

    @property
    def cli_executable(self) -> tuple[str, ...]:
        return tuple(shlex.split(self.arguments.candidate_command))

    def run_cli_case(
        self,
        case: CliCase,
        environment: dict[str, str],
        level: str,
        extra_arguments: tuple[str, ...] = (),
        executable: tuple[str, ...] | None = None,
        external_sample_interval: float = 0.0,
    ) -> CliResult:
        command = [
            *(executable if executable is not None else self.cli_executable),
            *case.arguments,
            *extra_arguments,
        ]
        started = time.monotonic()
        execution = self.stream_command(
            command, environment, external_sample_interval=external_sample_interval
        )
        elapsed = time.monotonic() - started
        log_path: Path | None = None
        matches = LOG_PATH_PATTERN.findall(execution.output)
        if matches:
            log_path = Path(matches[-1])
        result = CliResult(
            case=case,
            return_code=execution.return_code,
            output=execution.output,
            elapsed_seconds=elapsed,
            log_path=log_path,
            run_directory=log_path.parent if log_path is not None else None,
            external_peak_rss_mb=execution.external_peak_rss_mb,
            external_sample_count=execution.external_sample_count,
        )
        failure = result.assertion_failure()
        self.record(case.name, level, failure is None, elapsed, failure or "")
        return result

    def graphql(self, query: str, variables: dict[str, object]) -> dict[str, Any]:
        """Independent GraphQL read path: stdlib urllib only, no package code."""
        payload = json.dumps({"query": query, "variables": variables}).encode("utf-8")
        request = urllib.request.Request(
            f"{self.endpoint}/.api/graphql",
            data=payload,
            headers={
                "Authorization": f"token {self.access_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            body = cast("dict[str, Any]", json.load(response))
        errors = body.get("errors")
        if errors:
            raise RuntimeError(f"GraphQL errors: {errors}")
        return cast("dict[str, Any]", body["data"])

    def read_back_explicit_repo_names(self, username: str) -> set[str] | None:
        """Query the instance directly for a user's explicit-API repo names."""
        names: set[str] = set()
        after_cursor: str | None = None
        while True:
            data = self.graphql(
                EXPLICIT_REPOS_READ_BACK_QUERY,
                {"username": username, "first": READ_BACK_PAGE_SIZE, "after": after_cursor},
            )
            user = cast("dict[str, Any] | None", data.get("user"))
            if user is None:
                return None
            permissions_info = cast("dict[str, Any] | None", user.get("permissionsInfo"))
            if permissions_info is None:
                return names
            connection = cast("dict[str, Any]", permissions_info["repositories"])
            for node in cast("list[dict[str, Any]]", connection["nodes"]):
                repository = cast("dict[str, Any] | None", node.get("repository"))
                if repository is not None:
                    names.add(cast(str, repository["name"]))
            page_info = cast("dict[str, Any]", connection["pageInfo"])
            if not page_info.get("hasNextPage"):
                return names
            after_cursor = cast("str | None", page_info.get("endCursor"))

    def read_back_saml_groups(self, username: str) -> list[str] | None:
        """Return a user's sorted SAML group claims, or None if user/account missing.

        Reads the same `externalAccounts.accountData` surface the product
        parses; used to verify the fabricated accounts from tests/setup.py.
        """
        data = self.graphql(
            "query TestSamlGroups($username: String!) { user(username: $username) {"
            "  externalAccounts(first: 50) { nodes { serviceType accountData } } } }",
            {"username": username},
        )
        user = cast("dict[str, Any] | None", data.get("user"))
        if user is None:
            return None
        for account in cast("list[dict[str, Any]]", user["externalAccounts"]["nodes"]):
            if account["serviceType"] != "saml":
                continue
            account_data = cast("object", account.get("accountData"))
            if isinstance(account_data, str):
                account_data = cast("object", json.loads(account_data))
            if not isinstance(account_data, dict):
                return []
            attributes = cast("dict[str, Any]", account_data)
            groups_attribute = cast(
                "dict[str, Any]",
                cast("dict[str, Any]", attributes.get("Values") or {}).get("groups") or {},
            )
            group_values = cast("list[object]", groups_attribute.get("Values") or [])
            return sorted(
                cast(str, cast("dict[str, Any]", value)["Value"])
                for value in group_values
                if isinstance(value, dict) and "Value" in cast("dict[str, Any]", value)
            )
        return None

    def check_fabricated_saml_accounts(self, name: str, accounts: dict[str, list[str]]) -> bool:
        """Verify the fabricated SAML accounts match tests/setup.yaml."""
        started = time.monotonic()
        drift: list[str] = []
        for username, expected_groups in sorted(accounts.items()):
            actual_groups = self.read_back_saml_groups(username)
            if actual_groups != sorted(expected_groups):
                drift.append(
                    f"{username}: expected {sorted(expected_groups)}, found {actual_groups}"
                )
        self.record(
            name,
            "live",
            not drift,
            time.monotonic() - started,
            f"{'; '.join(drift)}; run `uv run tests/setup.py --apply`"
            if drift
            else f"{len(accounts)} account(s) match setup.yaml",
        )
        return not drift

    def saml_auth_provider(self) -> dict[str, str] | None:
        """Return the instance's SAML auth provider fields, or None when absent."""
        data = self.graphql(SAML_AUTH_PROVIDERS_QUERY, {})
        providers = cast(
            "list[dict[str, str]]",
            cast("dict[str, Any]", data["site"])["authProviders"]["nodes"],
        )
        return next(
            (provider for provider in providers if provider["serviceType"] == "saml"),
            None,
        )

    def read_back_organization_members(
        self, organization_name: str
    ) -> tuple[str, dict[str, str]] | None:
        """Return (org GraphQL ID, {member username: user GraphQL ID}), or None if missing."""
        data = self.graphql(
            ORGANIZATION_LOOKUP_QUERY,
            {"query": organization_name, "first": READ_BACK_PAGE_SIZE},
        )
        organizations = cast(
            "list[dict[str, str]]", cast("dict[str, Any]", data["organizations"])["nodes"]
        )
        organization = next(
            (entry for entry in organizations if entry["name"] == organization_name), None
        )
        if organization is None:
            return None
        members: dict[str, str] = {}
        after_cursor: str | None = None
        while True:
            data = self.graphql(
                ORGANIZATION_MEMBERS_READ_BACK_QUERY,
                {"id": organization["id"], "first": READ_BACK_PAGE_SIZE, "after": after_cursor},
            )
            connection = cast("dict[str, Any]", cast("dict[str, Any]", data["node"])["members"])
            for node in cast("list[dict[str, str]]", connection["nodes"]):
                members[node["username"]] = node["id"]
            page_info = cast("dict[str, Any]", connection["pageInfo"])
            if not page_info.get("hasNextPage"):
                return (organization["id"], members)
            after_cursor = cast("str | None", page_info.get("endCursor"))

    def read_back_repository_explicit_users(
        self, repository_name: str
    ) -> tuple[int, set[str]] | None:
        """Return (database id, explicit-API usernames) for one repo, or None if missing.

        Repo-centric `permissionsInfo.users` has no source filter, so usernames
        are taken from the "Explicit API" reason. Site admins are reported with
        only a "Site Admin" reason even when they also hold an explicit grant,
        so those users are disambiguated with a user-centric source:API query.
        """
        repository_id: int | None = None
        explicit_usernames: set[str] = set()
        ambiguous_usernames: set[str] = set()
        after_cursor: str | None = None
        while True:
            data = self.graphql(
                REPOSITORY_USERS_READ_BACK_QUERY,
                {"name": repository_name, "first": READ_BACK_PAGE_SIZE, "after": after_cursor},
            )
            repository = cast("dict[str, Any] | None", data.get("repository"))
            if repository is None:
                return None
            repository_id = decode_repository_node_id(cast(str, repository["id"]))
            permissions_info = cast("dict[str, Any] | None", repository.get("permissionsInfo"))
            if permissions_info is None:
                return (repository_id, explicit_usernames)
            connection = cast("dict[str, Any]", permissions_info["users"])
            for node in cast("list[dict[str, Any]]", connection["nodes"]):
                user = cast("dict[str, Any] | None", node.get("user"))
                if user is None:
                    continue
                username = cast(str, user["username"])
                reasons = cast("list[str]", node.get("reasons", []))
                if EXPLICIT_API_PERMISSION_REASON in reasons:
                    explicit_usernames.add(username)
                elif SITE_ADMIN_PERMISSION_REASON in reasons:
                    ambiguous_usernames.add(username)
            page_info = cast("dict[str, Any]", connection["pageInfo"])
            if not page_info.get("hasNextPage"):
                break
            after_cursor = cast("str | None", page_info.get("endCursor"))
        for username in sorted(ambiguous_usernames):
            user_repository_names = self.read_back_explicit_repo_names(username)
            if user_repository_names and repository_name in user_repository_names:
                explicit_usernames.add(username)
        assert repository_id is not None
        return (repository_id, explicit_usernames)

    def check_read_back(self, name: str, username: str, expected_names: set[str]) -> None:
        started = time.monotonic()
        try:
            actual_names = self.read_back_explicit_repo_names(username)
        except (urllib.error.URLError, RuntimeError, OSError) as error:
            self.record(name, "live", False, time.monotonic() - started, str(error))
            return
        if actual_names is None:
            self.record(
                name, "live", False, time.monotonic() - started, f"user {username!r} not found"
            )
            return
        if actual_names == expected_names:
            self.record(
                name,
                "live",
                True,
                time.monotonic() - started,
                f"{len(actual_names)} repo(s) match",
            )
            return
        missing = sorted(expected_names - actual_names)[:5]
        unexpected = sorted(actual_names - expected_names)[:5]
        self.record(
            name,
            "live",
            False,
            time.monotonic() - started,
            f"read-back mismatch for {username}: missing={missing} unexpected={unexpected}",
        )

    # -- live ------------------------------------------------------------------

    def prepare_live(self) -> dict[str, str]:
        env_values = read_env_file(self.arguments.env_file)
        endpoint = env_values.get("SRC_ENDPOINT") or os.environ.get("SRC_ENDPOINT") or ""
        token = env_values.get("SRC_ACCESS_TOKEN") or os.environ.get("SRC_ACCESS_TOKEN") or ""
        if not endpoint or not token:
            raise LiveAbort(
                f"SRC_ENDPOINT and SRC_ACCESS_TOKEN are required for live runs; "
                f"set them in {self.arguments.env_file} or the environment"
            )
        self.endpoint = endpoint.rstrip("/")
        self.access_token = resolve_secret_reference(token)
        assert_test_endpoint(self.endpoint, self.arguments.allow_non_test_endpoint)
        self.test_user = (
            self.arguments.user
            or os.environ.get("SRC_AUTH_PERMS_SYNC_TEST_USER")
            or os.environ.get("USER")
            or ""
        )
        if not self.test_user:
            raise LiveAbort("--user is required when SRC_AUTH_PERMS_SYNC_TEST_USER and USER unset")
        user_repos = self.read_back_explicit_repo_names(self.test_user)
        if user_repos is None:
            raise LiveAbort(f"user {self.test_user!r} does not exist on {self.endpoint}")
        log.info(
            "Live instance: %s  user: %s (%d explicit repo grant(s) currently)",
            self.endpoint,
            self.test_user,
            len(user_repos),
        )
        return self.cli_environment(self.endpoint, self.access_token)

    def run_live(self) -> None:
        log.info("\n=== Live: %s ===", self.endpoint or "(loading .env)")
        self.log_test_filter()
        try:
            environment = self.prepare_live()
        except (LiveAbort, SystemExit) as error:
            self.record("live prerequisites", "live", False, 0.0, str(error))
            return
        self.record("live prerequisites", "live", True, 0.0)

        self.check_live_hygiene()
        if self.select("wheel install smoke"):
            self.run_wheel_install_smoke()
        self.run_live_fixture_cases(environment)
        self.run_seeded_org_sync_check(environment)
        self.run_saml_group_change_check(environment)
        self.run_live_permission_cycles(environment)
        self.check_live_hygiene()

    def check_live_hygiene(self) -> None:
        """Cheap small-state guard: no pending bindIDs should ever persist.

        Deep hygiene (grant-table counts, orphan cleanup, SAML fixtures,
        synthetic emails) is `uv run tests/setup.py`'s job before the run.
        """
        if not self.select("live hygiene"):
            return
        started = time.monotonic()
        try:
            pending = cast(
                "list[str]",
                self.graphql("query TestPending { usersWithPendingPermissions }", {})[
                    "usersWithPendingPermissions"
                ],
            )
        except Exception as exception:
            self.record("live hygiene: pending bindIDs", "live", False, 0.0, str(exception))
            return
        synthetic = [
            bind_id for bind_id in pending if bind_id.startswith(SYNTHETIC_PENDING_BINDID_PREFIX)
        ]
        unknown = [
            bind_id
            for bind_id in pending
            if not bind_id.startswith(SYNTHETIC_PENDING_BINDID_PREFIX)
        ]
        details: list[str] = []
        if synthetic:
            details.append(
                f"synthetic leftovers from an interrupted run: {synthetic[:5]} — "
                "`uv run tests/setup.py --apply` clears them"
            )
        if unknown:
            details.append(
                f"pending bindIDs of unknown origin: {unknown[:5]} — investigate "
                "before clearing (an empty setRepositoryPermissionsForUsers on the "
                "affected repo removes its pending rows)"
            )
        self.record(
            "live hygiene: pending bindIDs",
            "live",
            not pending,
            time.monotonic() - started,
            "none" if not pending else "; ".join(details),
        )

    def run_wheel_install_smoke(self) -> None:
        log.info("\n--- Live: wheel build + pip install smoke ---")
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="src-auth-perms-sync-wheel-") as temporary:
            temporary_path = Path(temporary)
            dist_directory = temporary_path / "dist"
            venv_directory = temporary_path / "venv"
            steps: list[list[str]] = [
                [
                    "uv",
                    "build",
                    "--wheel",
                    "--out-dir",
                    str(dist_directory),
                    "--no-create-gitignore",
                ],
                [sys.executable, "-m", "venv", str(venv_directory)],
            ]
            for step in steps:
                execution = self.stream_command(step)
                if execution.return_code != 0:
                    self.record(
                        "wheel install smoke",
                        "live",
                        False,
                        time.monotonic() - started,
                        f"{step[0]} exit {execution.return_code}",
                    )
                    return
            wheels = sorted(dist_directory.glob("*.whl"))
            if not wheels:
                self.record(
                    "wheel install smoke",
                    "live",
                    False,
                    time.monotonic() - started,
                    "no wheel produced",
                )
                return
            venv_python = venv_directory / "bin" / "python"
            for step in (
                [str(venv_python), "-m", "pip", "install", "--quiet", str(wheels[0])],
                [str(venv_directory / "bin" / "src-auth-perms-sync"), "--help"],
            ):
                execution = self.stream_command(step)
                if execution.return_code != 0:
                    self.record(
                        "wheel install smoke",
                        "live",
                        False,
                        time.monotonic() - started,
                        f"{step[0]} exit {execution.return_code}",
                    )
                    return
        self.record("wheel install smoke", "live", True, time.monotonic() - started)

    # -- install smoke (--install) -------------------------------------------------

    def run_install(self) -> None:
        """PyPI install smoke: pip-install the published package into a clean
        venv and run every --help command. Replaces dev/test-cli-pypi-install.sh."""
        python = self.arguments.install_python
        package = self.arguments.install_package
        log.info("\n=== Install smoke: %s via %s ===", package, python)
        with tempfile.TemporaryDirectory(prefix="src-auth-perms-sync-pypi-install-") as temporary:
            venv_directory = Path(temporary) / "venv"
            venv_python = venv_directory / "bin" / "python"
            cli_path = venv_directory / "bin" / "src-auth-perms-sync"
            setup_steps: tuple[tuple[str, list[str]], ...] = (
                (
                    f"install: create venv ({python})",
                    [python, "-m", "venv", str(venv_directory)],
                ),
                (
                    "install: upgrade pip",
                    [str(venv_python), "-m", "pip", "install", "--quiet", "--upgrade", "pip"],
                ),
                (
                    # Not --quiet: the log must show which version was resolved.
                    f"install: pip install {package}",
                    [str(venv_python), "-m", "pip", "install", package],
                ),
            )
            for name, command in setup_steps:
                started = time.monotonic()
                execution = self.stream_command(command)
                passed = execution.return_code == 0
                self.record(
                    name,
                    "install",
                    passed,
                    time.monotonic() - started,
                    "" if passed else f"exit {execution.return_code}",
                )
                if not passed:
                    return
            for help_arguments in ((), ("get",), ("set",), ("restore",), ("sync-saml-orgs",)):
                name = "install: src-auth-perms-sync " + " ".join((*help_arguments, "--help"))
                started = time.monotonic()
                execution = self.stream_command([str(cli_path), *help_arguments, "--help"])
                usage_shown = "usage: src-auth-perms-sync" in execution.output
                passed = execution.return_code == 0 and usage_shown
                detail = ""
                if execution.return_code != 0:
                    detail = f"exit {execution.return_code}"
                elif not usage_shown:
                    detail = "usage text missing from --help output"
                self.record(name, "install", passed, time.monotonic() - started, detail)

    def run_live_fixture_cases(self, environment: dict[str, str]) -> None:
        log.info("\n--- Live: tests.yaml cases against the real instance ---")
        for case_name, case in self.fixture_cases_for_mode("live"):
            if self.select(f"live fixture: {case_name}"):
                self.run_fixture_case_on_instance(case_name, case, environment, level="live")

    def fixture_cases_for_mode(self, mode: str) -> list[tuple[str, dict[str, Any]]]:
        """Return registry cases that opted into a real-instance mode."""
        from tests.e2e.case_runner import case_modes, load_e2e_cases

        return [
            (case_name, cast("dict[str, Any]", case))
            for case_name, case in load_e2e_cases().items()
            if mode in case_modes(case)
        ]

    def run_fixture_case_on_instance(
        self,
        case_name: str,
        case: dict[str, Any],
        environment: dict[str, str],
        level: str,
        run_main_case: Callable[[CliCase], CliResult] | None = None,
    ) -> None:
        """Run one registry case against the real instance.

        Only mutating `set` commands run the full seed -> apply -> verify ->
        restore cycle (their fixture files must reference real instance
        users/repos). Everything else replays directly: read-only commands,
        and convergent commands like `sync-saml-orgs --apply` that validate
        their own outcome. `{user}` in the command resolves to the configured
        test user.
        """
        from tests.e2e.case_runner import case_cli_arguments, expected_exit_code

        label = f"{level} fixture: {case_name}"
        if "cliCommand" not in case and "args" not in case:
            self.record(label, level, False, 0.0, f"{level} mode requires args or a cliCommand")
            return
        typed_case = cast("Any", case)
        arguments = tuple(
            token.replace("{user}", self.test_user)
            for token in case_cli_arguments(typed_case, case_name)
        )
        if arguments[:1] == ("restore",) and "--apply" in arguments:
            self.record(
                label,
                level,
                False,
                0.0,
                "registry cases must not run a bare restore --apply",
            )
            return
        if arguments[:1] == ("set",) and "--apply" in arguments:
            self.run_seeded_fixture_apply(case_name, case, environment, level, run_main_case)
            return
        expected_errors = tuple(cast("list[str]", case.get("expectedErrors", [])))
        expected_output = tuple(cast("list[str]", case.get("expectedOutput", [])))
        replay_case = CliCase(
            label,
            arguments,
            expected_exit_code(typed_case),
            expected_errors + expected_output,
        )
        if run_main_case is not None:
            run_main_case(replay_case)
        else:
            self.run_cli_case(replay_case, environment, level=level)

    def run_seeded_fixture_apply(
        self,
        case_name: str,
        case: dict[str, Any],
        environment: dict[str, str],
        level: str,
        run_main_case: Callable[[CliCase], CliResult] | None = None,
    ) -> None:
        """Seed the case's before-state, run it with --apply, verify, restore.

        Every involved repo — fixture state repos, exact rule names, and any
        declared `live.involvedRepos` — is read, seeded, verified, and
        restored, all SCOPED to those repos via direct GraphQL (seconds),
        never through the product's restore command (which performs a full
        instance capture: minutes at 10k users, and whole-instance restore
        semantics that clobber concurrently-running cases). Involved repos
        absent from after.json are canaries: they are seeded to their
        before-state (empty when undeclared) and must read back unchanged,
        which catches selectors matching wider than the case intends.
        """
        from tests.e2e.case_runner import case_cli_arguments

        label = f"{level} fixture: {case_name}"
        expected_errors = tuple(cast("list[str]", case.get("expectedErrors", [])))
        expected_mutations = cast("int | None", case.get("expectedMutations"))
        live_settings = cast("dict[str, Any]", case.get("live") or {})
        declared_repository_names = cast("list[str]", live_settings.get("involvedRepos") or [])

        before_grants = fixture_grants(case_name, "before.json")
        if before_grants is None:
            self.record(label, level, False, 0.0, "missing before.json")
            return
        after_grants = fixture_grants(case_name, "after.json") or before_grants
        before_pending = fixture_pending(case_name, "before.json") or {}
        after_pending = fixture_pending(case_name, "after.json") or before_pending
        rule_repository_names, selector_error = fixture_maps_repo_scope(
            case_name, has_declared_repository_names=bool(declared_repository_names)
        )
        if selector_error:
            self.record(label, level, False, 0.0, selector_error)
            return

        involved_names = sorted(
            set(before_grants)
            | set(after_grants)
            | rule_repository_names
            | set(declared_repository_names)
        )
        original_state: dict[str, tuple[int, set[str]]] = {}
        for repository_name in involved_names:
            read_back = self.read_back_repository_explicit_users(repository_name)
            if read_back is None:
                self.record(
                    label,
                    level,
                    False,
                    0.0,
                    f"repo {repository_name!r} does not exist on {self.endpoint}; live "
                    "cases must use real instance repo/user names in their fixture files",
                )
                return
            original_state[repository_name] = read_back
        repository_ids = {name: state[0] for name, state in original_state.items()}

        # Pending grants ride along: seeded with the before-state, expected to
        # survive the run exactly as the fixture says, and restored with the
        # original state. The read-backs and extra outcomes only engage when
        # the case or the instance actually involves pending grants.
        original_pending = self.read_back_pending_by_repository(set(involved_names))
        pending_in_scope = bool(
            original_pending
            or any(before_pending.get(name) for name in involved_names)
            or any(after_pending.get(name) for name in involved_names)
        )

        # Preflight: some modes (e.g. --users-without-explicit-perms) are only
        # deterministic when the named users hold no grants beyond the
        # involved repos. Assert that instance-wide before mutating anything.
        for username in cast("list[str]", live_settings.get("usersWithoutOtherGrants") or []):
            grant_names = self.read_back_explicit_repo_names(username)
            if grant_names is None:
                self.record(label, level, False, 0.0, f"user {username!r} not found")
                return
            outside_grants = sorted(grant_names - set(involved_names))
            if outside_grants:
                self.record(
                    label,
                    level,
                    False,
                    0.0,
                    f"precondition not met: {username} holds explicit grants outside "
                    f"the involved repos: {outside_grants[:5]}",
                )
                return

        # Preflight: SAML cases need the fabricated accounts from
        # tests/setup.py (setup.yaml samlAccounts). Verify groups through
        # the same GraphQL surface the product reads.
        required_saml_groups = cast(
            "dict[str, list[str]]", live_settings.get("requiredSamlGroups") or {}
        )
        for username, expected_groups in required_saml_groups.items():
            actual_groups = self.read_back_saml_groups(username)
            if actual_groups != sorted(expected_groups):
                self.record(
                    label,
                    level,
                    False,
                    0.0,
                    f"SAML fixture drift for {username}: expected {sorted(expected_groups)}, "
                    f"found {actual_groups}; run `uv run tests/setup.py --apply`",
                )
                return

        # Repos in scope but absent from after.json must come back exactly as
        # seeded — these are the canaries that detect widened selectors.
        expected_after = {
            name: after_grants.get(name, before_grants.get(name, set())) for name in involved_names
        }

        temporary_usernames = cast("list[str]", live_settings.get("temporaryUsers") or [])
        created_temporary_user_ids: dict[str, str] = {}
        try:
            for username in temporary_usernames:
                user_id = self.create_temporary_user(username)
                if user_id is None:
                    self.record(label, level, False, 0.0, f"could not create temp user {username}")
                    return
                created_temporary_user_ids[username] = user_id

            seeded = self.set_repository_states(
                f"{label} [seed before-state]",
                level,
                {
                    name: (
                        repository_ids[name],
                        before_grants.get(name, set()) | before_pending.get(name, set()),
                    )
                    for name in involved_names
                },
            )
            if not seeded:
                return
            self.check_repository_states(
                f"{label} [seed verified]",
                level,
                {name: before_grants.get(name, set()) for name in involved_names},
            )
            if pending_in_scope:
                self.check_pending_states(
                    f"{label} [seed pending verified]",
                    level,
                    {name: before_pending.get(name, set()) for name in involved_names},
                )

            today = datetime.datetime.now(datetime.UTC).date().isoformat()
            main_arguments = tuple(
                token.replace("{user}", self.test_user).replace("{today}", today)
                for token in case_cli_arguments(cast("Any", case), case_name)
            )
            main_case = CliCase(
                label,
                main_arguments,
                1 if expected_errors else 0,
                expected_errors,
            )
            if run_main_case is not None:
                result = run_main_case(main_case)
            else:
                result = self.run_cli_case(main_case, environment, level=level)
            if expected_mutations is not None:
                actual_mutations = mutations_succeeded_from_log(result.log_path) or 0
                self.record(
                    f"{label} [mutation count]",
                    level,
                    actual_mutations == expected_mutations,
                    0.0,
                    f"expected {expected_mutations}, got {actual_mutations}",
                )
            self.check_repository_states(f"{label} [state verified]", level, expected_after)
            if pending_in_scope:
                self.check_pending_states(
                    f"{label} [pending preserved]",
                    level,
                    {
                        name: after_pending.get(name, before_pending.get(name, set()))
                        for name in involved_names
                    },
                )
        finally:
            self.set_repository_states(
                f"{label} [restore original state]",
                level,
                {
                    name: (state[0], state[1] | original_pending.get(name, set()))
                    for name, state in original_state.items()
                },
            )
            self.check_repository_states(
                f"{label} [restore verified]",
                level,
                {name: state[1] for name, state in original_state.items()},
            )
            if pending_in_scope:
                self.check_pending_states(
                    f"{label} [restore pending verified]",
                    level,
                    {name: original_pending.get(name, set()) for name in involved_names},
                )
            for username, user_id in created_temporary_user_ids.items():
                self.delete_temporary_user(label, level, username, user_id)

    def create_temporary_user(self, username: str) -> str | None:
        """Create a throwaway user (created_at = now) for created-after cases."""
        try:
            data = self.graphql(
                "mutation TestCreateUser($username: String!) {"
                "  createUser(username: $username) { user { id } } }",
                {"username": username},
            )
            return cast(str, data["createUser"]["user"]["id"])
        except Exception as exception:
            log.error("createUser %s failed: %s", username, exception)
            return None

    def delete_temporary_user(self, label: str, level: str, username: str, user_id: str) -> None:
        """Hard-delete a temp user (also cascades its permission rows)."""
        try:
            self.graphql(
                "mutation TestDeleteUser($user: ID!) {"
                "  deleteUser(user: $user, hard: true) { alwaysNil } }",
                {"user": user_id},
            )
            self.record(f"{label} [temp user removed]", level, True, 0.0, username)
        except Exception as exception:
            self.record(
                f"{label} [temp user removed]",
                level,
                False,
                0.0,
                f"hard-delete of {username} failed: {exception}",
            )

    def set_repository_states(
        self, name: str, level: str, target_grants: dict[str, tuple[int, set[str]]]
    ) -> bool:
        """Directly overwrite involved repos' explicit users via GraphQL.

        Scoped replacement for seeding/restoring through the product's
        `restore` command, which always performs a full instance capture
        (~minutes at 10k users) even for a two-repo snapshot. Writing the
        involved repos directly keeps live functional cases scoped to
        seconds, and keeps concurrent cases from clobbering each other's
        repos. Returns True when every repo was written.
        """
        started = time.monotonic()
        failures: list[str] = []
        for repository_name, (database_id, usernames) in sorted(target_grants.items()):
            try:
                self.graphql(
                    SET_REPOSITORY_PERMISSIONS_MUTATION,
                    {
                        "repository": encode_repository_node_id(database_id),
                        "userPermissions": [
                            {"bindID": username, "permission": "READ"}
                            for username in sorted(usernames)
                        ],
                    },
                )
            except Exception as exception:
                failures.append(f"{repository_name}: {exception}")
        self.record(
            name,
            level,
            not failures,
            time.monotonic() - started,
            "; ".join(failures) if failures else f"{len(target_grants)} repo(s) written",
        )
        return not failures

    def check_repository_states(
        self, name: str, level: str, expected_grants: dict[str, set[str]]
    ) -> None:
        """Independently read back involved repos and compare explicit users."""
        started = time.monotonic()
        mismatches: list[str] = []
        for repository_name, expected_usernames in sorted(expected_grants.items()):
            read_back = self.read_back_repository_explicit_users(repository_name)
            if read_back is None:
                mismatches.append(f"{repository_name}: repo not found")
                continue
            actual_usernames = read_back[1]
            if actual_usernames != expected_usernames:
                missing = sorted(expected_usernames - actual_usernames)[:5]
                unexpected = sorted(actual_usernames - expected_usernames)[:5]
                mismatches.append(f"{repository_name}: missing={missing} unexpected={unexpected}")
        self.record(
            name,
            level,
            not mismatches,
            time.monotonic() - started,
            "; ".join(mismatches) if mismatches else f"{len(expected_grants)} repo(s) match",
        )

    # -- live: seeded organization sync ----------------------------------------

    def run_seeded_org_sync_check(self, environment: dict[str, str]) -> None:
        """Seeded `sync-saml-orgs --apply`: membership must be added AND removed.

        The fabricated SAML accounts (tests/setup.yaml samlAccounts) define
        the desired members of the throwaway orgs derived from the synthetic
        groups. Seeding makes one org diverge both ways — a member no SAML
        group justifies, and a missing member the group requires — then one
        `sync-saml-orgs --apply` must converge every synthetic-group org back
        to SAML truth, verified by an independent member read-back.
        """
        label = "live: sync-saml-orgs seeded"
        if not self.select(label):
            return
        log.info("\n--- Live: seeded organization sync (membership added AND removed) ---")
        from src_auth_perms_sync.orgs.sync import organization_name_for_saml_group

        saml_accounts = cast("dict[str, list[str]]", load_setup_config()["samlAccounts"])
        if not self.check_fabricated_saml_accounts(f"{label} [saml fixtures]", saml_accounts):
            return
        provider = self.saml_auth_provider()
        if provider is None:
            self.record(label, "live", False, 0.0, f"no SAML auth provider on {self.endpoint}")
            return

        members_by_group: dict[str, set[str]] = {}
        for username, groups in saml_accounts.items():
            for group in groups:
                members_by_group.setdefault(group, set()).add(username)
        expected_members_by_organization = {
            organization_name_for_saml_group(provider["configID"], group): usernames
            for group, usernames in members_by_group.items()
        }

        seeded_group = min(members_by_group)
        seeded_organization = organization_name_for_saml_group(provider["configID"], seeded_group)
        # The sync must REMOVE this member: no SAML group puts them in the org.
        unjustified_member = next(
            username
            for username in sorted(saml_accounts)
            if seeded_group not in saml_accounts[username]
        )
        # The sync must ADD this member back: the SAML group requires them.
        required_member = min(members_by_group[seeded_group])

        try:
            if not self.seed_organization_divergence(
                f"{label} [seed divergence]",
                seeded_organization,
                unjustified_member,
                required_member,
            ):
                return
            self.run_cli_case(
                CliCase(
                    f"{label} [apply]",
                    ("sync-saml-orgs", "--apply"),
                    0,
                    (ORGANIZATION_SYNC_VALIDATION_OK,),
                ),
                environment,
                level="live",
            )
            self.check_organization_members(
                f"{label} [member read-back]", expected_members_by_organization
            )
        finally:
            self.repair_organization_divergence(
                f"{label} [seed repaired]",
                seeded_organization,
                unjustified_member,
                required_member,
            )

    def seed_organization_divergence(
        self, name: str, organization_name: str, unjustified_member: str, required_member: str
    ) -> bool:
        """Force one org's membership to diverge from SAML truth in both directions.

        Adds `unjustified_member` and removes `required_member`. Creates the
        org when missing — createOrganization auto-adds the calling admin,
        which is one more unjustified member the sync must remove.
        """
        started = time.monotonic()
        try:
            looked_up = self.read_back_organization_members(organization_name)
            if looked_up is None:
                created = cast(
                    "dict[str, str]",
                    self.graphql(CREATE_ORGANIZATION_MUTATION, {"name": organization_name})[
                        "createOrganization"
                    ],
                )
                organization_id = created["id"]
                current_members: dict[str, str] = {}
            else:
                organization_id, current_members = looked_up
            if unjustified_member not in current_members:
                self.graphql(
                    ADD_ORGANIZATION_MEMBER_MUTATION,
                    {"organization": organization_id, "username": unjustified_member},
                )
            required_member_id = current_members.get(required_member)
            if required_member_id is not None:
                self.graphql(
                    REMOVE_ORGANIZATION_MEMBER_MUTATION,
                    {"organization": organization_id, "user": required_member_id},
                )
            seeded = self.read_back_organization_members(organization_name)
            seeded_members = set(seeded[1]) if seeded else set[str]()
            diverged = (
                unjustified_member in seeded_members and required_member not in seeded_members
            )
            self.record(
                name,
                "live",
                diverged,
                time.monotonic() - started,
                f"{organization_name} members now {sorted(seeded_members)}",
            )
            return diverged
        except Exception as exception:
            self.record(name, "live", False, time.monotonic() - started, str(exception))
            return False

    def check_organization_members(
        self, name: str, expected_members_by_organization: dict[str, set[str]]
    ) -> None:
        """Independently read back each org's member list and compare exactly."""
        started = time.monotonic()
        mismatches: list[str] = []
        for organization_name, expected_usernames in sorted(
            expected_members_by_organization.items()
        ):
            looked_up = self.read_back_organization_members(organization_name)
            if looked_up is None:
                mismatches.append(f"{organization_name}: org not found")
                continue
            actual_usernames = set(looked_up[1])
            if actual_usernames != expected_usernames:
                missing = sorted(expected_usernames - actual_usernames)[:5]
                unexpected = sorted(actual_usernames - expected_usernames)[:5]
                mismatches.append(f"{organization_name}: missing={missing} unexpected={unexpected}")
        self.record(
            name,
            "live",
            not mismatches,
            time.monotonic() - started,
            "; ".join(mismatches)
            if mismatches
            else f"{len(expected_members_by_organization)} org(s) match",
        )

    def repair_organization_divergence(
        self, name: str, organization_name: str, unjustified_member: str, required_member: str
    ) -> None:
        """Best-effort undo of seeded divergence when the sync did not converge.

        A successful sync already removed `unjustified_member` and re-added
        `required_member`, making this a silent no-op; after a failed run it
        puts the org back so later runs start from SAML truth.
        """
        started = time.monotonic()
        try:
            looked_up = self.read_back_organization_members(organization_name)
            if looked_up is None:
                return
            organization_id, current_members = looked_up
            repaired: list[str] = []
            if unjustified_member in current_members:
                self.graphql(
                    REMOVE_ORGANIZATION_MEMBER_MUTATION,
                    {"organization": organization_id, "user": current_members[unjustified_member]},
                )
                repaired.append(f"removed {unjustified_member}")
            if required_member not in current_members:
                self.graphql(
                    ADD_ORGANIZATION_MEMBER_MUTATION,
                    {"organization": organization_id, "username": required_member},
                )
                repaired.append(f"re-added {required_member}")
            if repaired:
                self.record(name, "live", True, time.monotonic() - started, "; ".join(repaired))
        except Exception as exception:
            self.record(name, "live", False, time.monotonic() - started, str(exception))

    # -- live: permissions follow a SAML group change ---------------------------

    def run_saml_group_change_check(self, environment: dict[str, str]) -> None:
        """A user added to a mapped SAML group must gain the mapped perms.

        Reuses the saml-group-live fixture's mapping (samlGroup → exact
        repos). Baseline: a full apply grants only the group's current
        members. Then the fabricated SAML account of a non-member gains the
        mapped group (the same SQL path tests/setup.py uses), the same apply
        runs again, and the user must now hold the mapped grants. The
        account and the repos are restored afterwards.
        """
        label = "live: perms follow saml group change"
        if not self.select(label):
            return
        log.info("\n--- Live: permissions follow a SAML group change ---")
        import yaml

        from tests import setup as instance_setup

        setup_config = load_setup_config()
        saml_accounts = cast("dict[str, list[str]]", setup_config["samlAccounts"])
        if not self.check_fabricated_saml_accounts(f"{label} [saml fixtures]", saml_accounts):
            return
        provider = self.saml_auth_provider()
        if provider is None:
            self.record(label, "live", False, 0.0, f"no SAML auth provider on {self.endpoint}")
            return

        maps_path = FIXTURES_DIR / SAML_GROUP_CHANGE_CASE / "maps.yaml"
        loaded_maps = cast("dict[str, Any]", yaml.safe_load(maps_path.read_text(encoding="utf-8")))
        rules = cast("list[dict[str, Any]]", loaded_maps["maps"])
        mapped_group = cast(
            str,
            cast("dict[str, Any]", cast("dict[str, Any]", rules[0]["users"])["authProvider"])[
                "samlGroup"
            ],
        )
        mapped_repository_names, selector_error = fixture_maps_repo_scope(
            SAML_GROUP_CHANGE_CASE, has_declared_repository_names=False
        )
        if selector_error or not mapped_repository_names:
            self.record(label, "live", False, 0.0, selector_error or "no mapped repos")
            return

        baseline_members = {
            username for username, groups in saml_accounts.items() if mapped_group in groups
        }
        changed_user = next(
            username
            for username in sorted(saml_accounts)
            if mapped_group not in saml_accounts[username]
        )
        original_groups = list(saml_accounts[changed_user])
        kubectl_config = cast("dict[str, Any]", setup_config["kubectl"])
        account_id = str(cast("dict[str, Any]", setup_config["users"])["emailTemplate"]).replace(
            "{username}", changed_user
        )

        original_state: dict[str, tuple[int, set[str]]] = {}
        for repository_name in sorted(mapped_repository_names):
            read_back = self.read_back_repository_explicit_users(repository_name)
            if read_back is None:
                self.record(
                    label,
                    "live",
                    False,
                    0.0,
                    f"repo {repository_name!r} does not exist on {self.endpoint}",
                )
                return
            original_state[repository_name] = read_back

        set_arguments = ("set", "--full", "--apply", "--no-backup", "--maps-path", str(maps_path))
        saml_account_changed = False
        try:
            if not self.set_repository_states(
                f"{label} [seed before-state]",
                "live",
                {name: (state[0], set[str]()) for name, state in original_state.items()},
            ):
                return
            self.apply_maps_and_check_grants(
                label,
                "baseline",
                environment,
                set_arguments,
                mapped_repository_names,
                baseline_members,
            )

            instance_setup.upsert_saml_account(
                kubectl_config,
                changed_user,
                [*original_groups, mapped_group],
                service_id=provider["serviceID"],
                client_id=provider["clientID"],
                account_id=account_id,
            )
            saml_account_changed = True
            expected_groups = sorted([*original_groups, mapped_group])
            actual_groups = self.read_back_saml_groups(changed_user)
            self.record(
                f"{label} [saml group added]",
                "live",
                actual_groups == expected_groups,
                0.0,
                f"{changed_user}: expected {expected_groups}, found {actual_groups}",
            )
            if actual_groups != expected_groups:
                return

            self.apply_maps_and_check_grants(
                label,
                "after group change",
                environment,
                set_arguments,
                mapped_repository_names,
                baseline_members | {changed_user},
            )
        finally:
            if saml_account_changed:
                self.restore_saml_account(
                    f"{label} [saml account restored]",
                    kubectl_config,
                    changed_user,
                    original_groups,
                    service_id=provider["serviceID"],
                    client_id=provider["clientID"],
                    account_id=account_id,
                )
            self.set_repository_states(f"{label} [restore original state]", "live", original_state)
            self.check_repository_states(
                f"{label} [restore verified]",
                "live",
                {name: state[1] for name, state in original_state.items()},
            )

    def apply_maps_and_check_grants(
        self,
        label: str,
        step: str,
        environment: dict[str, str],
        set_arguments: tuple[str, ...],
        repository_names: set[str],
        expected_usernames: set[str],
    ) -> None:
        """Run one mapped apply, then verify mutation count and repo grants."""
        result = self.run_cli_case(
            CliCase(f"{label} [{step} apply]", set_arguments, 0), environment, level="live"
        )
        expected_mutations = len(repository_names)
        actual_mutations = mutations_succeeded_from_log(result.log_path) or 0
        self.record(
            f"{label} [{step} mutation count]",
            "live",
            actual_mutations == expected_mutations,
            0.0,
            f"expected {expected_mutations}, got {actual_mutations}",
        )
        self.check_repository_states(
            f"{label} [{step} grants]",
            "live",
            {name: expected_usernames for name in sorted(repository_names)},
        )

    def restore_saml_account(
        self,
        name: str,
        kubectl_config: dict[str, Any],
        username: str,
        original_groups: list[str],
        *,
        service_id: str,
        client_id: str,
        account_id: str,
    ) -> None:
        """Put a fabricated SAML account back to its setup.yaml groups."""
        from tests import setup as instance_setup

        started = time.monotonic()
        try:
            instance_setup.upsert_saml_account(
                kubectl_config,
                username,
                original_groups,
                service_id=service_id,
                client_id=client_id,
                account_id=account_id,
            )
            restored_groups = self.read_back_saml_groups(username)
            self.record(
                name,
                "live",
                restored_groups == sorted(original_groups),
                time.monotonic() - started,
                f"{username}: expected {sorted(original_groups)}, found {restored_groups}",
            )
        except Exception as exception:
            self.record(
                name,
                "live",
                False,
                time.monotonic() - started,
                f"{exception}; run `uv run tests/setup.py --apply`",
            )

    def read_back_pending_repo_names(self, bind_id: str) -> set[str]:
        """Return the repo names a pending bindID has explicit-API grants on.

        `authorizedUserRepositories` falls back to the pending-permissions
        store when the bindID matches no user — the only API that exposes a
        pending bindID's repos.
        """
        names: set[str] = set()
        after_cursor: str | None = None
        while True:
            data = self.graphql(
                PENDING_REPOS_READ_BACK_QUERY,
                {"bindID": bind_id, "first": READ_BACK_PAGE_SIZE, "after": after_cursor},
            )
            connection = cast("dict[str, Any]", data["authorizedUserRepositories"])
            for node in cast("list[dict[str, Any]]", connection["nodes"]):
                names.add(cast(str, node["name"]))
            page_info = cast("dict[str, Any]", connection["pageInfo"])
            if not page_info.get("hasNextPage"):
                return names
            after_cursor = cast("str | None", page_info.get("endCursor"))

    def read_back_pending_by_repository(self, repository_names: set[str]) -> dict[str, set[str]]:
        """Return {involved repo name: pending bindIDs} read from the instance."""
        pending_by_repository: dict[str, set[str]] = {}
        bind_ids = cast(
            "list[str]",
            self.graphql("query TestPending { usersWithPendingPermissions }", {})[
                "usersWithPendingPermissions"
            ],
        )
        for bind_id in bind_ids:
            for repository_name in self.read_back_pending_repo_names(bind_id):
                if repository_name in repository_names:
                    pending_by_repository.setdefault(repository_name, set()).add(bind_id)
        return pending_by_repository

    def check_pending_states(
        self, name: str, level: str, expected_pending: dict[str, set[str]]
    ) -> None:
        """Independently read back involved repos' pending bindIDs and compare."""
        started = time.monotonic()
        actual_pending = self.read_back_pending_by_repository(set(expected_pending))
        mismatches: list[str] = []
        for repository_name, expected_bind_ids in sorted(expected_pending.items()):
            actual_bind_ids = actual_pending.get(repository_name, set())
            if actual_bind_ids != expected_bind_ids:
                missing = sorted(expected_bind_ids - actual_bind_ids)[:5]
                unexpected = sorted(actual_bind_ids - expected_bind_ids)[:5]
                mismatches.append(f"{repository_name}: missing={missing} unexpected={unexpected}")
        self.record(
            name,
            level,
            not mismatches,
            time.monotonic() - started,
            "; ".join(mismatches) if mismatches else f"{len(expected_pending)} repo(s) match",
        )

    def run_live_permission_cycles(self, environment: dict[str, str]) -> None:
        # The baseline get is a prerequisite for both cycles, so it runs when
        # any of them is selected.
        want_user_cycle = self.select("live: set --users apply", "user cycle")
        # The full cycle applies the ROOT maps.yaml to the whole instance
        # (10k users x ~1,150 repos) — an instance-wide stress run that has
        # crashed the test instance's Postgres. Opt-in only:
        #   uv run tests/run.py --live "full cycle"
        want_full_cycle = self.explicitly_selected("live: set --full", "full cycle")
        if want_full_cycle:
            self.filter_matched_count += 1
        want_baseline = (
            want_user_cycle or want_full_cycle or self.select("live: get user baseline", "baseline")
        )
        if not want_baseline:
            return
        log.info("\n--- Live: permission cycles with independent read-back ---")
        baseline = self.run_cli_case(
            CliCase(
                "live: get user baseline",
                ("get", "--users", self.test_user),
                0,
                ("Wrote before-snapshot",),
            ),
            environment,
            level="live",
        )
        baseline_names = self.user_scoped_snapshot_repo_names(baseline, self.test_user)
        if baseline_names is None:
            self.record("live: baseline artifact", "live", False, 0.0, "missing before.json")
            return
        self.check_read_back("live: baseline read-back", self.test_user, baseline_names)
        if want_user_cycle:
            self.run_user_scoped_cycle(environment, baseline_names)
        if want_full_cycle:
            self.run_full_cycle(environment, baseline_names)

    def run_user_scoped_cycle(self, environment: dict[str, str], baseline: set[str]) -> None:
        apply_result = self.run_cli_case(
            CliCase(
                "live: set --users apply",
                ("set", "--users", self.test_user, "--apply"),
                0,
                must_contain_one_of=(
                    "VALIDATION OK",
                    "All selected users already have the mapped explicit grants",
                ),
            ),
            environment,
            level="live",
        )
        try:
            expected = self.user_scoped_snapshot_repo_names(apply_result, self.test_user)
            if expected is None:
                self.record("live: set --users read-back", "live", False, 0.0, "missing after.json")
            else:
                self.check_read_back("live: set --users read-back", self.test_user, expected)
        finally:
            if apply_result.run_directory is not None:
                snapshot_path = apply_result.run_directory / "before.json"
                # Dry run first: it must plan without mutating. The apply
                # restore plus the baseline read-back below prove that.
                self.run_cli_case(
                    CliCase(
                        "live: restore user scope dry-run",
                        ("restore", "--restore-path", str(snapshot_path)),
                        0,
                        must_contain_one_of=(
                            "Dry run complete",
                            "Scoped restore target already matches current state",
                        ),
                    ),
                    environment,
                    level="live",
                )
                self.run_cli_case(
                    CliCase(
                        "live: restore user scope",
                        ("restore", "--restore-path", str(snapshot_path), "--apply"),
                        0,
                        must_contain_one_of=(
                            "VALIDATION OK",
                            "Scoped restore target already matches current state",
                        ),
                    ),
                    environment,
                    level="live",
                )
        self.check_read_back("live: post-restore equals baseline", self.test_user, baseline)

    def run_full_cycle(self, environment: dict[str, str], baseline: set[str]) -> None:
        dry_run = self.run_cli_case(
            CliCase(
                "live: set --full dry-run",
                ("set", "--full"),
                0,
                ("Dry run complete",),
            ),
            environment,
            level="live",
        )
        if dry_run.run_directory is None:
            self.record("live: full cycle", "live", False, 0.0, "dry run produced no artifacts")
            return
        baseline_snapshot = dry_run.run_directory / "before.json"
        projected_after = dry_run.run_directory / "after.json"

        self.run_cli_case(
            CliCase(
                "live: set --full apply",
                ("set", "--full", "--apply", "--no-backup"),
                0,
                must_contain_one_of=("VALIDATION OK", "Apply done"),
            ),
            environment,
            level="live",
        )
        try:
            self.check_full_apply_read_back(projected_after)
        finally:
            # Dry run first: it must plan without mutating. The apply
            # restore plus the baseline read-back below prove that.
            self.run_cli_case(
                CliCase(
                    "live: restore full baseline dry-run",
                    (
                        "restore",
                        "--restore-path",
                        str(baseline_snapshot),
                        "--no-backup",
                        "--parallelism",
                        "1",
                    ),
                    0,
                    must_contain_one_of=(
                        "Dry run complete",
                        "Nothing to restore",
                    ),
                ),
                environment,
                level="live",
            )
            self.run_cli_case(
                CliCase(
                    "live: restore full baseline",
                    (
                        "restore",
                        "--restore-path",
                        str(baseline_snapshot),
                        "--apply",
                        "--no-backup",
                        "--parallelism",
                        "1",
                    ),
                    0,
                    must_contain_one_of=(
                        "VALIDATION OK",
                        "Restore done",
                        "Nothing to restore",
                    ),
                ),
                environment,
                level="live",
            )
        self.check_read_back("live: post-full-restore equals baseline", self.test_user, baseline)

    def check_full_apply_read_back(self, projected_after: Path) -> None:
        if not projected_after.is_file():
            self.record(
                "live: full apply read-back", "live", False, 0.0, f"missing {projected_after}"
            )
            return
        snapshot = cast("dict[str, Any]", json.loads(projected_after.read_text(encoding="utf-8")))
        repos = cast("dict[str, dict[str, Any]]", snapshot.get("repos", {}))
        repo_names_by_user: dict[str, set[str]] = {}
        for repo in repos.values():
            for username in cast("list[str]", repo.get("users", [])):
                repo_names_by_user.setdefault(username, set()).add(cast(str, repo["name"]))
        sampled_users = [self.test_user] + [
            username
            for username, _ in sorted(
                repo_names_by_user.items(), key=lambda entry: len(entry[1]), reverse=True
            )
            if username != self.test_user
        ][: FULL_APPLY_READ_BACK_USER_SAMPLE - 1]
        for username in sampled_users:
            expected = repo_names_by_user.get(username, set())
            self.check_read_back(f"live: full apply read-back ({username})", username, expected)

    def user_scoped_snapshot_repo_names(self, result: CliResult, username: str) -> set[str] | None:
        """Read one user's repo names from a run's snapshot artifact.

        Handles both artifact shapes: user-scoped snapshots (`set --users`,
        keyed by username) and repo-keyed snapshots (`get`, keyed by repo ID
        with per-repo user lists).
        """
        if result.run_directory is None:
            return None
        # `set --users` writes after.json; `get --users` writes only before.json.
        for artifact_name in ("after.json", "before.json"):
            artifact_path = result.run_directory / artifact_name
            if not artifact_path.is_file():
                continue
            snapshot = cast("dict[str, Any]", json.loads(artifact_path.read_text(encoding="utf-8")))
            if snapshot.get("snapshot_kind") == "user_scope":
                users = cast("dict[str, dict[str, Any]]", snapshot.get("users", {}))
                user_entry = users.get(username)
                if user_entry is None:
                    return set()
                return {
                    cast(str, repo["name"])
                    for repo in cast("list[dict[str, Any]]", user_entry["repos"])
                }
            repos = cast("dict[str, dict[str, Any]]", snapshot.get("repos", {}))
            return {
                cast(str, repo["name"])
                for repo in repos.values()
                if username in cast("list[str]", repo.get("users", []))
            }
        return None

    # -- performance -------------------------------------------------------------

    def performance_variants(self) -> list[tuple[str, tuple[str, ...]]]:
        candidate = ("candidate", self.cli_executable)
        if not self.arguments.baseline_command:
            return [candidate]
        baseline = ("baseline", tuple(shlex.split(self.arguments.baseline_command)))
        return [baseline, candidate]

    def run_performance(self) -> None:
        log.info(
            "\n=== Performance: repeat=%d, jaeger_trace_limit=%d ===",
            self.arguments.repeat,
            self.arguments.jaeger_trace_limit,
        )
        self.log_test_filter()
        try:
            environment = self.prepare_live()
        except (LiveAbort, SystemExit) as error:
            self.record("performance prerequisites", "performance", False, 0.0, str(error))
            return
        trace_fetcher: JaegerTraceFetcher | None = None
        if self.arguments.jaeger_trace_limit > 0:
            trace_fetcher = JaegerTraceFetcher(
                endpoint=self.endpoint,
                access_token=self.access_token,
                artifact_prefix=self.artifact_prefix,
                limit=self.arguments.jaeger_trace_limit,
            )
        load_monitor: SourcegraphLoadMonitor | None = None
        if self.arguments.monitor_sourcegraph_load:
            load_monitor = SourcegraphLoadMonitor(
                self.arguments, with_suffix_name(self.artifact_prefix, "-sourcegraph-load")
            )
        rows: list[dict[str, object]] = []
        try:
            if load_monitor is not None:
                load_monitor.start()
            for variant_name, variant_executable in self.performance_variants():
                for iteration in range(1, self.arguments.repeat + 1):
                    rows.extend(
                        self.run_performance_iteration(
                            environment,
                            variant_name,
                            variant_executable,
                            iteration,
                            trace_fetcher,
                        )
                    )
        finally:
            if load_monitor is not None:
                load_monitor.stop()
        self.write_performance_report(rows)
        self.check_memory_regressions(rows)

    def run_performance_iteration(
        self,
        environment: dict[str, str],
        variant_name: str,
        variant_executable: tuple[str, ...],
        iteration: int,
        trace_fetcher: JaegerTraceFetcher | None,
    ) -> list[dict[str, object]]:
        performance_flags = ("--fetch-sg-traces", "--sample-interval", "1")
        rows: list[dict[str, object]] = []

        def measure(case: CliCase) -> CliResult:
            result = self.run_cli_case(
                case,
                environment,
                level="performance",
                extra_arguments=performance_flags,
                executable=variant_executable,
                external_sample_interval=self.arguments.external_sample_interval,
            )
            jaeger_found = 0
            jaeger_requested = 0
            if trace_fetcher is not None and result.log_path is not None:
                jaeger_found, jaeger_requested = trace_fetcher.collect_for_run(
                    f"{variant_name}-{strip_iteration_suffix(case.name)}", result.log_path
                )
            rows.append(
                self.performance_row(
                    case.name, variant_name, iteration, result, jaeger_found, jaeger_requested
                )
            )
            return result

        # The dry run is also the baseline snapshot source for the apply +
        # restore pair, so selecting the apply implies running the dry run.
        want_apply = self.select("perf: set --full apply", "perf: restore full")
        want_dry_run = want_apply or self.select("perf: set --full dry-run")

        if want_dry_run:
            dry_run = measure(
                CliCase(f"perf: set --full dry-run [{iteration}]", ("set", "--full"), 0)
            )
            if want_apply and dry_run.run_directory is not None:
                baseline_snapshot = dry_run.run_directory / "before.json"
                measure(
                    CliCase(
                        f"perf: set --full apply [{iteration}]",
                        ("set", "--full", "--apply", "--no-backup"),
                        0,
                    )
                )
                measure(
                    CliCase(
                        f"perf: restore full [{iteration}]",
                        (
                            "restore",
                            "--restore-path",
                            str(baseline_snapshot),
                            "--apply",
                            "--no-backup",
                            "--parallelism",
                            "1",
                        ),
                        0,
                    )
                )
        for case_name, case in self.fixture_cases_for_mode("performance"):
            if self.select(f"performance fixture: {case_name}"):
                self.run_fixture_case_on_instance(
                    case_name,
                    case,
                    environment,
                    level="performance",
                    run_main_case=measure,
                )
        return rows

    def performance_row(
        self,
        case_name: str,
        variant_name: str,
        iteration: int,
        result: CliResult,
        jaeger_found: int,
        jaeger_requested: int,
    ) -> dict[str, object]:
        summary = read_run_log_summary(result.log_path)
        duration_ms: float | None = None
        peak_rss_mb: float | None = None
        if summary.run_record is not None:
            duration_ms = float_field(summary.run_record, "duration_ms")
            peak_rss_mb = float_field(summary.run_record, "peak_rss_mb")
        return {
            "case": strip_iteration_suffix(case_name),
            "variant": variant_name,
            "iteration": iteration,
            "exit_code": result.return_code,
            "elapsed_seconds": round(result.elapsed_seconds, 3),
            "duration_ms": duration_ms if duration_ms is not None else "",
            "peak_rss_mb": peak_rss_mb if peak_rss_mb is not None else "",
            "sampled_peak_rss_mb": (
                summary.sampled_peak_rss_mb if summary.sampled_peak_rss_mb is not None else ""
            ),
            "external_peak_rss_mb": (
                round(result.external_peak_rss_mb, 1)
                if result.external_peak_rss_mb is not None
                else ""
            ),
            "max_num_fds": summary.max_num_fds if summary.max_num_fds is not None else "",
            "max_num_threads": (
                summary.max_num_threads if summary.max_num_threads is not None else ""
            ),
            "max_process_cpu_percent": (
                summary.max_process_cpu_percent
                if summary.max_process_cpu_percent is not None
                else ""
            ),
            "jaeger_traces_found": jaeger_found,
            "jaeger_traces_requested": jaeger_requested,
            "log_path": str(result.log_path) if result.log_path is not None else "",
        }

    def write_performance_report(self, rows: list[dict[str, object]]) -> None:
        if not rows:
            return
        report_path = with_suffix_name(self.artifact_prefix, "-results.tsv")
        columns = list(rows[0].keys())
        lines = ["\t".join(columns)]
        lines.extend("\t".join(str(row[column]) for column in columns) for row in rows)
        report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        log.info("Wrote performance results: %s", report_path)

        log.info("\nMedians per case and variant:")
        for case_name, variant_name in sorted(
            {(cast(str, row["case"]), cast(str, row["variant"])) for row in rows}
        ):
            elapsed = performance_median(rows, case_name, variant_name, "elapsed_seconds")
            peak_rss = performance_median(rows, case_name, variant_name, "peak_rss_mb")
            log.info(
                "  %-28s %-10s elapsed=%ss peak_rss=%sMiB",
                case_name,
                variant_name,
                f"{elapsed:.1f}" if elapsed is not None else "n/a",
                f"{peak_rss:.1f}" if peak_rss is not None else "n/a",
            )

    def check_memory_regressions(self, rows: list[dict[str, object]]) -> None:
        """Compare candidate vs baseline median peak RSS against the thresholds."""
        if not self.arguments.baseline_command:
            return
        threshold_percent = self.arguments.fail_on_memory_regression_percent
        threshold_mib = self.arguments.fail_on_memory_regression_mib
        for case_name in sorted({cast(str, row["case"]) for row in rows}):
            baseline_rss = performance_median(rows, case_name, "baseline", "peak_rss_mb")
            candidate_rss = performance_median(rows, case_name, "candidate", "peak_rss_mb")
            if baseline_rss is None or candidate_rss is None:
                continue
            delta_mib = candidate_rss - baseline_rss
            delta_percent = (delta_mib / baseline_rss * 100.0) if baseline_rss else 0.0
            log.info(
                "  regression check %-28s baseline=%.1fMiB candidate=%.1fMiB "
                "delta=%+.1fMiB (%+.1f%%)",
                case_name,
                baseline_rss,
                candidate_rss,
                delta_mib,
                delta_percent,
            )
            exceeded_percent = threshold_percent is not None and delta_percent > threshold_percent
            exceeded_mib = threshold_mib is not None and delta_mib > threshold_mib
            if exceeded_percent or exceeded_mib:
                self.record(
                    f"memory regression: {case_name}",
                    "performance",
                    False,
                    0.0,
                    f"candidate peak RSS {candidate_rss:.1f}MiB vs baseline "
                    f"{baseline_rss:.1f}MiB ({delta_mib:+.1f}MiB, {delta_percent:+.1f}%)",
                )

    # -- summary -------------------------------------------------------------------

    def print_summary(self) -> int:
        if self.arguments.test_filter and self.filter_matched_count == 0:
            self.record(
                "test filter",
                self.arguments.level,
                False,
                0.0,
                f"filter {list(self.arguments.test_filter)} matched none of the "
                f"{len(self.skipped_check_names)} available checks",
            )
        log.info("\n%s", "=" * 72)
        passed = sum(1 for result in self.results if result.passed)
        failed = len(self.results) - passed
        for result in self.results:
            if not result.passed:
                log.error("FAILED [%s] %s — %s", result.level, result.name, result.detail)
        skipped_suffix = (
            f" Skipped {len(self.skipped_check_names)} check(s) not matching the test filter."
            if self.skipped_check_names
            else ""
        )
        log.log(
            logging.ERROR if failed else logging.INFO,
            "Summary: %d passed, %d failed, %d total.%s",
            passed,
            failed,
            len(self.results),
            skipped_suffix,
        )
        return 1 if failed else 0


# ---------------------------------------------------------------------------
# Randomized permission invariants
#
# Each check generates random instance states and mapping rules, runs the
# REAL `set --full --apply` code path against the in-memory fixture client,
# and asserts a safety property that must hold for every input:
#
#   1. Grants for combined rules equal the union of each rule's grants.
#   2. Adding a filter to a rule never widens the grant set (README:
#      "adding multiple filters casts a smaller net").
#   3. Applying the same maps twice is idempotent (zero second-run mutations).
#   4. The final state matches an independent oracle computed directly from
#      the mapping layer; unmapped repos are untouched.
# ---------------------------------------------------------------------------

PROPERTY_GROUPS = ("engineering", "lob1", "admins")
PROPERTY_EMAIL_DOMAINS = ("example.com", "other.test")
PROPERTY_OKTA_SERVICE_ID = "http://www.okta.com/test123"
PROPERTY_OKTA_CLIENT_ID = "https://sourcegraph.test/.auth/saml/metadata"


@dataclass(frozen=True)
class PropertyCheckOutcome:
    name: str
    passed: bool
    seconds: float
    detail: str = ""


def random_fixture_state(rng: random.Random, with_grants: bool) -> FixtureState:
    """Generate a random in-memory instance: providers, users, repos, grants."""
    builtin_provider = {
        "serviceType": "builtin",
        "serviceID": "",
        "clientID": "",
        "displayName": "Builtin username/password",
        "isBuiltin": True,
        "configID": "",
    }
    okta_provider = {
        "serviceType": "saml",
        "serviceID": PROPERTY_OKTA_SERVICE_ID,
        "clientID": PROPERTY_OKTA_CLIENT_ID,
        "displayName": "Okta",
        "isBuiltin": False,
        "configID": "okta",
    }
    services = [
        {
            "id": 1,
            "kind": "GITHUB",
            "displayName": "GitHub",
            "url": "https://github.com/",
            "config": "{}",
        },
        {
            "id": 2,
            "kind": "BITBUCKETSERVER",
            "displayName": "Bitbucket",
            "url": "https://bitbucket.test/",
            "config": '{"username": "LOB1-SA1"}',
        },
    ]

    usernames: list[str] = []
    users: list[dict[str, Any]] = []
    for index in range(1, rng.randint(4, 9) + 1):
        username = f"user{index:02d}"
        usernames.append(username)
        accounts: list[dict[str, Any]] = []
        if rng.random() < 0.7:
            groups = [group for group in PROPERTY_GROUPS if rng.random() < 0.5]
            accounts.append(
                {
                    "serviceType": "saml",
                    "serviceID": PROPERTY_OKTA_SERVICE_ID,
                    "clientID": PROPERTY_OKTA_CLIENT_ID,
                    "accountData": {
                        "Values": {"groups": {"Values": [{"Value": group} for group in groups]}}
                    },
                }
            )
        users.append(
            {
                "id": index,
                "username": username,
                "builtinAuth": not accounts,
                "createdAt": f"2026-01-{index:02d}T00:00:00Z",
                "emails": [
                    {
                        "email": f"{username}@{rng.choice(PROPERTY_EMAIL_DOMAINS)}",
                        "verified": True,
                    }
                ],
                "externalAccounts": accounts,
            }
        )

    repos: list[dict[str, Any]] = []
    for index in range(1, rng.randint(5, 12) + 1):
        service_id = rng.choice((1, 2))
        host = "github.com" if service_id == 1 else "bitbucket.test"
        organization = rng.choice(("acme", "lob1"))
        grants = [username for username in usernames if rng.random() < 0.25] if with_grants else []
        # Pending grants (bindIDs without a matching user) appear on some
        # repos so every randomized run exercises pending preservation.
        pending = [f"pending_user{index:02d}"] if rng.random() < 0.3 else []
        repos.append(
            {
                "id": 100 + index,
                "name": f"{host}/{organization}/repo{index:02d}",
                "externalServiceID": service_id,
                "explicitPermissionsUsers": grants,
                "pendingBindIDs": pending,
            }
        )

    return cast(
        "FixtureState",
        {
            "endpoint": "https://fixture.sourcegraph.test",
            "authProviders": [builtin_provider, okta_provider],
            "externalServices": services,
            "users": users,
            "repos": repos,
        },
    )


def random_mapping_rule(
    rng: random.Random, state: FixtureState, rule_number: int
) -> dict[str, Any]:
    """Generate one random mapping rule referencing the generated state."""
    usernames = [user["username"] for user in state["users"]]
    repo_names = [repository["name"] for repository in state["repos"]]
    emails = [user["emails"][0]["email"] for user in state["users"]]

    auth_provider_matcher: dict[str, str] = {"configID": "okta"}
    if rng.random() < 0.7:
        auth_provider_matcher["samlGroup"] = rng.choice(PROPERTY_GROUPS)
    user_filter_choices: list[tuple[str, object]] = [
        ("usernames", rng.sample(usernames, rng.randint(1, min(3, len(usernames))))),
        ("usernameRegexes", [f"^user0[{rng.randint(1, 9)}-9]"]),
        ("emails", rng.sample(emails, rng.randint(1, min(2, len(emails))))),
        ("emailRegexes", [f"@{re.escape(rng.choice(PROPERTY_EMAIL_DOMAINS))}$"]),
        ("authProvider", auth_provider_matcher),
    ]
    repo_filter_choices: list[tuple[str, object]] = [
        ("names", rng.sample(repo_names, rng.randint(1, min(3, len(repo_names))))),
        (
            "nameRegexes",
            [f"^{re.escape(rng.choice(('github.com/', 'bitbucket.test/', 'github.com/acme/')))}"],
        ),
        ("codeHostConnection", {"kind": rng.choice(("GITHUB", "BITBUCKETSERVER"))}),
    ]
    return {
        "name": f"Random rule {rule_number}",
        "users": dict(rng.sample(user_filter_choices, rng.randint(1, 2))),
        "repos": dict(rng.sample(repo_filter_choices, rng.randint(1, 2))),
    }


def run_set_full_in_memory(
    state: FixtureState, rules: list[dict[str, Any]], maps_path: Path
) -> tuple[FixtureState, int]:
    """Run the real `set --full --apply` code path against an in-memory instance.

    Backups stay enabled (redirected into the maps temp directory) so the runs
    exercise the real snapshot capture and the short-circuit filter that skips
    repos already at the desired state.
    """
    import src_py_lib as src
    import yaml

    from src_auth_perms_sync import cli
    from src_auth_perms_sync.shared import backups
    from tests.e2e.case_runner import FakeSourcegraphClient

    maps_path.write_text(yaml.safe_dump({"maps": rules}, sort_keys=False), encoding="utf-8")
    client = FakeSourcegraphClient(state)
    config = cli.Config(
        src_endpoint=state["endpoint"],
        src_access_token="invariant-token",
    ).model_copy(
        update={
            "maps_path": maps_path,
            "apply": True,
            "no_backup": False,
            "parallelism": 1,
            "full": True,
        }
    )
    command = cli.resolve_command("set", config)
    artifacts_directory = maps_path.parent / f"artifacts-{time.monotonic_ns()}"
    with (
        backups.run_artifacts_context(artifacts_directory, backups.backup_timestamp()),
        ThreadPoolExecutor(max_workers=1) as worker_pool,
    ):
        cli.run_command(config, command, cast("src.SourcegraphClient", client), worker_pool)
    return client.export_state(), client.mutation_count


def grant_pairs(state: FixtureState) -> set[tuple[int, str]]:
    return {
        (repository["id"], username)
        for repository in state["repos"]
        for username in repository["explicitPermissionsUsers"]
    }


def pending_pairs(state: FixtureState) -> set[tuple[int, str]]:
    return {
        (repository["id"], bind_id)
        for repository in state["repos"]
        for bind_id in repository.get("pendingBindIDs", [])
    }


def oracle_expected_grants(state: FixtureState, rules: list[dict[str, Any]]) -> dict[int, set[str]]:
    """Independently compute per-repo grants straight from the mapping layer."""
    import src_py_lib as src

    from src_auth_perms_sync.permissions import mapping
    from src_auth_perms_sync.permissions import types as permission_types
    from src_auth_perms_sync.shared import types as shared_types

    users = [
        cast(
            "shared_types.User",
            {
                "id": f"user-{user['id']}",
                "username": user["username"],
                "builtinAuth": user["builtinAuth"],
                "externalAccounts": {"nodes": list(user["externalAccounts"])},
                "emails": list(user["emails"]),
            },
        )
        for user in state["users"]
    ]
    services_by_id = {
        service["id"]: cast(
            "permission_types.ExternalService",
            {
                "id": src.encode_sourcegraph_node_id("ExternalService", service["id"]),
                "kind": service["kind"],
                "displayName": service["displayName"],
                "url": service["url"],
                "config": service["config"],
            },
        )
        for service in state["externalServices"]
    }
    repos_by_service: dict[int, list[permission_types.Repository]] = {}
    all_repos_by_id: dict[str, permission_types.Repository] = {}
    for repository in state["repos"]:
        graphql_repository: permission_types.Repository = {
            "id": src.encode_repository_id(repository["id"]),
            "name": repository["name"],
        }
        repos_by_service.setdefault(repository["externalServiceID"], []).append(graphql_repository)
        all_repos_by_id[graphql_repository["id"]] = graphql_repository

    expected: dict[int, set[str]] = {}
    for rule in rules:
        matched_users = mapping.resolve_users(
            cast("permission_types.UserSelector", rule["users"]),
            users,
            state["authProviders"],
            None,
        )
        if not matched_users:
            continue
        matched_repos = mapping.resolve_repos(
            cast("permission_types.RepositorySelector", rule["repos"]),
            services_by_id,
            repos_by_service,
            all_repos_by_id,
        )
        for repository in matched_repos:
            expected.setdefault(src.decode_repository_id(repository["id"]), set()).update(
                user["username"] for user in matched_users
            )
    return expected


def check_union_across_rules(rng: random.Random, maps_path: Path) -> str:
    state = random_fixture_state(rng, with_grants=False)
    rule_one = random_mapping_rule(rng, state, 1)
    rule_two = random_mapping_rule(rng, state, 2)
    combined, _ = run_set_full_in_memory(state, [rule_one, rule_two], maps_path)
    separate_one, _ = run_set_full_in_memory(state, [rule_one], maps_path)
    separate_two, _ = run_set_full_in_memory(state, [rule_two], maps_path)
    expected = grant_pairs(separate_one) | grant_pairs(separate_two)
    actual = grant_pairs(combined)
    if actual != expected:
        return (
            "combined grants are not the union of per-rule grants: "
            f"extra={sorted(actual - expected)[:5]} missing={sorted(expected - actual)[:5]}"
        )
    return ""


def with_extra_user_filter(
    rng: random.Random, state: FixtureState, rule: dict[str, Any]
) -> dict[str, Any] | None:
    """Return the rule with one additional user filter, or None if all are taken."""
    usernames = [user["username"] for user in state["users"]]
    users_selector = dict(cast("dict[str, Any]", rule["users"]))
    additional = [
        choice
        for choice in (
            ("usernames", [rng.choice(usernames)]),
            ("usernameRegexes", ["^user0[13579]"]),
            ("emails", [f"{rng.choice(usernames)}@example.com"]),
        )
        if choice[0] not in users_selector
    ]
    if not additional:
        return None
    field_name, value = rng.choice(additional)
    users_selector[field_name] = value
    return {**rule, "users": users_selector}


def check_narrowing_monotonicity(rng: random.Random, maps_path: Path) -> str:
    state = random_fixture_state(rng, with_grants=False)
    rule = random_mapping_rule(rng, state, 1)
    narrowed_rule = with_extra_user_filter(rng, state, rule)
    if narrowed_rule is None:
        return ""
    base_state, _ = run_set_full_in_memory(state, [rule], maps_path)
    narrowed_state, _ = run_set_full_in_memory(state, [narrowed_rule], maps_path)
    widened = grant_pairs(narrowed_state) - grant_pairs(base_state)
    if widened:
        return f"adding a user filter widened the grant set: {sorted(widened)[:5]}"
    return ""


def check_apply_idempotency(rng: random.Random, maps_path: Path) -> str:
    state = random_fixture_state(rng, with_grants=True)
    rules = [random_mapping_rule(rng, state, 1)]
    first_state, _ = run_set_full_in_memory(state, rules, maps_path)
    second_state, second_mutations = run_set_full_in_memory(first_state, rules, maps_path)
    if second_mutations != 0:
        return f"second identical run performed {second_mutations} mutation(s)"
    if grant_pairs(second_state) != grant_pairs(first_state):
        return "second identical run changed the grant set"
    return ""


def check_oracle_equivalence(rng: random.Random, maps_path: Path) -> str:
    state = random_fixture_state(rng, with_grants=True)
    rules = [random_mapping_rule(rng, state, number) for number in (1, 2)]
    final_state, _ = run_set_full_in_memory(state, rules, maps_path)
    expected_by_repo = oracle_expected_grants(state, rules)
    before_by_repo = {
        repository["id"]: set(repository["explicitPermissionsUsers"])
        for repository in state["repos"]
    }
    for repository in final_state["repos"]:
        actual_users = set(repository["explicitPermissionsUsers"])
        expected_users = expected_by_repo.get(repository["id"])
        if expected_users is None:
            if actual_users != before_by_repo[repository["id"]]:
                return f"unmapped repo {repository['name']} changed: {sorted(actual_users)}"
        elif actual_users != expected_users:
            return (
                f"repo {repository['name']}: expected {sorted(expected_users)}, "
                f"got {sorted(actual_users)}"
            )
    return ""


def check_pending_preservation(rng: random.Random, maps_path: Path) -> str:
    state = random_fixture_state(rng, with_grants=True)
    rules = [random_mapping_rule(rng, state, 1)]
    final_state, _ = run_set_full_in_memory(state, rules, maps_path)
    before_pending = pending_pairs(state)
    after_pending = pending_pairs(final_state)
    if after_pending != before_pending:
        return (
            "set --full changed pending grants: "
            f"lost={sorted(before_pending - after_pending)[:5]} "
            f"created={sorted(after_pending - before_pending)[:5]}"
        )
    return ""


def run_property_checks(seed: int, iterations: int) -> list[PropertyCheckOutcome]:
    checks: list[tuple[str, Callable[[random.Random, Path], str]]] = [
        ("grants for combined rules union per-rule grants", check_union_across_rules),
        ("adding filters never widens the grant set", check_narrowing_monotonicity),
        ("apply is idempotent", check_apply_idempotency),
        ("grants match the mapping-layer oracle", check_oracle_equivalence),
        ("set --full neither creates nor loses pending grants", check_pending_preservation),
    ]
    outcomes: list[PropertyCheckOutcome] = []
    with tempfile.TemporaryDirectory(prefix="src-auth-perms-sync-invariants-") as temporary:
        maps_path = Path(temporary) / "maps.yaml"
        for name, check in checks:
            rng = random.Random(seed)
            started = time.monotonic()
            passed = True
            detail = ""
            for iteration in range(1, iterations + 1):
                try:
                    failure = check(rng, maps_path)
                except Exception as exception:  # noqa: BLE001 - record, don't kill the suite.
                    failure = f"crashed: {type(exception).__name__}: {exception}"
                if failure:
                    passed = False
                    detail = f"iteration {iteration} (seed {seed}): {failure}"
                    break
            outcomes.append(PropertyCheckOutcome(name, passed, time.monotonic() - started, detail))
    return outcomes


# ---------------------------------------------------------------------------
# Live fixture-case helpers: identity translation, fixture-state loading
# ---------------------------------------------------------------------------

EXACT_REPOSITORY_SELECTOR_FIELDS = {"names"}


def load_setup_config() -> dict[str, Any]:
    """Parse tests/setup.yaml — the source of truth for fabricated SAML accounts."""
    import yaml

    return cast("dict[str, Any]", yaml.safe_load(SETUP_CONFIG_PATH.read_text(encoding="utf-8")))


def fixture_grants(case_name: str, file_name: str) -> dict[str, set[str]] | None:
    """Return {repo name: usernames} from one fixture state file."""
    path = FIXTURES_DIR / case_name / file_name
    if not path.is_file():
        return None
    state = cast("dict[str, Any]", json.loads(path.read_text(encoding="utf-8")))
    return {
        cast(str, repository["name"]): set(
            cast("list[str]", repository["explicitPermissionsUsers"])
        )
        for repository in cast("list[dict[str, Any]]", state["repos"])
    }


def fixture_pending(case_name: str, file_name: str) -> dict[str, set[str]] | None:
    """Return {repo name: pending bindIDs} from one fixture state file."""
    path = FIXTURES_DIR / case_name / file_name
    if not path.is_file():
        return None
    state = cast("dict[str, Any]", json.loads(path.read_text(encoding="utf-8")))
    return {
        cast(str, repository["name"]): set(
            cast("list[str]", repository.get("pendingBindIDs") or [])
        )
        for repository in cast("list[dict[str, Any]]", state["repos"])
    }


def fixture_maps_repo_scope(
    case_name: str, has_declared_repository_names: bool
) -> tuple[set[str], str]:
    """Return (exact repo names used by rules, error).

    Mutating instance runs must be able to enumerate every repo a rule can
    touch, so they capture and restore exactly that set. Exact `names:`
    selectors enumerate themselves; any other repo selector (regexes,
    code-host matchers) requires the case to declare `live.involvedRepos`
    covering everything the selector can match — undeclared matches are
    mutated without restore and only detected by the canary checks.

    User-side selectors are unrestricted: whatever users a rule matches, the
    mutations stay confined to the involved repos, and the post-run state
    verification catches wrong user matching.
    """
    import yaml

    maps_text = (FIXTURES_DIR / case_name / "maps.yaml").read_text(encoding="utf-8")
    loaded = cast("dict[str, Any]", yaml.safe_load(maps_text))
    rule_repository_names: set[str] = set()
    for rule in cast("list[dict[str, Any]]", loaded.get("maps") or []):
        repository_selector = cast("dict[str, Any]", rule.get("repos") or {})
        non_exact_fields = sorted(set(repository_selector) - EXACT_REPOSITORY_SELECTOR_FIELDS)
        if non_exact_fields and not has_declared_repository_names:
            return (
                rule_repository_names,
                f"rule {rule.get('name')!r} uses non-exact repo selectors "
                f"{non_exact_fields}; declare live.involvedRepos covering every repo "
                f"they can match, or use exact names",
            )
        rule_repository_names.update(cast("list[str]", repository_selector.get("names") or []))
    return (rule_repository_names, "")


def decode_repository_node_id(graphql_id: str) -> int:
    """Decode a base64 GraphQL Repository node ID to its integer database ID."""
    decoded = base64.b64decode(graphql_id, validate=True).decode()
    kind, _, database_id = decoded.partition(":")
    if kind != "Repository":
        raise ValueError(f"not a Repository node ID: {decoded!r}")
    return int(database_id)


def encode_repository_node_id(database_id: int) -> str:
    """Encode an integer database ID as a base64 GraphQL Repository node ID."""
    return base64.b64encode(f"Repository:{database_id}".encode()).decode()


def mutations_succeeded_from_log(log_path: Path | None) -> int | None:
    """Return the last mutations_succeeded count from a run's structured log."""
    if log_path is None or not log_path.is_file():
        return None
    succeeded: int | None = None
    with log_path.open(encoding="utf-8") as log_file:
        for line in log_file:
            if '"mutations_succeeded"' not in line:
                continue
            try:
                record = cast("dict[str, Any]", json.loads(line))
            except json.JSONDecodeError:
                continue
            value = record.get("mutations_succeeded")
            if isinstance(value, int):
                succeeded = value
    return succeeded


def strip_iteration_suffix(case_name: str) -> str:
    return re.sub(r" \[\d+\]$", "", case_name)


def performance_median(
    rows: list[dict[str, object]], case_name: str, variant_name: str, column: str
) -> float | None:
    values = [
        float(value)
        for row in rows
        if row["case"] == case_name and row["variant"] == variant_name
        for value in (row.get(column),)
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    ]
    return statistics.median(values) if values else None


# ---------------------------------------------------------------------------
# Jaeger trace collection (performance level)
#
# After each performance case, the CLI run's structured log is scanned for
# GraphQL requests with Sourcegraph trace metadata (the CLI is run with
# --fetch-sg-traces so the server retains traces). The slowest traces are
# fetched from Sourcegraph's Jaeger API and written to the test run directory:
# summaries to jaeger-trace-summaries.jsonl, full traces under jaeger-traces/.
# ---------------------------------------------------------------------------

JAEGER_INITIAL_DELAY_SECONDS = 15.0
JAEGER_RETRY_DELAYS_SECONDS = (5.0, 10.0, 20.0, 30.0, 60.0)
JAEGER_FETCH_PARALLELISM = 4


def string_headers(headers: object) -> dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    values: dict[str, str] = {}
    for header_name, value in cast("dict[object, object]", headers).items():
        if not isinstance(header_name, str):
            continue
        if isinstance(value, str):
            values[header_name] = value
        elif isinstance(value, list):
            string_values = [item for item in cast("list[object]", value) if isinstance(item, str)]
            if string_values:
                values[header_name] = string_values[0]
    return values


def header_value(headers: dict[str, str], name: str) -> str | None:
    lower_name = name.lower()
    for header_name, value in headers.items():
        if header_name.lower() == lower_name:
            return value
    return None


def trace_id_from_traceparent(traceparent: str | None) -> str | None:
    if traceparent is None:
        return None
    parts = traceparent.split("-")
    if len(parts) != 4:
        return None
    trace_id = parts[1]
    if len(trace_id) != 32 or not all(character in "0123456789abcdef" for character in trace_id):
        return None
    return trace_id


def graphql_trace_request_from_record(record: dict[str, Any]) -> dict[str, Any] | None:
    """Return Sourcegraph trace metadata from one structured http_request record."""
    import src_py_lib as src
    from src_py_lib.clients.sourcegraph import sourcegraph_trace_from_headers

    if record.get("event") != "http_request" or record.get("phase") != "end":
        return None
    if not str(record.get("url", "")).endswith("/.api/graphql"):
        return None
    request_headers = string_headers(record.get("request_headers"))
    response_headers = string_headers(record.get("response_headers"))
    trace = sourcegraph_trace_from_headers(response_headers, request_headers)
    if trace is None:
        trace_id = trace_id_from_traceparent(header_value(request_headers, "traceparent"))
        if trace_id is None:
            return None
        trace = src.SourcegraphTrace(
            trace_id=trace_id,
            trace_url=header_value(response_headers, "x-trace-url"),
        )
    return trace.to_json() | {
        "duration_ms": float_field(record, "duration_ms") or 0.0,
        "timestamp": record.get("ts"),
        "status": record.get("status"),
        "status_code": record.get("status_code"),
        "error_type": record.get("error_type"),
    }


def trace_requests_from_log(log_path: Path, limit: int) -> list[dict[str, Any]]:
    """Return the slowest unique GraphQL trace requests from one run log."""
    requests_by_trace_id: dict[str, dict[str, Any]] = {}
    with log_path.open(encoding="utf-8") as log_file:
        for line in log_file:
            if not line.strip():
                continue
            try:
                record = cast("dict[str, Any]", json.loads(line))
            except json.JSONDecodeError:
                continue
            trace_request = graphql_trace_request_from_record(record)
            if trace_request is None:
                continue
            trace_id = str(trace_request["trace_id"])
            existing = requests_by_trace_id.get(trace_id)
            if existing is None or cast(float, trace_request["duration_ms"]) > cast(
                float, existing["duration_ms"]
            ):
                requests_by_trace_id[trace_id] = trace_request
    slowest_first = sorted(
        requests_by_trace_id.values(),
        key=lambda trace_request: cast(float, trace_request["duration_ms"]),
        reverse=True,
    )
    return slowest_first[:limit]


class JaegerTraceFetcher:
    """Fetch the slowest Sourcegraph Jaeger traces for each performance case."""

    def __init__(self, endpoint: str, access_token: str, artifact_prefix: Path, limit: int) -> None:
        import src_py_lib as src

        self.limit = limit
        self.summaries_path = with_suffix_name(artifact_prefix, "-jaeger-traces.jsonl")
        self.traces_directory = with_suffix_name(artifact_prefix, "-jaeger-traces")
        http = src.HTTPClient(
            user_agent="src-auth-perms-sync-tests/0.1 (+python)",
            max_attempts=1,
            max_connections=JAEGER_FETCH_PARALLELISM,
        )
        self._client = src.SourcegraphClient(endpoint=endpoint, token=access_token, http=http)

    def collect_for_run(self, case_label: str, log_path: Path) -> tuple[int, int]:
        """Fetch traces for one run. Returns (fetched, requested)."""
        if not log_path.is_file():
            return (0, 0)
        trace_requests = trace_requests_from_log(log_path, self.limit)
        if not trace_requests:
            return (0, 0)
        log.info(
            "Fetching %d slowest Jaeger trace(s) for %s (waiting %.0fs for trace ingestion) ...",
            len(trace_requests),
            case_label,
            JAEGER_INITIAL_DELAY_SECONDS,
        )
        time.sleep(JAEGER_INITIAL_DELAY_SECONDS)
        fetched = 0

        def fetch_one(trace_request: dict[str, Any]) -> dict[str, Any]:
            return self._fetch_one(case_label, trace_request)

        with ThreadPoolExecutor(max_workers=JAEGER_FETCH_PARALLELISM) as fetch_pool:
            summaries = list(fetch_pool.map(fetch_one, trace_requests))
        for summary in summaries:
            if summary.get("jaeger_found") is True:
                fetched += 1
            self._append_summary(summary)
            self._log_summary(summary)
        return (fetched, len(trace_requests))

    def _fetch_one(self, case_label: str, trace_request: dict[str, Any]) -> dict[str, Any]:
        import src_py_lib as src
        from src_py_lib.clients.sourcegraph import summarize_jaeger_trace

        trace = src.SourcegraphTrace(
            trace_id=str(trace_request["trace_id"]),
            span_id=optional_string(trace_request.get("span_id")),
            trace_url=optional_string(trace_request.get("trace_url")),
            parent_trace_id=optional_string(trace_request.get("parent_trace_id")),
            parent_span_id=optional_string(trace_request.get("parent_span_id")),
        )
        try:
            jaeger_trace = self._client.fetch_jaeger_trace(
                trace.trace_id,
                retry_delays_seconds=JAEGER_RETRY_DELAYS_SECONDS,
            )
            summary = summarize_jaeger_trace(trace, jaeger_trace).to_json()
            trace_path = self._write_complete_trace(case_label, trace_request, jaeger_trace)
            if trace_path is not None:
                summary["jaeger_trace_path"] = str(trace_path)
            return trace_request | summary | {"case": case_label}
        except Exception as exception:  # noqa: BLE001 - keep evidence collection alive.
            return trace_request | {
                "case": case_label,
                "jaeger_found": False,
                "error": f"{type(exception).__name__}: {exception}",
            }

    def _write_complete_trace(
        self, case_label: str, trace_request: dict[str, Any], jaeger_trace: dict[str, Any]
    ) -> Path | None:
        trace_id = str(trace_request["trace_id"])
        path = self.traces_directory / case_label / f"{trace_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {"trace_request": trace_request, "jaeger_trace": jaeger_trace},
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return path

    def _append_summary(self, summary: dict[str, Any]) -> None:
        self.summaries_path.parent.mkdir(parents=True, exist_ok=True)
        with self.summaries_path.open("a", encoding="utf-8") as summaries_file:
            summaries_file.write(json.dumps(summary, sort_keys=True, default=str) + "\n")

    def _log_summary(self, summary: dict[str, Any]) -> None:
        duration_ms = float(cast("int | float", summary.get("duration_ms") or 0))
        if summary.get("jaeger_found") is not True:
            log.info("  %0.0fms %s: %s", duration_ms, summary.get("trace_id"), summary.get("error"))
            return
        log.info(
            "  %0.0fms %s: %s span(s)",
            duration_ms,
            summary.get("trace_id"),
            summary.get("span_count", 0),
        )


def optional_string(value: object) -> str | None:
    return value if isinstance(value, str) else None


# ---------------------------------------------------------------------------
# Sourcegraph load monitor (performance level, optional)
#
# Python port of dev/memory-efficiency-monitor-sourcegraph.sh: samples
# Sourcegraph pod and Postgres load via kubectl while performance cases run.
# ---------------------------------------------------------------------------

POSTGRES_ACTIVITY_SQL = """
select
  pid,
  now() - query_start as age,
  state,
  wait_event_type,
  wait_event,
  left(query, 220) as query
from pg_stat_activity
where state <> 'idle'
order by age desc
limit 30;

select
  wait_event_type,
  wait_event,
  state,
  count(*)
from pg_stat_activity
group by 1,2,3
order by count(*) desc;

select
  locktype,
  mode,
  granted,
  count(*)
from pg_locks
group by 1,2,3
order by count(*) desc;
"""

POSTGRES_STATEMENTS_SETUP_SQL = """
select current_database(), current_user;
show shared_preload_libraries;
show track_io_timing;
create extension if not exists pg_stat_statements;
select pg_stat_statements_reset();
"""

POSTGRES_STATEMENTS_SQL = """
select
  calls,
  round(total_exec_time::numeric, 1) as total_ms,
  round(mean_exec_time::numeric, 1) as mean_ms,
  rows,
  left(query, 260) as query
from pg_stat_statements
order by total_exec_time desc
limit 25;
"""

POD_PROCESS_SAMPLE_SCRIPT = """
echo "--- top CPU ---"
ps auxww | sort -nrk3 | head -30
echo "--- top RSS ---"
ps auxww | sort -nrk4 | head -30
"""


class SourcegraphLoadMonitor:
    """Sample Sourcegraph pod and Postgres load via kubectl in background threads."""

    def __init__(self, arguments: TestArguments, output_directory: Path) -> None:
        self.arguments = arguments
        self.output_directory = output_directory
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        self.output_directory.mkdir(parents=True, exist_ok=True)
        log.info("Starting Sourcegraph load monitor: %s", self.output_directory)
        self._run_psql("postgres-statements-setup.log", POSTGRES_STATEMENTS_SETUP_SQL)
        self._snapshot_pod_descriptions()
        samplers: list[tuple[str, float, Callable[[], None]]] = [
            ("kubectl-top", self.arguments.monitor_interval_seconds, self._sample_kubectl_top),
            ("processes", self.arguments.monitor_interval_seconds, self._sample_pod_processes),
            (
                "postgres-activity",
                self.arguments.monitor_postgres_interval_seconds,
                self._sample_postgres_activity,
            ),
            (
                "postgres-statements",
                self.arguments.monitor_statements_interval_seconds,
                self._sample_postgres_statements,
            ),
        ]
        for name, interval_seconds, sample in samplers:
            thread = threading.Thread(
                target=self._loop,
                args=(float(interval_seconds), sample),
                name=f"SourcegraphLoadMonitor-{name}",
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)

    def stop(self) -> None:
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=10.0)
        self._snapshot_pod_descriptions()
        log.info("Stopped Sourcegraph load monitor. Output: %s", self.output_directory)

    def _loop(self, interval_seconds: float, sample: Callable[[], None]) -> None:
        while not self._stop.is_set():
            sample()
            if self._stop.wait(interval_seconds):
                return

    def _append(self, file_name: str, title: str, text: str) -> None:
        timestamp = datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")
        with (self.output_directory / file_name).open("a", encoding="utf-8") as output_file:
            output_file.write(f"\n===== {timestamp} {title} =====\n{text}")

    def _run_capture(self, command: list[str], stdin_text: str | None = None) -> str:
        try:
            completed = subprocess.run(
                command,
                input=stdin_text,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            return f"<monitor error: {type(error).__name__}: {error}>\n"
        return completed.stdout + completed.stderr

    def _kubectl(self, *kubectl_arguments: str) -> list[str]:
        return ["kubectl", "-n", self.arguments.monitor_namespace, *kubectl_arguments]

    def _sample_kubectl_top(self) -> None:
        output = self._run_capture(self._kubectl("top", "pods", "--containers"))
        self._append("kubectl-top-pods-containers.log", "kubectl top pods --containers", output)

    def _sample_pod_processes(self) -> None:
        for label, target in (
            ("frontend", self.arguments.monitor_frontend_target),
            ("postgres", self.arguments.monitor_postgres_target),
        ):
            output = self._run_capture(
                self._kubectl("exec", target, "--", "sh", "-lc", POD_PROCESS_SAMPLE_SCRIPT)
            )
            self._append(f"{label}-processes.log", f"{target} process CPU/RSS", output)

    def _run_psql(self, file_name: str, sql: str) -> None:
        output = self._run_capture(
            self._kubectl(
                "exec",
                "-i",
                self.arguments.monitor_postgres_target,
                "--",
                "sh",
                "-lc",
                f"{self.arguments.monitor_psql_command} -P pager=off",
            ),
            stdin_text=sql,
        )
        self._append(file_name, "psql", output)

    def _sample_postgres_activity(self) -> None:
        self._run_psql("postgres-activity.log", POSTGRES_ACTIVITY_SQL)

    def _sample_postgres_statements(self) -> None:
        self._run_psql("postgres-statements.log", POSTGRES_STATEMENTS_SQL)

    def _snapshot_pod_descriptions(self) -> None:
        for target in (
            self.arguments.monitor_frontend_target,
            self.arguments.monitor_postgres_target,
        ):
            output = self._run_capture(self._kubectl("describe", target))
            self._append("pod-descriptions.log", f"kubectl describe {target}", output)


def main() -> None:
    arguments = parse_arguments()
    stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%d-%H%M%S")
    artifact_prefix = TEST_LOGS_DIR / f"{stamp}-{arguments.level}"
    log_path = with_suffix_name(artifact_prefix, ".log")
    configure_logging(log_path, quiet=arguments.quiet)
    if arguments.quiet:
        # The console only shows warnings and failures in quiet mode; the log
        # file path must stay visible.
        print(f"Writing test output to {log_path}")
    log.info("Writing test output to %s", log_path)

    suite = TestSuite(arguments=arguments, artifact_prefix=artifact_prefix)

    if arguments.update_golden:
        suite.run_fixture_checks(update_golden=True)
        log.info("\nGolden files regenerated. Review `git diff tests/e2e/fixtures/` carefully.")
        sys.exit(suite.print_summary())

    if arguments.level == "local":
        suite.run_toolchain_gates()
        suite.run_fixture_checks(update_golden=False)
        suite.run_property_checks()
    elif arguments.level == "live":
        suite.run_live()
    elif arguments.level == "install":
        suite.run_install()
    else:
        suite.run_performance()

    exit_code = suite.print_summary()
    log.info("Full log: %s", log_path)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
