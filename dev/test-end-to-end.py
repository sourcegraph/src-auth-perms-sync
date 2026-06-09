#!/usr/bin/env python3
"""Run src-auth-perms-sync end-to-end cases and assert expected outcomes.

This is an integration smoke runner for a real Sourcegraph test instance. It
uses the same CLI entrypoint an operator uses (`uv run src-auth-perms-sync`) and
checks both process exit codes and structured `run` log records.

The script covers every major command path: read-only, dry-run,
invalid-argument, no-op apply, mutating apply, and overwrite/restore. It avoids
running the same expensive full-snapshot path more than once when another case
already covers that behavior.
"""

from __future__ import annotations

import contextlib
import csv
import datetime
import heapq
import json
import os
import re
import shlex
import signal
import statistics
import subprocess
import sys
import threading
import time
from collections.abc import Iterable, Mapping, Sequence
from concurrent.futures import Future
from concurrent.futures import wait as wait_for_futures
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO, cast
from urllib.parse import urlsplit

import src_py_lib as src
from src_py_lib.clients.sourcegraph import sourcegraph_trace_from_headers, summarize_jaeger_trace

LOG_PATH_PATTERN = re.compile(r"Writing log events to (.+?/log\.json)\.")
SAFE_PATH_PART_PATTERN = re.compile(r"[^A-Za-z0-9_.-]+")
DEFAULT_FUTURE_DATE = "2099-01-01"
REMOVED_SRC_AUTH_PERMS_SYNC_ENVIRONMENT_PREFIX = "SRC_AUTH_PERMS_SYNC_"
DEFAULT_SAMPLE_INTERVAL_SECONDS = 1.0
DEFAULT_REPEAT_COUNT = 1
DEFAULT_JAEGER_TRACE_LIMIT: int | None = None
DEFAULT_JAEGER_TRACE_PARALLELISM = 8
DEFAULT_JAEGER_INITIAL_DELAY_SECONDS = 35.0
DEFAULT_JAEGER_RETRY_DELAYS_SECONDS = (
    2.0,
    5.0,
    10.0,
    20.0,
    30.0,
    60.0,
    60.0,
    60.0,
    60.0,
    60.0,
    60.0,
)
DEFAULT_PARALLELISM = 4
DEFAULT_FULL_RESTORE_PARALLELISM = 1
DEFAULT_INCLUDE_REDUNDANT_SCALE_CASES = False
DEFAULT_MEMORY_SUMMARY_LIMIT = 20
DEFAULT_SRC_AUTH_PERMS_SYNC_COMMAND = "uv run src-auth-perms-sync"
DEFAULT_SOURCEGRAPH_MONITOR_NAMESPACE = "m"
DEFAULT_SOURCEGRAPH_MONITOR_INTERVAL_SECONDS = 5
DEFAULT_SOURCEGRAPH_MONITOR_POSTGRES_INTERVAL_SECONDS = 10
DEFAULT_SOURCEGRAPH_MONITOR_STATEMENTS_INTERVAL_SECONDS = 30
DEFAULT_SOURCEGRAPH_MONITOR_FRONTEND_TARGET = "deployment/sourcegraph-frontend"
DEFAULT_SOURCEGRAPH_MONITOR_POSTGRES_TARGET = "pod/pgsql-0"
DEFAULT_SOURCEGRAPH_MONITOR_PSQL_COMMAND = "psql -X -U sg -d sg"


def format_jaeger_retry_delays(delays: Sequence[float]) -> str:
    """Return retry delays in the format accepted by --jaeger-retry-delays."""
    return ",".join(f"{delay:g}" for delay in delays)


class EndToEndConfig(src.SourcegraphClientConfig, src.LoggingConfig):
    """Config values for the end-to-end runner."""

    src_endpoint: str = src.config_field(
        default="",
        env_var="SRC_ENDPOINT",
        cli_flag="--src-endpoint",
        cli_aliases=("--endpoint",),
        metavar="URL",
        help="Sourcegraph test instance URL",
        required=True,
    )
    src_access_token: str = src.config_field(
        default="",
        env_var="SRC_ACCESS_TOKEN",
        cli_flag="--src-access-token",
        cli_aliases=("--access-token",),
        metavar="TOKEN",
        help="Sourcegraph access token, or op:// secret reference",
        secret=True,
        required=True,
    )
    src_auth_perms_sync_command: str = src.config_field(
        default=DEFAULT_SRC_AUTH_PERMS_SYNC_COMMAND,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_COMMAND",
        cli_flag="--src-auth-perms-sync-command",
        help=(
            "Candidate command used to invoke the CLI "
            f"(default: {DEFAULT_SRC_AUTH_PERMS_SYNC_COMMAND})"
        ),
    )
    candidate_command: str | None = src.config_field(
        default=None,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_CANDIDATE_COMMAND",
        cli_flag="--candidate-command",
        help="Candidate command to compare; overrides --src-auth-perms-sync-command",
    )
    baseline_command: str | None = src.config_field(
        default=None,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_BASELINE_COMMAND",
        cli_flag="--baseline-command",
        help="Optional baseline command. When set, baseline and candidate results are compared.",
    )
    repeat: int = src.config_field(
        default=DEFAULT_REPEAT_COUNT,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_REPEAT",
        cli_flag="--repeat",
        metavar="N",
        ge=1,
        help=(
            "Number of times to run each command for each variant "
            f"(default: {DEFAULT_REPEAT_COUNT})"
        ),
    )
    user: str = src.config_field(
        default="",
        env_var="SRC_AUTH_PERMS_SYNC_TEST_USER",
        cli_flag="--user",
        metavar="USER",
        help="Sourcegraph user for user-scoped get/set/restore cases (default: USER)",
    )
    future_date: str = src.config_field(
        default=DEFAULT_FUTURE_DATE,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_FUTURE_DATE",
        cli_flag="--future-date",
        metavar="YYYY-MM-DD",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
        help=f"YYYY-MM-DD date expected to match no users (default: {DEFAULT_FUTURE_DATE})",
    )
    parallelism: int = src.config_field(
        default=DEFAULT_PARALLELISM,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_PARALLELISM",
        cli_flag="--parallelism",
        metavar="N",
        ge=1,
        help=f"Parallelism for light mutation/no-op apply cases (default: {DEFAULT_PARALLELISM})",
    )
    full_restore_parallelism: int = src.config_field(
        default=DEFAULT_FULL_RESTORE_PARALLELISM,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_FULL_RESTORE_PARALLELISM",
        cli_flag="--full-restore-parallelism",
        metavar="N",
        ge=1,
        help=(
            "Parallelism for the expensive full restore cleanup "
            f"(default: {DEFAULT_FULL_RESTORE_PARALLELISM})"
        ),
    )
    include_redundant_scale_cases: bool = src.config_field(
        default=DEFAULT_INCLUDE_REDUNDANT_SCALE_CASES,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_INCLUDE_REDUNDANT_SCALE_CASES",
        cli_flag="--include-redundant-scale-cases",
        cli_action="store_true",
        help=(
            "Also run older overlapping full-scale cases. Default keeps one heavy full "
            "snapshot path and uses smaller cases for overlapping coverage."
        ),
    )
    allow_non_test_endpoint: bool = src.config_field(
        default=False,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_ALLOW_NON_TEST_ENDPOINT",
        cli_flag="--allow-non-test-endpoint",
        cli_action="store_true",
        help="Allow mutating cases outside localhost/sgdev endpoints",
    )
    keep_going: bool = src.config_field(
        default=False,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_KEEP_GOING",
        cli_flag="--keep-going",
        cli_action="store_true",
        help="Continue after assertion failures where it is safe to do so",
    )
    fetch_sg_traces: bool = src.config_field(
        default=False,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_FETCH_SG_TRACES",
        cli_flag="--fetch-sg-traces",
        cli_action="store_true",
        help="Pass --fetch-sg-traces to each child src-auth-perms-sync command",
    )
    jaeger_trace_limit: int | None = src.config_field(
        default=DEFAULT_JAEGER_TRACE_LIMIT,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_JAEGER_TRACE_LIMIT",
        cli_flag="--jaeger-trace-limit",
        metavar="N",
        ge=0,
        help=(
            "When --fetch-sg-traces is set, fetch and summarize the N slowest GraphQL "
            "Jaeger traces "
            "while each child command runs; omit for all traces, set 0 to disable"
        ),
    )
    jaeger_trace_parallelism: int = src.config_field(
        default=DEFAULT_JAEGER_TRACE_PARALLELISM,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_JAEGER_TRACE_PARALLELISM",
        cli_flag="--jaeger-trace-parallelism",
        metavar="N",
        ge=1,
        help=(
            "Concurrent Jaeger trace fetch requests when --fetch-sg-traces is set "
            f"(default: {DEFAULT_JAEGER_TRACE_PARALLELISM})"
        ),
    )
    jaeger_initial_delay_seconds: float = src.config_field(
        default=DEFAULT_JAEGER_INITIAL_DELAY_SECONDS,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_JAEGER_INITIAL_DELAY_SECONDS",
        cli_flag="--jaeger-initial-delay-seconds",
        metavar="SECONDS",
        ge=0,
        help=(
            "Seconds to wait before first fetching each Jaeger trace, to allow OTel tail "
            f"sampling to decide (default: {DEFAULT_JAEGER_INITIAL_DELAY_SECONDS:g})"
        ),
    )
    jaeger_trace_jsonl: Path | None = src.config_field(
        default=None,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_JAEGER_TRACE_JSONL",
        cli_flag="--jaeger-trace-jsonl",
        metavar="PATH",
        help=(
            "Write Jaeger trace summaries incrementally as JSON Lines. Defaults to a sibling "
            "of --results-json or --results-csv when --fetch-sg-traces is set."
        ),
    )
    jaeger_trace_directory: Path | None = src.config_field(
        default=None,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_JAEGER_TRACE_DIR",
        cli_flag="--jaeger-trace-dir",
        metavar="PATH",
        help=(
            "Directory where complete raw Jaeger trace JSON files are written. Defaults "
            "to a sibling directory of --results-json or --results-csv when --fetch-sg-traces "
            "is set."
        ),
    )
    jaeger_retry_delays: tuple[float, ...] = src.config_field(
        default=DEFAULT_JAEGER_RETRY_DELAYS_SECONDS,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_JAEGER_RETRY_DELAYS",
        cli_flag="--jaeger-retry-delays",
        metavar="SECONDS[,SECONDS...]",
        help=(
            "Comma-separated delays between queued Jaeger trace fetch retries. "
            "Each value schedules one retry after the initial fetch; add more values "
            "to try for longer "
            f"(default: {format_jaeger_retry_delays(DEFAULT_JAEGER_RETRY_DELAYS_SECONDS)})"
        ),
    )
    sample_interval: float = src.config_field(
        default=DEFAULT_SAMPLE_INTERVAL_SECONDS,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_SAMPLE_INTERVAL",
        cli_flag="--sample-interval",
        metavar="SECONDS",
        ge=0,
        help=(
            "Seconds between child resource_sample log events. The run end record always "
            "includes peak_rss_mb; set 0 to disable samples. Default: "
            f"{DEFAULT_SAMPLE_INTERVAL_SECONDS}"
        ),
    )
    external_sample_interval: float = src.config_field(
        default=DEFAULT_SAMPLE_INTERVAL_SECONDS,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_EXTERNAL_SAMPLE_INTERVAL",
        cli_flag="--external-sample-interval",
        metavar="SECONDS",
        ge=0,
        help=(
            "Seconds between external child process-tree RSS samples; set 0 to disable "
            f"(default: {DEFAULT_SAMPLE_INTERVAL_SECONDS})"
        ),
    )
    memory_summary_limit: int = src.config_field(
        default=DEFAULT_MEMORY_SUMMARY_LIMIT,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_MEMORY_SUMMARY_LIMIT",
        cli_flag="--memory-summary-limit",
        metavar="N",
        ge=1,
        help="Number of highest-RSS cases to print in the final memory summary",
    )
    results_json: Path | None = src.config_field(
        default=None,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_RESULTS_JSON",
        cli_flag="--results-json",
        metavar="PATH",
        help="Optional path to write machine-readable run and comparison results as JSON",
    )
    results_csv: Path | None = src.config_field(
        default=None,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_RESULTS_CSV",
        cli_flag="--results-csv",
        metavar="PATH",
        help=(
            "Optional path to write per-command memory results as CSV; phase rows are written "
            "beside it as *-phases.csv"
        ),
    )
    monitor_sourcegraph_load: bool = src.config_field(
        default=False,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_MONITOR_SOURCEGRAPH_LOAD",
        cli_flag="--monitor-sourcegraph-load",
        cli_action="store_true",
        help=(
            "Start the Sourcegraph pod/Postgres load monitor for this e2e run and write "
            "its output beside the result artifacts."
        ),
    )
    sourcegraph_monitor_namespace: str = src.config_field(
        default=DEFAULT_SOURCEGRAPH_MONITOR_NAMESPACE,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_MONITOR_NAMESPACE",
        cli_flag="--monitor-namespace",
        metavar="NAME",
        help=(
            "Kubernetes namespace for Sourcegraph load monitoring "
            f"(default: {DEFAULT_SOURCEGRAPH_MONITOR_NAMESPACE})"
        ),
    )
    sourcegraph_monitor_output_dir: Path | None = src.config_field(
        default=None,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_MONITOR_OUTPUT_DIR",
        cli_flag="--monitor-output-dir",
        metavar="PATH",
        help="Directory for Sourcegraph load monitor output; defaults beside result artifacts.",
    )
    sourcegraph_monitor_interval_seconds: int = src.config_field(
        default=DEFAULT_SOURCEGRAPH_MONITOR_INTERVAL_SECONDS,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_MONITOR_INTERVAL_SECONDS",
        cli_flag="--monitor-interval-seconds",
        metavar="SECONDS",
        ge=1,
        help=(
            "Pod/process/cgroup monitor interval in seconds "
            f"(default: {DEFAULT_SOURCEGRAPH_MONITOR_INTERVAL_SECONDS})"
        ),
    )
    sourcegraph_monitor_postgres_interval_seconds: int = src.config_field(
        default=DEFAULT_SOURCEGRAPH_MONITOR_POSTGRES_INTERVAL_SECONDS,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_MONITOR_POSTGRES_INTERVAL_SECONDS",
        cli_flag="--monitor-postgres-interval-seconds",
        metavar="SECONDS",
        ge=1,
        help=(
            "Postgres activity monitor interval in seconds "
            f"(default: {DEFAULT_SOURCEGRAPH_MONITOR_POSTGRES_INTERVAL_SECONDS})"
        ),
    )
    sourcegraph_monitor_statements_interval_seconds: int = src.config_field(
        default=DEFAULT_SOURCEGRAPH_MONITOR_STATEMENTS_INTERVAL_SECONDS,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_MONITOR_STATEMENTS_INTERVAL_SECONDS",
        cli_flag="--monitor-statements-interval-seconds",
        metavar="SECONDS",
        ge=1,
        help=(
            "pg_stat_statements monitor interval in seconds "
            f"(default: {DEFAULT_SOURCEGRAPH_MONITOR_STATEMENTS_INTERVAL_SECONDS})"
        ),
    )
    sourcegraph_monitor_frontend_target: str = src.config_field(
        default=DEFAULT_SOURCEGRAPH_MONITOR_FRONTEND_TARGET,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_MONITOR_FRONTEND_TARGET",
        cli_flag="--monitor-frontend-target",
        metavar="TARGET",
        help=(
            "kubectl target for Sourcegraph frontend "
            f"(default: {DEFAULT_SOURCEGRAPH_MONITOR_FRONTEND_TARGET})"
        ),
    )
    sourcegraph_monitor_postgres_target: str = src.config_field(
        default=DEFAULT_SOURCEGRAPH_MONITOR_POSTGRES_TARGET,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_MONITOR_POSTGRES_TARGET",
        cli_flag="--monitor-postgres-target",
        metavar="TARGET",
        help=(
            "kubectl target for Sourcegraph Postgres "
            f"(default: {DEFAULT_SOURCEGRAPH_MONITOR_POSTGRES_TARGET})"
        ),
    )
    sourcegraph_monitor_psql_command: str = src.config_field(
        default=DEFAULT_SOURCEGRAPH_MONITOR_PSQL_COMMAND,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_MONITOR_PSQL_COMMAND",
        cli_flag="--monitor-psql-command",
        metavar="COMMAND",
        help=(
            "psql command to run inside the Postgres pod "
            f"(default: {DEFAULT_SOURCEGRAPH_MONITOR_PSQL_COMMAND})"
        ),
    )
    sourcegraph_monitor_no_logs: bool = src.config_field(
        default=False,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_MONITOR_NO_LOGS",
        cli_flag="--monitor-no-logs",
        cli_action="store_true",
        help="Do not stream frontend logs while Sourcegraph load monitoring is enabled.",
    )
    fail_on_memory_regression_percent: float | None = src.config_field(
        default=None,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_FAIL_ON_MEMORY_REGRESSION_PERCENT",
        cli_flag="--fail-on-memory-regression-percent",
        metavar="PERCENT",
        ge=0,
        help="Fail if candidate median peak RSS regresses by more than this percent",
    )
    fail_on_memory_regression_mib: float | None = src.config_field(
        default=None,
        env_var="SRC_AUTH_PERMS_SYNC_E2E_FAIL_ON_MEMORY_REGRESSION_MIB",
        cli_flag="--fail-on-memory-regression-mib",
        metavar="MIB",
        ge=0,
        help="Fail if candidate median peak RSS regresses by more than this many MiB",
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
    jaeger_traces: list[dict[str, Any]]
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


class SourcegraphLoadMonitor:
    """Run the Sourcegraph pod/Postgres monitor for the duration of the e2e suite."""

    def __init__(self, config: EndToEndConfig, output_dir: Path) -> None:
        self.config = config
        self.output_dir = output_dir
        self.log_path = output_dir.with_name(f"{output_dir.name}.log")
        self._log_file: TextIO | None = None
        self._process: subprocess.Popen[str] | None = None

    def start(self) -> None:
        script_path = sourcegraph_monitor_script_path()
        if not script_path.exists():
            raise RuntimeError(f"Sourcegraph load monitor script not found: {script_path}")
        self.output_dir.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        command = [
            str(script_path),
            "--namespace",
            self.config.sourcegraph_monitor_namespace,
            "--output-dir",
            str(self.output_dir),
            "--interval-seconds",
            str(self.config.sourcegraph_monitor_interval_seconds),
            "--postgres-interval-seconds",
            str(self.config.sourcegraph_monitor_postgres_interval_seconds),
            "--statements-interval-seconds",
            str(self.config.sourcegraph_monitor_statements_interval_seconds),
            "--frontend-target",
            self.config.sourcegraph_monitor_frontend_target,
            "--postgres-target",
            self.config.sourcegraph_monitor_postgres_target,
            "--psql-command",
            self.config.sourcegraph_monitor_psql_command,
        ]
        if self.config.sourcegraph_monitor_no_logs:
            command.append("--no-logs")
        print(f"Starting Sourcegraph load monitor: {self.output_dir}")
        self._log_file = self.log_path.open("w", encoding="utf-8")
        self._process = subprocess.Popen(  # noqa: S603 - command is trusted test config.
            command,
            cwd=Path.cwd(),
            stdout=self._log_file,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        self._wait_until_started()

    def stop(self) -> None:
        process = self._process
        if process is None:
            self._close_log_file()
            return
        if process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=15)
        return_code = process.returncode
        self._close_log_file()
        if return_code not in {0, -15, 143}:
            print(
                f"Sourcegraph load monitor exited with status {return_code}; see {self.log_path}",
                file=sys.stderr,
            )
        else:
            print(f"Stopped Sourcegraph load monitor. Output: {self.output_dir}")

    def _wait_until_started(self) -> None:
        process = self._process
        if process is None:
            return
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(
                    f"Sourcegraph load monitor exited before startup completed; see {self.log_path}"
                )
            if self.log_path.exists() and "Started kubectl-top" in self.log_path.read_text(
                encoding="utf-8", errors="ignore"
            ):
                return
            time.sleep(0.2)
        raise RuntimeError(
            f"Timed out waiting for Sourcegraph load monitor startup; see {self.log_path}"
        )

    def _close_log_file(self) -> None:
        if self._log_file is not None:
            self._log_file.close()
            self._log_file = None


@dataclass
class JaegerTraceFetchTask:
    """One trace fetch request that can be retried across the whole e2e run."""

    trace_request: dict[str, Any]
    future: Future[dict[str, Any]]
    fetch_attempts: int = 0
    first_fetch_at: str | None = None
    last_fetch_at: str | None = None


class JaegerTraceFetchPool:
    """Fetch Sourcegraph Jaeger traces through one bounded retry queue."""

    def __init__(
        self,
        config: EndToEndConfig,
        *,
        parallelism: int,
        initial_delay_seconds: float,
        retry_delays_seconds: Sequence[float],
        jsonl_path: Path | None,
        trace_directory: Path | None,
    ) -> None:
        self.initial_delay_seconds = initial_delay_seconds
        self.retry_delays_seconds = tuple(retry_delays_seconds)
        self.max_fetch_attempts = len(self.retry_delays_seconds) + 1
        self._trace_directory = trace_directory
        self._tasks: list[tuple[float, int, JaegerTraceFetchTask]] = []
        self._condition = threading.Condition()
        self._sequence = 0
        self._closed = False
        self._jsonl_file: TextIO | None = None
        self._lock = threading.Lock()
        http = src.HTTPClient(
            user_agent="src-auth-perms-sync-e2e/0.1 (+python)",
            max_attempts=1,
            max_connections=parallelism,
        )
        self._client = src.sourcegraph_client_from_config(config, http=http)
        if jsonl_path is not None:
            jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            self._jsonl_file = jsonl_path.open("w", encoding="utf-8")
            print(f"Writing Jaeger trace summaries incrementally to {jsonl_path}")
        if self._trace_directory is not None:
            self._trace_directory.mkdir(parents=True, exist_ok=True)
            print(f"Writing complete Jaeger traces to {self._trace_directory}")
        self._workers = [
            threading.Thread(
                target=self._worker,
                name=f"JaegerTraceFetch-{worker_number}",
                daemon=True,
            )
            for worker_number in range(1, parallelism + 1)
        ]
        for worker in self._workers:
            worker.start()

    def submit(
        self,
        trace_request: dict[str, Any],
        collector: JaegerTraceCollector,
    ) -> Future[dict[str, Any]]:
        future: Future[dict[str, Any]] = Future()
        future.add_done_callback(lambda completed: self._record_summary(collector, completed))
        task = JaegerTraceFetchTask(
            trace_request=trace_request,
            future=future,
        )
        self._schedule(task, self.initial_delay_seconds)
        return future

    def close(self) -> None:
        with self._condition:
            self._closed = True
            self._condition.notify_all()
        for worker in self._workers:
            worker.join()
        self._client.http.close()
        if self._jsonl_file is not None:
            self._jsonl_file.close()

    def _schedule(self, task: JaegerTraceFetchTask, delay_seconds: float) -> None:
        with self._condition:
            self._sequence += 1
            heapq.heappush(
                self._tasks,
                (time.monotonic() + delay_seconds, self._sequence, task),
            )
            self._condition.notify()

    def _worker(self) -> None:
        while True:
            task = self._next_ready_task()
            if task is None:
                return
            self._process(task)

    def _next_ready_task(self) -> JaegerTraceFetchTask | None:
        with self._condition:
            while True:
                if self._closed and not self._tasks:
                    return None
                if not self._tasks:
                    self._condition.wait()
                    continue
                ready_at, _sequence, task = self._tasks[0]
                delay_seconds = ready_at - time.monotonic()
                if delay_seconds > 0:
                    self._condition.wait(delay_seconds)
                    continue
                heapq.heappop(self._tasks)
                return task

    def _process(self, task: JaegerTraceFetchTask) -> None:
        if task.future.done():
            return
        summary = self._fetch_summary(task)
        if summary.get("jaeger_found") is True or not self._should_retry(task, summary):
            task.future.set_result(summary)
            return
        self._schedule(task, self._retry_delay_seconds(task.fetch_attempts))

    def _fetch_summary(self, task: JaegerTraceFetchTask) -> dict[str, Any]:
        task.fetch_attempts += 1
        now = datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")
        if task.first_fetch_at is None:
            task.first_fetch_at = now
        task.last_fetch_at = now
        try:
            trace = sourcegraph_trace_from_request(task.trace_request)
            jaeger_trace = self._client.fetch_jaeger_trace(
                trace.trace_id,
                retry_delays_seconds=(0.0,),
            )
            summary = summarize_jaeger_trace(trace, jaeger_trace).to_json()
            try:
                trace_path = self._write_complete_trace(task, jaeger_trace, summary)
                if trace_path is not None:
                    summary["jaeger_trace_path"] = str(trace_path)
            except OSError as write_error:
                summary["jaeger_trace_write_error"] = f"{type(write_error).__name__}: {write_error}"
            return self._with_fetch_fields(task, summary)
        except Exception as exception:  # noqa: BLE001 - keep long-running evidence collection alive.
            return self._with_fetch_fields(
                task,
                {
                    **task.trace_request,
                    "jaeger_found": False,
                    "error": f"{type(exception).__name__}: {exception}",
                },
            )

    def _with_fetch_fields(
        self, task: JaegerTraceFetchTask, summary: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            **task.trace_request,
            **summary,
            "fetch_attempts": task.fetch_attempts,
            "first_fetch_at": task.first_fetch_at,
            "last_fetch_at": task.last_fetch_at,
            "max_fetch_attempts": self.max_fetch_attempts,
        }

    def _write_complete_trace(
        self,
        task: JaegerTraceFetchTask,
        jaeger_trace: dict[str, Any],
        summary: dict[str, Any],
    ) -> Path | None:
        if self._trace_directory is None:
            return None
        path = complete_jaeger_trace_path(self._trace_directory, task.trace_request)
        payload = {
            "collected_at": task.last_fetch_at,
            "fetch_attempts": task.fetch_attempts,
            "max_fetch_attempts": self.max_fetch_attempts,
            "trace_request": task.trace_request,
            "jaeger_summary": summary,
            "jaeger_trace": jaeger_trace,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = path.with_name(
            f".{path.name}.tmp-{threading.get_ident()}-{time.monotonic_ns()}"
        )
        temporary_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary_path.replace(path)
        return path

    def _should_retry(self, task: JaegerTraceFetchTask, summary: dict[str, Any]) -> bool:
        if self._closed or task.fetch_attempts >= self.max_fetch_attempts:
            return False
        error = str(summary.get("error") or "")
        return error.startswith(("HTTP 404", "HTTP 502", "HTTP 503", "HTTP 504"))

    def _retry_delay_seconds(self, fetch_attempts: int) -> float:
        if not self.retry_delays_seconds:
            return 0.0
        delay_index = min(fetch_attempts - 1, len(self.retry_delays_seconds) - 1)
        return self.retry_delays_seconds[delay_index]

    def _record_summary(
        self,
        collector: JaegerTraceCollector,
        future: Future[dict[str, Any]],
    ) -> None:
        summary = future.result()
        collector.record_summary(summary)
        self._write_jsonl(summary)

    def _write_jsonl(self, summary: dict[str, Any]) -> None:
        if self._jsonl_file is None:
            return
        with self._lock:
            self._jsonl_file.write(json.dumps(summary, sort_keys=True) + "\n")
            self._jsonl_file.flush()


class JaegerTraceCollector:
    """Tail a child log and submit Jaeger trace fetches while the child runs."""

    def __init__(
        self,
        log_path: Path,
        limit: int | None,
        fetch_pool: JaegerTraceFetchPool,
        *,
        variant: str,
        iteration: int,
        case_name: str,
    ) -> None:
        self.log_path = log_path
        self.limit = limit
        self.fetch_pool = fetch_pool
        self.variant = variant
        self.iteration = iteration
        self.case_name = case_name
        self.summaries: list[dict[str, Any]] = []
        self._graphql_queries_by_span: dict[tuple[str, str], dict[str, Any]] = {}
        self._trace_requests_by_graphql_span: dict[tuple[str, str], dict[str, Any]] = {}
        self._requests_by_trace_id: dict[str, dict[str, Any]] = {}
        self._queued_trace_ids: set[str] = set()
        self._futures: list[Future[dict[str, Any]]] = []
        self._lock = threading.Lock()
        self._log_complete = threading.Event()
        self._started = False
        self._tail_thread: threading.Thread | None = None

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        scope = "all traced" if self.limit is None else f"up to {self.limit} slowest traced"
        print(f"Collecting {scope} GraphQL Jaeger trace(s) for this case in the background ...")
        self._tail_thread = threading.Thread(
            target=self._tail_log,
            name="JaegerTraceLogTail",
            daemon=True,
        )
        self._tail_thread.start()

    def finish_log_capture(self) -> None:
        self._log_complete.set()
        if self._tail_thread is not None:
            self._tail_thread.join()

    def wait(self) -> None:
        if not self._started:
            return
        self.finish_log_capture()
        with self._lock:
            futures = list(self._futures)
        if futures:
            wait_for_futures(futures)
        with self._lock:
            self.summaries.sort(key=trace_summary_duration_ms, reverse=True)
        print_jaeger_trace_summaries(self.summaries)

    def record_summary(self, summary: dict[str, Any]) -> None:
        with self._lock:
            self.summaries.append(summary)

    def _tail_log(self) -> None:
        while not self.log_path.exists():
            if self._log_complete.wait(0.1):
                self._submit_limited_requests()
                return
        with self.log_path.open(encoding="utf-8") as log_file:
            while True:
                position = log_file.tell()
                line = log_file.readline()
                if line:
                    if not line.endswith("\n") and not self._log_complete.is_set():
                        log_file.seek(position)
                        time.sleep(0.1)
                        continue
                    self._record_line(line)
                    continue
                if self._log_complete.is_set():
                    break
                time.sleep(0.1)
        self._submit_limited_requests()

    def _record_line(self, line: str) -> None:
        if not line.strip():
            return
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return
        if not isinstance(record, dict):
            return
        self._record_graphql_query_metadata(cast(dict[str, Any], record))
        trace_request = graphql_trace_request_from_record(cast(dict[str, Any], record))
        if trace_request is None:
            return
        trace_request.update(
            {"variant": self.variant, "iteration": self.iteration, "case": self.case_name}
        )
        graphql_span_key = self._graphql_span_key_for_http_record(cast(dict[str, Any], record))
        trace_id = trace_request["trace_id"]
        submit_request: dict[str, Any] | None = None
        with self._lock:
            if graphql_span_key is not None:
                graphql_query = self._graphql_queries_by_span.get(graphql_span_key)
                if graphql_query is not None:
                    trace_request["graphql_query"] = dict(graphql_query)
                self._trace_requests_by_graphql_span[graphql_span_key] = trace_request
            existing_request = self._requests_by_trace_id.get(trace_id)
            if existing_request is None or trace_summary_duration_ms(
                trace_request
            ) > trace_summary_duration_ms(existing_request):
                self._requests_by_trace_id[trace_id] = trace_request
            if self.limit is None and trace_id not in self._queued_trace_ids:
                self._queued_trace_ids.add(trace_id)
                submit_request = trace_request
        if submit_request is not None:
            future = self.fetch_pool.submit(submit_request, self)
            with self._lock:
                self._futures.append(future)

    def _record_graphql_query_metadata(self, record: dict[str, Any]) -> None:
        metadata = graphql_query_metadata_from_record(record)
        if metadata is None:
            return
        span_key = graphql_query_span_key(record)
        if span_key is None:
            return
        with self._lock:
            existing_metadata = self._graphql_queries_by_span.get(span_key, {})
            merged_metadata = existing_metadata | metadata
            self._graphql_queries_by_span[span_key] = merged_metadata
            trace_request = self._trace_requests_by_graphql_span.get(span_key)
            if trace_request is not None:
                trace_request["graphql_query"] = dict(merged_metadata)

    @staticmethod
    def _graphql_span_key_for_http_record(record: dict[str, Any]) -> tuple[str, str] | None:
        trace_id = optional_string(record.get("trace"))
        parent_span_id = optional_string(record.get("parent_span"))
        if trace_id is None or parent_span_id is None:
            return None
        return trace_id, parent_span_id

    def _submit_limited_requests(self) -> None:
        if self.limit is None:
            return
        with self._lock:
            trace_requests = sorted(
                self._requests_by_trace_id.values(),
                key=trace_summary_duration_ms,
                reverse=True,
            )[: self.limit]
            new_trace_requests = [
                trace_request
                for trace_request in trace_requests
                if trace_request["trace_id"] not in self._queued_trace_ids
            ]
            self._queued_trace_ids.update(
                trace_request["trace_id"] for trace_request in new_trace_requests
            )
        futures = [
            self.fetch_pool.submit(trace_request, self) for trace_request in new_trace_requests
        ]
        with self._lock:
            self._futures.extend(futures)


class CommandPermutationRunner:
    """Run command cases and assert CLI/log outcomes."""

    def __init__(
        self,
        variant: RunVariant,
        environment: dict[str, str],
        *,
        iteration: int,
        keep_going: bool,
        fetch_sg_traces: bool,
        jaeger_trace_limit: int | None,
        jaeger_trace_fetch_pool: JaegerTraceFetchPool | None,
        sample_interval: float,
        external_sample_interval: float,
    ) -> None:
        self.variant = variant
        self.environment = environment
        self.iteration = iteration
        self.keep_going = keep_going
        self.fetch_sg_traces = fetch_sg_traces
        self.jaeger_trace_limit = jaeger_trace_limit
        self.jaeger_trace_fetch_pool = jaeger_trace_fetch_pool
        self.sample_interval = sample_interval
        self.external_sample_interval = external_sample_interval
        self.results: list[CommandResult] = []
        self.failures: list[str] = []
        self.jaeger_collectors: list[JaegerTraceCollector] = []

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
            *(("--fetch-sg-traces",) if self.fetch_sg_traces else ()),
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
        log_path: Path | None = None
        jaeger_collector: JaegerTraceCollector | None = None
        assert process.stdout is not None
        for line in process.stdout:
            output_lines.append(line)
            print(line, end="")
            if log_path is None:
                log_path = _extract_log_path(line)
                if log_path is not None and self.jaeger_trace_fetch_pool is not None:
                    jaeger_collector = JaegerTraceCollector(
                        log_path,
                        self.jaeger_trace_limit,
                        self.jaeger_trace_fetch_pool,
                        variant=self.variant.name,
                        iteration=self.iteration,
                        case_name=case.name,
                    )
                    jaeger_collector.start()
        return_code = process.wait()
        external_sampler.stop()
        output = "".join(output_lines)
        elapsed_seconds = time.monotonic() - started_at
        if log_path is None:
            log_path = _extract_log_path(output)
        if (
            jaeger_collector is None
            and log_path is not None
            and self.jaeger_trace_fetch_pool is not None
        ):
            jaeger_collector = JaegerTraceCollector(
                log_path,
                self.jaeger_trace_limit,
                self.jaeger_trace_fetch_pool,
                variant=self.variant.name,
                iteration=self.iteration,
                case_name=case.name,
            )
            jaeger_collector.start()
        run_record: dict[str, Any] | None = None
        memory: MemorySummary | None = None
        phase_memory: list[PhaseMemorySummary] = []
        artifact_sizes: dict[str, int] = {}
        workload: dict[str, int | float | str] = {}
        if jaeger_collector is not None:
            jaeger_collector.finish_log_capture()
            self.jaeger_collectors.append(jaeger_collector)
            jaeger_traces = jaeger_collector.summaries
        else:
            jaeger_traces = []
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
            jaeger_traces=jaeger_traces,
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
    config = load_end_to_end_config()
    logging_settings = src.logging_settings_from_config(
        config,
        logs_dir=Path("logs-test-end-to-end"),
    )
    with src.logging(
        config,
        command="test_end_to_end",
        git_cwd=Path.cwd(),
        logging_config=logging_settings,
    ):
        run_end_to_end(config)


def load_end_to_end_config() -> EndToEndConfig:
    """Load runner Config from CLI flags, environment, and .env."""
    config = src.parse_args(
        EndToEndConfig,
        description="Run src-auth-perms-sync end-to-end cases against a test instance.",
    )
    validate_date(config.future_date, "--future-date")
    if any(delay < 0 for delay in config.jaeger_retry_delays):
        raise SystemExit("--jaeger-retry-delays values must be >= 0")
    user = config.user or os.environ.get("SRC_AUTH_PERMS_SYNC_TEST_USER") or os.environ.get("USER")
    if not user:
        raise SystemExit("--user is required when SRC_AUTH_PERMS_SYNC_TEST_USER and USER are unset")
    normalized_endpoint = src.normalize_sourcegraph_endpoint(config.src_endpoint)
    if not config.allow_non_test_endpoint:
        assert_test_endpoint(normalized_endpoint)
    return config.model_copy(update={"src_endpoint": normalized_endpoint, "user": user})


def run_end_to_end(config: EndToEndConfig) -> None:
    """Run the full matrix for the loaded Config."""
    variants = run_variants(config)
    environment = command_environment(config)
    all_results: list[CommandResult] = []
    all_failures: list[str] = []
    all_jaeger_collectors: list[JaegerTraceCollector] = []
    jaeger_trace_fetch_pool = create_jaeger_trace_fetch_pool(config)
    sourcegraph_load_monitor = create_sourcegraph_load_monitor(config)
    latest_baseline_repositories: set[str] = set()
    try:
        if sourcegraph_load_monitor is not None:
            sourcegraph_load_monitor.start()
        with src.event(
            "end_to_end_matrix",
            repeat=config.repeat,
            variant_count=len(variants),
            fetch_sg_traces=config.fetch_sg_traces,
            sourcegraph_load_monitor=sourcegraph_load_monitor is not None,
        ) as matrix_summary:
            if sourcegraph_load_monitor is not None:
                matrix_summary["sourcegraph_load_monitor_dir"] = str(
                    sourcegraph_load_monitor.output_dir
                )
            for iteration in range(1, config.repeat + 1):
                for variant in variants:
                    with src.stage("matrix_variant", variant=variant.name, iteration=iteration):
                        runner = CommandPermutationRunner(
                            variant,
                            environment,
                            iteration=iteration,
                            keep_going=config.keep_going,
                            fetch_sg_traces=config.fetch_sg_traces,
                            jaeger_trace_limit=config.jaeger_trace_limit,
                            jaeger_trace_fetch_pool=jaeger_trace_fetch_pool,
                            sample_interval=config.sample_interval,
                            external_sample_interval=config.external_sample_interval,
                        )
                        try:
                            latest_baseline_repositories = run_matrix(config, runner)
                        finally:
                            all_results.extend(runner.results)
                            all_failures.extend(
                                f"{variant.name}: {failure}" for failure in runner.failures
                            )
                            all_jaeger_collectors.extend(runner.jaeger_collectors)
            matrix_summary["case_count"] = len(all_results)
            matrix_summary["failure_count"] = len(all_failures)
    finally:
        wait_for_jaeger_trace_collectors(all_jaeger_collectors)
        if jaeger_trace_fetch_pool is not None:
            jaeger_trace_fetch_pool.close()
        if sourcegraph_load_monitor is not None:
            sourcegraph_load_monitor.stop()
    if all_failures:
        print("\nFailures:", file=sys.stderr)
        for failure in all_failures:
            print(f"- {failure}", file=sys.stderr)
        raise SystemExit(1)

    print("\nAll end-to-end cases passed.")
    print(f"Cases passed: {len(all_results)}")
    print(f"Baseline repositories for {config.user}: {len(latest_baseline_repositories)}")
    print_memory_summary(all_results, config.memory_summary_limit)
    print_phase_memory_summary(all_results, config.memory_summary_limit)
    comparisons = compare_variants(all_results)
    print_comparison_summary(comparisons)
    write_results_files(all_results, comparisons, config, sourcegraph_load_monitor)
    raise_for_memory_regressions(comparisons, config)


def run_variants(config: EndToEndConfig) -> list[RunVariant]:
    """Return the executable variants to measure."""
    candidate_command = config.candidate_command or config.src_auth_perms_sync_command
    candidate = RunVariant("candidate", tuple(shlex.split(candidate_command)))
    if not candidate.executable:
        raise SystemExit("candidate command cannot be empty")
    if not config.baseline_command:
        return [candidate]
    baseline = RunVariant("baseline", tuple(shlex.split(config.baseline_command)))
    if not baseline.executable:
        raise SystemExit("--baseline-command cannot be empty")
    return [baseline, candidate]


def create_jaeger_trace_fetch_pool(
    config: EndToEndConfig,
) -> JaegerTraceFetchPool | None:
    """Return the shared trace fetch pool for this run, if trace collection is enabled."""
    if not config.fetch_sg_traces or config.jaeger_trace_limit == 0:
        return None
    return JaegerTraceFetchPool(
        config,
        parallelism=config.jaeger_trace_parallelism,
        initial_delay_seconds=config.jaeger_initial_delay_seconds,
        retry_delays_seconds=config.jaeger_retry_delays,
        jsonl_path=jaeger_trace_jsonl_path(config),
        trace_directory=jaeger_trace_directory(config),
    )


def jaeger_trace_jsonl_path(config: EndToEndConfig) -> Path | None:
    """Return where to stream trace summaries for this run."""
    if config.jaeger_trace_jsonl is not None:
        return config.jaeger_trace_jsonl
    anchor = config.results_json or config.results_csv
    if anchor is not None:
        return anchor.with_name(f"{anchor.stem}-jaeger-traces.jsonl")
    stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%d-%H%M%S")
    return Path("/tmp") / f"src-auth-perms-sync-end-to-end-jaeger-traces-{stamp}.jsonl"


def jaeger_trace_directory(config: EndToEndConfig) -> Path:
    """Return the directory where complete raw Jaeger traces should be stored."""
    if config.jaeger_trace_directory is not None:
        return config.jaeger_trace_directory
    anchor = config.results_json or config.results_csv
    if anchor is not None:
        return anchor.with_name(f"{anchor.stem}-jaeger-traces")
    stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%d-%H%M%S")
    return Path("/tmp") / f"src-auth-perms-sync-end-to-end-jaeger-traces-{stamp}"


def create_sourcegraph_load_monitor(config: EndToEndConfig) -> SourcegraphLoadMonitor | None:
    """Return the Sourcegraph load monitor for this run, if enabled."""
    if not config.monitor_sourcegraph_load:
        return None
    return SourcegraphLoadMonitor(config, sourcegraph_monitor_output_dir(config))


def sourcegraph_monitor_output_dir(config: EndToEndConfig) -> Path:
    """Return where Sourcegraph pod/Postgres monitor artifacts should be stored."""
    if config.sourcegraph_monitor_output_dir is not None:
        return config.sourcegraph_monitor_output_dir
    anchor = config.results_json or config.results_csv
    if anchor is not None:
        return anchor.with_name(f"{anchor.stem}-sourcegraph-load")
    stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%d-%H%M%S")
    return Path("/tmp") / f"src-auth-perms-sync-end-to-end-sourcegraph-load-{stamp}"


def sourcegraph_monitor_script_path() -> Path:
    """Return the lower-level monitor script used by the e2e orchestrator."""
    return Path(__file__).resolve().with_name("memory-efficiency-monitor-sourcegraph.sh")


def complete_jaeger_trace_path(trace_directory: Path, trace_request: dict[str, Any]) -> Path:
    """Return the stable per-trace path for a complete Jaeger trace payload."""
    variant = safe_path_part(trace_request.get("variant"), default="variant")
    iteration = int_field(trace_request, "iteration") or 0
    case_name = safe_path_part(trace_request.get("case"), default="case")
    trace_id = safe_path_part(trace_request.get("trace_id"), default="trace")
    return trace_directory / variant / f"iteration-{iteration:04d}" / case_name / f"{trace_id}.json"


def safe_path_part(value: object, *, default: str) -> str:
    """Return a filesystem-safe path segment for generated trace artifacts."""
    text = str(value) if value is not None else ""
    safe_text = SAFE_PATH_PART_PATTERN.sub("-", text).strip("-.")
    return safe_text[:120] or default


def command_environment(config: EndToEndConfig) -> dict[str, str]:
    """Return a deterministic child environment for CLI config parsing."""
    environment = dict(os.environ)
    for name in list(environment):
        if name.startswith(REMOVED_SRC_AUTH_PERMS_SYNC_ENVIRONMENT_PREFIX):
            del environment[name]
    environment["SRC_ENDPOINT"] = config.src_endpoint
    environment["SRC_ACCESS_TOKEN"] = config.src_access_token
    return environment


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
    config: EndToEndConfig,
    runner: CommandPermutationRunner,
) -> set[str]:
    for case in invalid_configuration_cases(config):
        runner.run(case)

    baseline_result: CommandResult | None = None
    for case in read_only_cases(config):
        result = runner.run(case)
        if case.name == "get-users-baseline":
            baseline_result = result
    assert baseline_result is not None
    baseline_repositories = repositories_for_user(snapshot_path(baseline_result), config.user)

    run_safe_set_cases(config, runner)
    run_full_apply_cases(config, runner)

    set_user_dry_run = runner.run(set_user_dry_run_case(config))
    runner.run(restore_scoped_dry_run_case(snapshot_path(set_user_dry_run), config))
    set_user_apply = runner.run(set_user_apply_case(config))
    try:
        runner.run(restore_scoped_apply_case(snapshot_path(set_user_apply), config))
    finally:
        final_result = runner.run(final_get_user_case(config))
        final_repositories = repositories_for_user(snapshot_path(final_result), config.user)
        if final_repositories != baseline_repositories:
            added = sorted(final_repositories - baseline_repositories)
            removed = sorted(baseline_repositories - final_repositories)
            raise CommandPermutationFailure(
                f"final user baseline differs after cleanup; added={added}, removed={removed}"
            )

    runner.run(users_without_explicit_permissions_no_op_case(config))
    runner.run(sync_saml_apply_case())
    return baseline_repositories


def invalid_configuration_cases(config: EndToEndConfig) -> list[CommandCase]:
    restore_placeholder = "definitely-missing-before.json"
    missing_maps = "definitely-missing-command-permutation-maps.yaml"
    command_pairs: list[tuple[str, tuple[str, ...]]] = [
        ("get-set", ("get", "set")),
        ("get-restore", ("get", "restore", "--restore-path", restore_placeholder)),
        ("set-restore", ("set", "--maps-path", "maps.yaml", "restore")),
    ]
    cases = [
        CommandCase(
            name=f"invalid-multiple-commands-{name}",
            arguments=command_arguments,
            expected_exit_code=2,
            must_contain=("unrecognized arguments",),
        )
        for name, command_arguments in command_pairs
    ]
    cases.append(
        CommandCase(
            name="invalid-restore-sync-saml-orgs",
            arguments=("restore", "--restore-path", restore_placeholder, "--sync-saml-orgs"),
            expected_exit_code=2,
            must_contain=("unrecognized arguments",),
        )
    )
    cases.extend(
        [
            CommandCase(
                name="invalid-full-without-set",
                arguments=("get", "--full"),
                expected_exit_code=2,
                must_contain=("unrecognized arguments",),
            ),
            CommandCase(
                name="invalid-set-full-and-user",
                arguments=("set", "--full", "--users", config.user),
                expected_exit_code=2,
                must_contain=("choose at most one",),
            ),
            CommandCase(
                name="invalid-set-full-and-users-without-explicit-perms",
                arguments=(
                    "set",
                    "--full",
                    "--users-without-explicit-perms",
                ),
                expected_exit_code=2,
                must_contain=("choose at most one",),
            ),
            CommandCase(
                name="invalid-user-filter-conflict",
                arguments=("get", "--users", config.user, "--users-without-explicit-perms"),
                expected_exit_code=2,
                must_contain=("choose only one of --users or --users-without-explicit-perms",),
            ),
            CommandCase(
                name="invalid-restore-user-filter",
                arguments=(
                    "restore",
                    "--restore-path",
                    restore_placeholder,
                    "--users",
                    config.user,
                ),
                expected_exit_code=2,
                must_contain=("unrecognized arguments",),
            ),
            CommandCase(
                name="invalid-sync-created-after-filter",
                arguments=("sync-saml-orgs", "--created-after", config.future_date),
                expected_exit_code=2,
                must_contain=("unrecognized arguments",),
            ),
            CommandCase(
                name="invalid-date-shape",
                arguments=("get", "--created-after", "2026-1-01"),
                expected_exit_code=2,
            ),
            CommandCase(
                name="invalid-date-value",
                arguments=("get", "--created-after", "2026-02-31"),
                expected_exit_code=1,
                must_contain=("--created-after must use YYYY-MM-DD",),
            ),
            CommandCase(
                name="invalid-missing-set-file",
                arguments=("set", "--maps-path", missing_maps),
                expected_exit_code=1,
                expected_log_command="set_full",
                expected_log_status="error",
                must_contain=("set input file does not exist",),
            ),
            CommandCase(
                name="invalid-removed-repositories-created-after-flag",
                arguments=("get", "--repositories-created-after", config.future_date),
                expected_exit_code=2,
                must_contain=("unrecognized arguments",),
            ),
            CommandCase(
                name="invalid-removed-get-schema-flag",
                arguments=("get", "--get-schema", "definitely-missing-schema.gql"),
                expected_exit_code=2,
                must_contain=("unrecognized arguments",),
            ),
        ]
    )
    return cases


def read_only_cases(config: EndToEndConfig) -> list[CommandCase]:
    cases = [
        CommandCase(
            name="help",
            arguments=("--help",),
            must_contain=("usage: src-auth-perms-sync", "commands:"),
            must_not_contain=("--repositories-created-after", "--get-schema"),
        ),
        CommandCase(
            name="get-users-baseline",
            arguments=("get", "--users", config.user),
            expected_log_command="get",
            must_contain=("Wrote before-snapshot",),
        ),
        CommandCase(
            name="get-created-after-future",
            arguments=("get", "--created-after", config.future_date),
            expected_log_command="get",
            must_contain=("Selected 0 user(s) for get output",),
        ),
        CommandCase(
            name="get-user-created-after-future",
            arguments=("get", "--users", config.user, "--created-after", config.future_date),
            expected_log_command="get",
            must_contain_one_of=(
                "Selected 0 user(s) for get output",
                "Wrote before-snapshot",
            ),
        ),
        CommandCase(
            name="get-users-without-explicit-perms-created-after-future",
            arguments=(
                "get",
                "--users-without-explicit-perms",
                "--created-after",
                config.future_date,
            ),
            expected_log_command="get",
            must_contain=("Selected 0 user(s) for get output",),
        ),
    ]
    return cases


def run_safe_set_cases(config: EndToEndConfig, runner: CommandPermutationRunner) -> None:
    runner.run(
        CommandCase(
            name="set-explicit-full-no-op-apply",
            arguments=(
                "set",
                "--full",
                "--created-after",
                config.future_date,
                "--apply",
                "--no-backup",
                "--parallelism",
                str(config.parallelism),
            ),
            expected_log_command="set_full",
            must_contain=("No repos resolved across any mapping",),
        )
    )


def set_user_dry_run_case(config: EndToEndConfig) -> CommandCase:
    return CommandCase(
        name="set-user-dry-run",
        arguments=("set", "--users", config.user),
        expected_log_command="set_users",
        must_contain=("Dry run complete",),
    )


def set_user_apply_case(config: EndToEndConfig) -> CommandCase:
    return CommandCase(
        name="set-user-apply",
        arguments=(
            "set",
            "--users",
            config.user,
            "--apply",
            "--parallelism",
            str(config.parallelism),
        ),
        expected_log_command="set_users",
        must_contain_one_of=(
            "VALIDATION OK: all",
            "All selected users already have the mapped explicit grants",
        ),
    )


def users_without_explicit_permissions_no_op_case(config: EndToEndConfig) -> CommandCase:
    return CommandCase(
        name="set-users-without-explicit-perms-no-op-apply",
        arguments=(
            "set",
            "--users-without-explicit-perms",
            "--created-after",
            config.future_date,
            "--apply",
            "--no-backup",
            "--parallelism",
            str(config.parallelism),
        ),
        expected_log_command="set_users_without_explicit_perms",
        must_contain=("No users selected",),
    )


def restore_scoped_dry_run_case(snapshot: Path, config: EndToEndConfig) -> CommandCase:
    return CommandCase(
        name="restore-scoped-dry-run",
        arguments=(
            "restore",
            "--restore-path",
            str(snapshot),
            "--parallelism",
            str(config.parallelism),
        ),
        expected_log_command="restore",
        must_contain=("Dry run complete",),
    )


def restore_scoped_apply_case(snapshot: Path, config: EndToEndConfig) -> CommandCase:
    return CommandCase(
        name="restore-scoped-apply-cleanup",
        arguments=(
            "restore",
            "--restore-path",
            str(snapshot),
            "--apply",
            "--parallelism",
            str(config.parallelism),
        ),
        expected_log_command="restore",
        must_contain_one_of=(
            "VALIDATION OK: scoped restore matches the target snapshot",
            "Scoped restore target already matches current state",
        ),
    )


def sync_saml_apply_case() -> CommandCase:
    return CommandCase(
        name="sync-saml-orgs-apply",
        arguments=("sync-saml-orgs", "--apply"),
        expected_log_command="sync_saml_orgs",
        must_contain=("VALIDATION OK: all target org memberships match",),
    )


def final_get_user_case(config: EndToEndConfig) -> CommandCase:
    return CommandCase(
        name="final-get-user-baseline-check",
        arguments=("get", "--users", config.user),
        expected_log_command="get",
        must_contain=("Wrote before-snapshot",),
    )


def run_full_apply_cases(config: EndToEndConfig, runner: CommandPermutationRunner) -> None:
    dry_run_result = runner.run(
        CommandCase(
            name="set-full-dry-run",
            arguments=("set",),
            expected_log_command="set_full",
            must_contain=("Dry run complete",),
        )
    )
    baseline_snapshot = snapshot_path(dry_run_result)

    if config.include_redundant_scale_cases:
        try:
            runner.run(
                CommandCase(
                    name="set-full-apply",
                    arguments=(
                        "set",
                        "--apply",
                        "--parallelism",
                        str(config.parallelism),
                    ),
                    expected_log_command="set_full",
                    must_contain=("VALIDATION OK",),
                )
            )
        finally:
            runner.run(
                restore_full_apply_case(
                    "restore-full-apply-cleanup",
                    baseline_snapshot,
                    config,
                    no_backup=False,
                )
            )

    try:
        runner.run(
            CommandCase(
                name="set-full-no-backup-apply",
                arguments=(
                    "set",
                    "--apply",
                    "--no-backup",
                    "--parallelism",
                    str(config.parallelism),
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
                config,
                no_backup=True,
            )
        )

    # Covers combined set+SAML dispatch and SAML dry-run with a user-scoped
    # set path, so the default suite keeps only one expensive full-snapshot
    # case. Pass --include-redundant-scale-cases to restore older overlap.
    runner.run(
        CommandCase(
            name="set-user-sync-saml-orgs-dry-run",
            arguments=(
                "set",
                "--users",
                config.user,
                "--sync-saml-orgs",
            ),
            expected_log_command="set_users_sync_saml_orgs",
            must_contain=("Dry run complete",),
        )
    )


def restore_full_apply_case(
    name: str,
    snapshot: Path,
    config: EndToEndConfig,
    *,
    no_backup: bool,
) -> CommandCase:
    restore_arguments = [
        "restore",
        "--restore-path",
        str(snapshot),
        "--apply",
        "--parallelism",
        str(config.full_restore_parallelism),
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
    """Collect named workload dimensions from structured log records.

    Earlier e2e summaries used raw field names from unrelated events, which made
    values like `total_users` and `repo_count` ambiguous. Keep this summary
    event-aware so each key says what it counts.
    """
    workload: dict[str, int | float | str] = {}
    for record in records:
        event_name = optional_string(record.get("event"))
        phase = optional_string(record.get("phase"))
        if event_name == "capture_explicit_grants":
            record_workload_max(workload, "sourcegraph_user_count", record.get("total_users"))
            if phase == "end":
                record_workload_max(workload, "captured_user_count", record.get("user_count"))
        elif event_name in {"build_snapshot", "build_user_scoped_snapshot"} and phase == "end":
            record_workload_max(workload, "snapshot_user_count_max", record.get("user_count"))
            record_workload_max(
                workload,
                "snapshot_repos_with_explicit_grants_max",
                record.get("repos_with_explicit_grants"),
            )
            record_workload_max(workload, "snapshot_total_grants_max", record.get("total_grants"))
            record_workload_max(workload, "captured_user_count", record.get("user_count"))
        elif event_name == "user_explicit_repos_batch_fetch" and phase == "end":
            record_workload_max(workload, "batch_user_count_max", record.get("user_count"))
            record_workload_max(
                workload,
                "batch_fetched_grant_count_max",
                record.get("fetched_grant_count")
                if "fetched_grant_count" in record
                else record.get("repo_count"),
            )
        elif event_name == "load_repos_by_external_service" and phase == "end":
            record_workload_max(workload, "loaded_repo_count", record.get("repo_count"))
            record_workload_max(
                workload,
                "expected_repo_count",
                record.get("expected_repo_count"),
            )
        elif event_name == "apply_username_overwrites":
            record_workload_max(workload, "apply_payload_count", record.get("payload_count"))
            record_workload_max(
                workload,
                "apply_payload_grant_count",
                record.get("payload_grant_count")
                if "payload_grant_count" in record
                else record.get("total_users"),
            )
            record_workload_max(workload, "parallelism", record.get("parallelism"))
            if phase == "end":
                record_workload_max(
                    workload,
                    "apply_mutations_succeeded",
                    record.get("succeeded"),
                )
                record_workload_max(workload, "apply_mutations_failed", record.get("failed"))
                record_workload_max(workload, "apply_mutations_canceled", record.get("canceled"))
        elif (
            event_name
            in {
                "cmd_get",
                "cmd_restore",
                "cmd_restore_user_scoped",
                "cmd_set",
                "cmd_set_additive_user",
                "cmd_set_additive_users_without_explicit_perms",
            }
            and phase == "end"
        ):
            record_command_workload(workload, record)
        elif event_name in {"sync_saml_orgs", "cmd_sync_saml_orgs"} and phase == "end":
            record_workload_max(
                workload,
                "target_organizations",
                record.get("target_organizations"),
            )
            record_workload_max(workload, "desired_memberships", record.get("desired_memberships"))

    record_workload_model_dimensions(workload)
    return workload


def record_command_workload(workload: dict[str, int | float | str], record: dict[str, Any]) -> None:
    """Copy command-level counts using names that preserve their meaning."""
    event_name = optional_string(record.get("event"))
    repo_count = record.get("repo_count")
    total_grants = record.get("total_grants")
    if event_name == "cmd_set":
        record_workload_max(workload, "planned_repo_count", repo_count)
        record_workload_max(workload, "planned_total_grants", total_grants)
    elif event_name == "cmd_get":
        record_workload_max(workload, "selected_user_count", record.get("user_count"))
        record_workload_max(workload, "selected_total_grants", total_grants)
    elif event_name == "cmd_restore":
        record_workload_max(workload, "restore_snapshot_repo_count", record.get("snapshot_repos"))
        record_workload_max(
            workload,
            "restore_snapshot_total_grants",
            record.get("snapshot_grants"),
        )
    elif event_name == "cmd_set_additive_user":
        record_workload_max(workload, "selected_user_count", record.get("user_count"))
        record_workload_max(workload, "planned_repo_count", repo_count)
        record_workload_max(workload, "planned_total_grants", total_grants)

    record_workload_max(workload, "mapping_count", record.get("mapping_count"))
    record_workload_max(workload, "mutations_succeeded", record.get("mutations_succeeded"))
    record_workload_max(workload, "mutations_failed", record.get("mutations_failed"))
    record_workload_max(workload, "mutations_canceled", record.get("mutations_canceled"))


def record_workload_model_dimensions(workload: dict[str, int | float | str]) -> None:
    """Add the canonical dimensions used by memory modeling."""
    user_count = max_workload_number(
        workload,
        (
            "selected_user_count",
            "captured_user_count",
            "snapshot_user_count_max",
            "sourcegraph_user_count",
        ),
    )
    repo_count = max_workload_number(
        workload,
        (
            "planned_repo_count",
            "restore_snapshot_repo_count",
            "snapshot_repos_with_explicit_grants_max",
            "loaded_repo_count",
        ),
    )
    grant_count = max_workload_number(
        workload,
        (
            "planned_total_grants",
            "restore_snapshot_total_grants",
            "selected_total_grants",
            "snapshot_total_grants_max",
            "apply_payload_grant_count",
        ),
    )
    if user_count is not None:
        workload["memory_model_user_count"] = user_count
    if repo_count is not None:
        workload["memory_model_repo_count"] = repo_count
    if grant_count is not None:
        workload["memory_model_grant_count"] = grant_count


def max_workload_number(
    workload: dict[str, int | float | str], field_names: Sequence[str]
) -> int | float | None:
    """Return the largest numeric value found for the supplied workload fields."""
    values = [
        value
        for field_name in field_names
        if isinstance((value := workload.get(field_name)), int | float)
    ]
    return max(values) if values else None


def record_workload_max(
    workload: dict[str, int | float | str], field_name: str, value: object
) -> None:
    """Record the maximum numeric value for a named workload dimension."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return
    old_value = workload.get(field_name)
    if not isinstance(old_value, int | float) or value > old_value:
        workload[field_name] = value


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


def wait_for_jaeger_trace_collectors(collectors: list[JaegerTraceCollector]) -> None:
    if not collectors:
        return
    print(f"\nWaiting for {len(collectors)} background Jaeger trace collector(s) ...")
    for collector in collectors:
        collector.wait()


def graphql_query_metadata_from_record(record: dict[str, Any]) -> dict[str, Any] | None:
    """Return correlation metadata from a structured `graphql_query` log record."""
    if record.get("event") != "graphql_query":
        return None
    metadata: dict[str, Any] = {
        "span_id": record.get("span"),
        "parent_span_id": record.get("parent_span"),
        "trace_id": record.get("trace"),
    }
    phase = record.get("phase")
    if phase == "start":
        metadata["started_at"] = record.get("ts")
    elif phase == "end":
        metadata["ended_at"] = record.get("ts")
    for field_name in (
        "cursor_present",
        "duration_ms",
        "error_type",
        "graphql_client",
        "page_number",
        "page_size",
        "query_bytes",
        "query_name",
        "response_fields",
        "status",
        "url",
        "variable_names",
        # Current src-py-lib logs variable names only. Keep these optional fields
        # so raw trace artifacts automatically include values if the GraphQL log
        # event grows an opt-in sanitized-variable field later.
        "input_variables",
        "variable_values",
        "variables",
    ):
        if field_name in record:
            metadata[field_name] = record[field_name]
    return {key: value for key, value in metadata.items() if value is not None}


def graphql_query_span_key(record: dict[str, Any]) -> tuple[str, str] | None:
    """Return the `(trace_id, span_id)` key for a GraphQL query log span."""
    trace_id = optional_string(record.get("trace"))
    span_id = optional_string(record.get("span"))
    if trace_id is None or span_id is None:
        return None
    return trace_id, span_id


def graphql_trace_request_from_record(record: dict[str, Any]) -> dict[str, Any] | None:
    if record.get("event") != "http_request" or record.get("phase") != "end":
        return None
    if not str(record.get("url", "")).endswith("/.api/graphql"):
        return None
    trace = sourcegraph_trace_from_record(record)
    if trace is None:
        return None
    return trace.to_json() | {
        "duration_ms": float_field(record, "duration_ms") or 0.0,
        "timestamp": record.get("ts"),
        "status": record.get("status"),
        "status_code": record.get("status_code"),
        "error_type": record.get("error_type"),
    }


def trace_summary_duration_ms(summary: dict[str, Any]) -> float:
    duration_ms = summary.get("duration_ms")
    return float(duration_ms) if isinstance(duration_ms, int | float) else 0.0


def sourcegraph_trace_from_record(record: dict[str, Any]) -> src.SourcegraphTrace | None:
    request_headers = string_headers(record.get("request_headers"))
    response_headers = string_headers(record.get("response_headers"))
    trace = sourcegraph_trace_from_headers(response_headers, request_headers)
    if trace is not None:
        return trace
    trace_id = trace_id_from_traceparent(header_value(request_headers, "traceparent"))
    if trace_id is None:
        return None
    return src.SourcegraphTrace(
        trace_id=trace_id,
        trace_url=header_value(response_headers, "x-trace-url"),
    )


def sourcegraph_trace_from_request(trace_request: dict[str, Any]) -> src.SourcegraphTrace:
    return src.SourcegraphTrace(
        trace_id=str(trace_request["trace_id"]),
        span_id=optional_string(trace_request.get("span_id")),
        trace_url=optional_string(trace_request.get("trace_url")),
        parent_trace_id=optional_string(trace_request.get("parent_trace_id")),
        parent_span_id=optional_string(trace_request.get("parent_span_id")),
    )


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


def string_headers(headers: object) -> dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    values: dict[str, str] = {}
    typed_headers = cast(dict[object, object], headers)
    for header_name, value in typed_headers.items():
        if not isinstance(header_name, str):
            continue
        if isinstance(value, str):
            values[header_name] = value
        elif isinstance(value, list):
            value_items = cast(list[object], value)
            string_values = [item for item in value_items if isinstance(item, str)]
            if string_values:
                values[header_name] = string_values[0]
    return values


def header_value(headers: Mapping[str, str], name: str) -> str | None:
    lower_name = name.lower()
    for header_name, value in headers.items():
        if header_name.lower() == lower_name:
            return value
    return None


def optional_string(value: object) -> str | None:
    return value if isinstance(value, str) else None


def print_jaeger_trace_summaries(summaries: list[dict[str, Any]]) -> None:
    found = sum(1 for summary in summaries if summary.get("jaeger_found") is True)
    print(f"Jaeger trace summaries: fetched {found} / {len(summaries)}.")
    for summary in summaries:
        duration_ms = float(summary.get("duration_ms") or 0)
        trace_id = summary.get("trace_id")
        if summary.get("jaeger_found") is not True:
            print(f"  {duration_ms:.0f}ms {trace_id}: {summary.get('error')}")
            continue
        hot_text = format_hot_operations(summary.get("hot_operations"))
        print(
            f"  {duration_ms:.0f}ms {trace_id}: {summary.get('span_count', 0)} span(s); {hot_text}"
        )


def format_hot_operations(value: object) -> str:
    if not isinstance(value, list):
        return ""
    return "; ".join(
        format_hot_operation(cast(dict[object, object], operation))
        for operation in cast(list[object], value)[:3]
        if isinstance(operation, dict)
    )


def format_hot_operation(operation: dict[object, object]) -> str:
    return (
        f"{operation.get('operation')} x{operation.get('count')} "
        f"sum={operation.get('sum_ms')}ms max={operation.get('max_ms')}ms"
    )


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
    rows.sort(key=lambda result: result_peak_rss_mb(result) or 0.0, reverse=True)
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
    config: EndToEndConfig,
    sourcegraph_load_monitor: SourcegraphLoadMonitor | None,
) -> None:
    if config.results_json is not None:
        write_results_json(config.results_json, results, comparisons, sourcegraph_load_monitor)
    if config.results_csv is not None:
        write_results_csv(config.results_csv, results)
        phase_csv = phase_results_csv_path(config.results_csv)
        write_phase_results_csv(phase_csv, results)


def write_results_json(
    path: Path,
    results: list[CommandResult],
    comparisons: list[CaseComparison],
    sourcegraph_load_monitor: SourcegraphLoadMonitor | None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    sourcegraph_monitor: dict[str, Any] | None = None
    if sourcegraph_load_monitor is not None:
        sourcegraph_monitor = {
            "output_dir": str(sourcegraph_load_monitor.output_dir),
            "log_path": str(sourcegraph_load_monitor.log_path),
        }
    with path.open("w", encoding="utf-8") as output_file:
        json.dump(
            {
                "generated_at": datetime.datetime.now(datetime.UTC).isoformat(),
                "sourcegraph_load_monitor": sourcegraph_monitor,
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
        "jaeger_trace_count",
        "jaeger_trace_found_count",
        "jaeger_trace_error_count",
        "slowest_graphql_trace_ms",
        "slowest_graphql_trace_id",
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


def raise_for_memory_regressions(comparisons: list[CaseComparison], config: EndToEndConfig) -> None:
    percent_limit = config.fail_on_memory_regression_percent
    mib_limit = config.fail_on_memory_regression_mib
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
        "jaeger_traces": result.jaeger_traces,
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
        "jaeger_trace_count": len(result.jaeger_traces),
        "jaeger_trace_found_count": sum(
            1 for trace in result.jaeger_traces if trace.get("jaeger_found") is True
        ),
        "jaeger_trace_error_count": sum(
            1 for trace in result.jaeger_traces if trace.get("jaeger_found") is not True
        ),
        "slowest_graphql_trace_ms": format_optional_float(slowest_graphql_trace_ms(result)),
        "slowest_graphql_trace_id": slowest_graphql_trace_id(result) or "",
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
    for field_name in (
        "memory_model_user_count",
        "memory_model_repo_count",
        "memory_model_grant_count",
    ):
        value = result.workload.get(field_name)
        if isinstance(value, int | float) and value > 0:
            normalized[f"peak_rss_mb_per_{field_name}"] = peak_rss_mb / float(value)
    return normalized


def slowest_graphql_trace_ms(result: CommandResult) -> float | None:
    if not result.jaeger_traces:
        return None
    duration = result.jaeger_traces[0].get("duration_ms")
    return float(duration) if isinstance(duration, int | float) else None


def slowest_graphql_trace_id(result: CommandResult) -> str | None:
    if not result.jaeger_traces:
        return None
    trace_id = result.jaeger_traces[0].get("trace_id")
    return trace_id if isinstance(trace_id, str) else None


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
