"""Endpoint-scoped artifact path helpers."""

from __future__ import annotations

import datetime
import re
from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from urllib.parse import urlsplit

ARTIFACTS_DIR_NAME = "auth-perms-sync-runs"
LOG_FILE_NAME = "log.json"
RUNS_DIR_NAME = "runs"

_CURRENT_RUN_ARTIFACTS_DIRECTORY: ContextVar[Path | None] = ContextVar(
    "current_run_artifacts_directory",
    default=None,
)
_CURRENT_RUN_TIMESTAMP: ContextVar[str | None] = ContextVar(
    "current_run_timestamp",
    default=None,
)


def backup_timestamp() -> str:
    """Return a filesystem-friendly UTC timestamp."""
    run_timestamp = _CURRENT_RUN_TIMESTAMP.get()
    if run_timestamp is not None:
        return run_timestamp
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d-%H-%M-%S")


@contextmanager
def run_artifacts_context(run_directory: Path, timestamp: str) -> Generator[None]:
    """Make backup helpers write into the current CLI run directory."""
    directory_token = _CURRENT_RUN_ARTIFACTS_DIRECTORY.set(run_directory)
    timestamp_token = _CURRENT_RUN_TIMESTAMP.set(timestamp)
    try:
        yield
    finally:
        _CURRENT_RUN_TIMESTAMP.reset(timestamp_token)
        _CURRENT_RUN_ARTIFACTS_DIRECTORY.reset(directory_token)


def artifact_run_directory(timestamp: str, endpoint: str, command: str) -> Path:
    """Return the artifact directory for one command run."""
    run_directory = safe_filename_part(f"{timestamp}-{command}")
    return endpoint_artifacts_directory(endpoint) / RUNS_DIR_NAME / run_directory


def backup_path(
    source_name: str,
    timestamp: str,
    endpoint: str,
    command: str,
    state: str | None = None,
    *,
    suffix: str = "json",
) -> Path:
    """Return an artifact path under one directory per endpoint run."""
    backup_directory = _CURRENT_RUN_ARTIFACTS_DIRECTORY.get() or artifact_run_directory(
        timestamp,
        endpoint,
        command,
    )
    if state is None:
        return backup_directory / safe_filename_part(source_name)
    return backup_directory / f"{safe_filename_part(state)}.{suffix}"


def run_log_path(run_directory: Path) -> Path:
    """Return the structured log path for a run artifact directory."""
    return run_directory / LOG_FILE_NAME


def endpoint_artifacts_directory(endpoint: str, current_directory: Path | None = None) -> Path:
    """Return this endpoint's artifact directory under the current working directory."""
    base_directory = current_directory or Path.cwd()
    return base_directory / ARTIFACTS_DIR_NAME / endpoint_directory_name(endpoint)


def endpoint_directory_name(endpoint: str) -> str:
    """Return a filesystem-friendly directory name for a Sourcegraph endpoint."""
    parsed_endpoint = urlsplit(endpoint)
    hostname = parsed_endpoint.hostname
    port = _fallback_endpoint_port(parsed_endpoint.netloc)
    if not hostname:
        endpoint_without_scheme = endpoint.split("://", 1)[-1]
        hostname_and_port = endpoint_without_scheme.split("/", 1)[0]
        hostname = hostname_and_port.split(":", 1)[0]
        port = _fallback_endpoint_port(hostname_and_port)
    directory_name = hostname.lower()
    if port is not None:
        directory_name = f"{directory_name}-{port}"
    return safe_filename_part(directory_name)


def endpoint_artifact_path(endpoint: str, path: Path) -> Path:
    """Resolve a user-facing artifact path within the endpoint directory by default."""
    if path.is_absolute():
        return path
    return endpoint_artifacts_directory(endpoint) / path


def _fallback_endpoint_port(hostname_and_port: str) -> int | None:
    """Parse a port from an endpoint netloc that urlsplit could not fully parse."""
    if ":" not in hostname_and_port:
        return None
    raw_port = hostname_and_port.rsplit(":", 1)[1]
    if not raw_port.isdecimal():
        return None
    return int(raw_port)


def safe_filename_part(value: str) -> str:
    """Return a non-empty string safe for backup filenames."""
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._-") or "unknown"
