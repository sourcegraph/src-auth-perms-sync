"""Endpoint-scoped artifact paths, resolved once per run into `RunPaths`."""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

ARTIFACTS_DIR_NAME = "src-auth-perms-sync-runs"
DEFAULT_MAPS_FILE_NAME = "maps.yaml"
LOG_FILE_NAME = "log.json"
RUNS_DIR_NAME = "runs"
CODE_HOSTS_FILE_NAME = "code-hosts.yaml"
AUTH_PROVIDERS_FILE_NAME = "auth-providers.yaml"


@dataclass(frozen=True)
class RunPaths:
    """Every filesystem location one run may read or write, resolved once.

    Built at the CLI/module edge by `resolve_run_paths()` and threaded
    explicitly through command code; nothing below the edge recomputes paths
    from cwd or global state. `write_files` is False under `--no-files`:
    path values stay valid for naming and messages, but nothing is written.
    """

    timestamp: str
    artifacts_dir: Path
    endpoint_directory: Path
    maps_path: Path
    code_hosts_path: Path
    auth_providers_path: Path
    run_directory: Path
    write_files: bool = True

    @property
    def log_path(self) -> Path:
        """The structured JSONL event log for this run."""
        return self.run_directory / LOG_FILE_NAME

    def artifact_path(self, state: str, *, family: str | None = None, suffix: str = "json") -> Path:
        """Return a run artifact path such as `before.json` or `<family>-diff.json`."""
        name = f"{family}-{state}" if family else state
        return self.run_directory / f"{safe_filename_part(name)}.{suffix}"

    def input_copy_path(self, input_name: str) -> Path:
        """Return the audit-copy path for an input file (e.g. the active maps YAML)."""
        return self.run_directory / safe_filename_part(input_name)


def resolve_run_paths(
    *,
    endpoint: str,
    command_artifact_name: str,
    artifacts_dir: Path | None = None,
    maps_path: Path | None = None,
    write_files: bool = True,
    current_directory: Path | None = None,
) -> RunPaths:
    """Resolve every path for one run; create the run directory exclusively.

    `artifacts_dir` is the directory containing endpoint subdirectories
    (default: `./src-auth-perms-sync-runs`). Paths are resolved to absolute
    once, so later working-directory changes cannot redirect writes. Run
    directories are created exclusively; a same-second collision gets a
    numeric suffix rather than sharing or overwriting an existing run.
    """
    base_directory = current_directory or Path.cwd()
    resolved_artifacts_dir = (
        artifacts_dir if artifacts_dir is not None else base_directory / ARTIFACTS_DIR_NAME
    )
    if not resolved_artifacts_dir.is_absolute():
        resolved_artifacts_dir = base_directory / resolved_artifacts_dir
    resolved_artifacts_dir = resolved_artifacts_dir.resolve()
    endpoint_directory = resolved_artifacts_dir / endpoint_directory_name(endpoint)

    resolved_maps_path = (
        maps_path if maps_path is not None else endpoint_directory / DEFAULT_MAPS_FILE_NAME
    )
    if not resolved_maps_path.is_absolute():
        resolved_maps_path = base_directory / resolved_maps_path
    resolved_maps_path = resolved_maps_path.resolve()

    timestamp = run_timestamp()
    run_directory = _exclusive_run_directory(
        endpoint_directory / RUNS_DIR_NAME,
        timestamp,
        command_artifact_name,
        create=write_files,
    )
    return RunPaths(
        timestamp=timestamp,
        artifacts_dir=resolved_artifacts_dir,
        endpoint_directory=endpoint_directory,
        maps_path=resolved_maps_path,
        code_hosts_path=endpoint_directory / CODE_HOSTS_FILE_NAME,
        auth_providers_path=endpoint_directory / AUTH_PROVIDERS_FILE_NAME,
        run_directory=run_directory,
        write_files=write_files,
    )


def run_timestamp() -> str:
    """Return a filesystem-friendly UTC timestamp."""
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d-%H-%M-%S")


def _exclusive_run_directory(
    runs_directory: Path,
    timestamp: str,
    command_artifact_name: str,
    *,
    create: bool,
) -> Path:
    """Create (or name) a unique run directory; never reuse an existing one."""
    base_name = safe_filename_part(f"{timestamp}-{command_artifact_name}")
    candidate = runs_directory / base_name
    if not create:
        return candidate
    for attempt in range(2, 1000):
        try:
            candidate.mkdir(parents=True, exist_ok=False)
            return candidate
        except FileExistsError:
            candidate = runs_directory / f"{base_name}-{attempt}"
    raise OSError(f"could not create a unique run directory under {runs_directory}")


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
