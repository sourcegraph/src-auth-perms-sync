"""Central structured logging for small CLIs and scripts.

Use `configure_logging()` once near process startup. Other modules should use
`logging.getLogger(__name__)` for human-readable operator messages and
`event()` / `log()` for structured JSONL events.
"""

from __future__ import annotations

import ast
import contextlib
import contextvars
import datetime as _datetime
import json
import logging
import os
import secrets
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Generator, Iterable, Mapping
from concurrent.futures import Executor, Future
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Self, cast

if sys.platform != "win32":
    import resource

from pydantic import model_validator

from src_py_lib.utils.config import Config, config_field, config_snapshot

RUN: Final[str] = secrets.token_hex(4)
DEFAULT_LOGS_DIR: Final[Path] = Path("logs")
DEFAULT_RETAIN_FILES: Final[int] = 50
DEFAULT_LOG_FILE_LEVEL: Final[str] = "debug"
SRC_LOG_LEVEL: Final[str] = "SRC_LOG_LEVEL"
SRC_LOG_VERBOSE: Final[str] = "SRC_LOG_VERBOSE"
SRC_LOG_QUIET: Final[str] = "SRC_LOG_QUIET"
SRC_LOG_SILENT: Final[str] = "SRC_LOG_SILENT"
TRACE_SPAN_BYTES: Final[int] = 4
MEBIBYTE: Final[int] = 1024 * 1024
SECRET_FIELD_FRAGMENTS: Final[tuple[str, ...]] = (
    "api_key",
    "authorization",
    "cookie",
    "password",
    "secret",
    "token",
)
LOG_FIELD_ORDER: Final[tuple[str, ...]] = (
    "ts",
    "command",
    "level",
    "run",
    "trace",
    "span",
    "parent_span",
    "logger",
    "event",
    "phase",
    "stage",
    "message",
)

_STRUCTURED_EVENT_ATTR: Final[str] = "_src_py_lib_structured_event"
_STRUCTURED_FIELDS_ATTR: Final[str] = "_src_py_lib_structured_fields"
_HTTPCORE_RESPONSE_HEADERS_PREFIX: Final[str] = "receive_response_headers.complete return_value="
_HTTPX_REQUEST_PREFIX: Final[str] = "HTTP Request: "
_HTTP_DEPENDENCY_LOGGER_PREFIXES: Final[tuple[str, ...]] = ("httpx", "httpcore")
_CONTEXT: contextvars.ContextVar[dict[str, Any]] = contextvars.ContextVar("src_py_lib_log_context")


@dataclass(frozen=True)
class LoggingSettings:
    """Logging destinations and levels."""

    logger_name: str = ""
    terminal_level: str = "info"
    log_file_level: str | None = None
    log_file: Path | None = None
    logs_dir: Path | None = DEFAULT_LOGS_DIR
    run: str = RUN
    retain_log_files: int = DEFAULT_RETAIN_FILES
    suppress_http_dependency_logs: bool = True
    resource_sample_interval_seconds: float | None = None


class LoggingConfig(Config):
    """Config fields for logging-related CLI and environment options."""

    src_log_level: str | None = config_field(
        default="INFO",
        env_var=SRC_LOG_LEVEL,
        cli_flag="--src-log-level",
        metavar="LEVEL",
        help="Log level (default: INFO)",
    )
    verbose: bool = config_field(
        default=False,
        env_var=SRC_LOG_VERBOSE,
        cli_flag="--verbose",
        cli_aliases=("-v",),
        cli_action="store_true",
        help="Alias for --src-log-level DEBUG",
    )
    quiet: bool = config_field(
        default=False,
        env_var=SRC_LOG_QUIET,
        cli_flag="--quiet",
        cli_aliases=("-q",),
        cli_action="store_true",
        help="Alias for --src-log-level WARNING",
    )
    silent: bool = config_field(
        default=False,
        env_var=SRC_LOG_SILENT,
        cli_flag="--silent",
        cli_aliases=("-s",),
        cli_action="store_true",
        help="Alias for --src-log-level ERROR",
    )

    @model_validator(mode="after")
    def validate_log_level_alias(self) -> Self:
        """Require at most one alias for the terminal/log-file level."""
        if sum((self.verbose, self.quiet, self.silent)) > 1:
            raise ValueError("choose only one of --verbose/-v, --quiet/-q, or --silent/-s")
        return self


def resolve_log_level_name(
    config: object | None = None,
    *,
    log_level: str | None = None,
    verbose: bool | None = None,
    quiet: bool | None = None,
    silent: bool | None = None,
) -> str | None:
    """Resolve common CLI log-level alias to a level name.

    Alias flags intentionally only map to strings. Explicit log-level
    values are returned unchanged so `configure_logging()` owns parsing
    and fallback behavior.
    """
    resolved_verbose = verbose if verbose is not None else bool(getattr(config, "verbose", False))
    resolved_quiet = quiet if quiet is not None else bool(getattr(config, "quiet", False))
    resolved_silent = silent if silent is not None else bool(getattr(config, "silent", False))
    if resolved_verbose:
        return "DEBUG"
    if resolved_quiet:
        return "WARNING"
    if resolved_silent:
        return "ERROR"
    if log_level is not None:
        return log_level
    return _src_log_level_from_config(config)


def logging_settings_from_config(
    config: object | None = None,
    *,
    terminal_default: str = "INFO",
    log_file_default: str | None = DEFAULT_LOG_FILE_LEVEL,
    logger_name: str = "",
    log_file: Path | None = None,
    logs_dir: Path | None = DEFAULT_LOGS_DIR,
    run: str = RUN,
    retain_log_files: int = DEFAULT_RETAIN_FILES,
    suppress_http_dependency_logs: bool = True,
    resource_sample_interval_seconds: float | None = None,
) -> LoggingSettings:
    """Return `LoggingSettings` using common CLI log-level alias."""
    explicit_level = resolve_log_level_name(config)
    return LoggingSettings(
        logger_name=logger_name,
        terminal_level=explicit_level or terminal_default,
        log_file_level=explicit_level or log_file_default,
        log_file=log_file,
        logs_dir=logs_dir,
        run=run,
        retain_log_files=retain_log_files,
        suppress_http_dependency_logs=suppress_http_dependency_logs,
        resource_sample_interval_seconds=resource_sample_interval_seconds,
    )


@dataclass(frozen=True)
class _SpanContext:
    trace: str
    span: str
    parent_span: str | None = None


_SPAN_CONTEXT: contextvars.ContextVar[_SpanContext | None] = contextvars.ContextVar(
    "src_py_lib_span_context", default=None
)

_HTTP_METRICS_LOCK: Final[threading.Lock] = threading.Lock()
_HTTP_METRICS: dict[str, int] = {
    "http_request_attempt_count": 0,
    "http_request_bytes_total": 0,
    "http_response_bytes_total": 0,
    "http_retry_count": 0,
    "http_2xx_count": 0,
    "http_3xx_count": 0,
    "http_4xx_count": 0,
    "http_429_count": 0,
    "http_5xx_count": 0,
    "http_transport_error_count": 0,
}


@dataclass
class ResourceSampler:
    """Emit optional process resource samples and summarize usage at run end."""

    interval_seconds: float
    _stop: threading.Event = field(init=False, default_factory=threading.Event)
    _thread: threading.Thread | None = field(init=False, default=None)
    _started_at: float = field(init=False, default_factory=time.perf_counter)
    _last_sample_at: float = field(init=False, default_factory=time.perf_counter)
    _last_cpu_seconds: float = field(init=False, default=0.0)
    _start_usage: Any = field(init=False, default=None)
    _peak_rss_bytes: int = field(init=False, default=0)

    def __post_init__(self) -> None:
        if self.interval_seconds < 0:
            raise ValueError("resource_sample_interval_seconds must be >= 0")
        self._start_usage = _resource_usage()
        if self._start_usage is not None:
            self._last_cpu_seconds = _cpu_seconds(self._start_usage)

    def start(self) -> None:
        """Start periodic sampling, if enabled by a positive interval."""
        if self.interval_seconds <= 0:
            return
        context = contextvars.copy_context()
        self._thread = threading.Thread(
            target=context.run,
            args=(self._loop,),
            name="ResourceSampler",
            daemon=True,
        )
        self._thread.start()
        self.emit_sample()

    def emit_sample(self) -> None:
        """Emit one DEBUG `resource_sample` event."""
        log("debug", "resource_sample", **self._sample_fields())

    def stop_and_summary(self) -> dict[str, Any]:
        """Stop periodic sampling and return run-end resource fields."""
        if self.interval_seconds > 0:
            self.emit_sample()
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        usage = _resource_usage()
        summary: dict[str, Any] = {
            "cpu_count_logical": os.cpu_count() or 0,
            "num_threads": threading.active_count(),
        }
        file_descriptors = _num_file_descriptors()
        if file_descriptors is not None:
            summary["num_fds"] = file_descriptors
        rss_bytes = _rss_bytes(usage)
        if rss_bytes is not None:
            self._peak_rss_bytes = max(self._peak_rss_bytes, rss_bytes)
        if self._peak_rss_bytes:
            summary["peak_rss_mb"] = _bytes_to_mib(self._peak_rss_bytes)
        if usage is not None and self._start_usage is not None:
            summary["cpu_user_seconds"] = round(
                float(usage.ru_utime) - float(self._start_usage.ru_utime), 3
            )
            summary["cpu_system_seconds"] = round(
                float(usage.ru_stime) - float(self._start_usage.ru_stime), 3
            )
            summary["io_read_count"] = int(usage.ru_inblock) - int(self._start_usage.ru_inblock)
            summary["io_write_count"] = int(usage.ru_oublock) - int(self._start_usage.ru_oublock)
        return summary

    def _loop(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            self.emit_sample()

    def _sample_fields(self) -> dict[str, Any]:
        now = time.perf_counter()
        usage = _resource_usage()
        fields: dict[str, Any] = {
            "num_threads": threading.active_count(),
        }
        rss_bytes = _rss_bytes(usage)
        if rss_bytes is not None:
            self._peak_rss_bytes = max(self._peak_rss_bytes, rss_bytes)
            fields["rss_mb"] = _bytes_to_mib(rss_bytes)
        file_descriptors = _num_file_descriptors()
        if file_descriptors is not None:
            fields["num_fds"] = file_descriptors
        if usage is not None:
            cpu_seconds = _cpu_seconds(usage)
            elapsed = max(now - self._last_sample_at, 0.001)
            fields["process_cpu_percent"] = round(
                max(cpu_seconds - self._last_cpu_seconds, 0.0) / elapsed * 100.0,
                1,
            )
            self._last_cpu_seconds = cpu_seconds
        self._last_sample_at = now
        return fields


class _DropStructuredEvents(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not hasattr(record, _STRUCTURED_EVENT_ATTR)


class _DropHTTPDependencyLogs(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not any(
            record.name == prefix or record.name.startswith(f"{prefix}.")
            for prefix in _HTTP_DEPENDENCY_LOGGER_PREFIXES
        )


class JSONLogFileHandler(logging.Handler):
    """Write every log record as one JSON object line."""

    def __init__(self, path: Path, *, run: str, level: int) -> None:
        super().__init__(level=level)
        self.path = path
        self._run = run
        self._lock = threading.Lock()
        self._file = path.open("w", encoding="utf-8", buffering=1)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            timestamp = _datetime.datetime.now(_datetime.UTC).isoformat(timespec="milliseconds")
            structured_event = getattr(record, _STRUCTURED_EVENT_ATTR, None)
            if isinstance(structured_event, str):
                fields = getattr(record, _STRUCTURED_FIELDS_ATTR, {})
                structured_fields: dict[str, Any] = (
                    dict(cast(Mapping[str, Any], fields)) if isinstance(fields, Mapping) else {}
                )
                payload = {
                    "ts": timestamp,
                    "run": self._run,
                    "level": record.levelname,
                    "event": structured_event,
                    **structured_fields,
                }
            else:
                message, log_fields = _structured_log_fields(record)
                payload = {
                    "ts": timestamp,
                    "run": self._run,
                    "level": record.levelname,
                    "event": "log",
                    "logger": record.name,
                    "message": message,
                }
                payload.update(log_fields)
                payload.update(_current_log_fields(payload))
                if record.exc_info:
                    payload["exc_info"] = self.format(record)
            with self._lock:
                self._file.write(json.dumps(_ordered_payload(payload), default=str) + "\n")
        except Exception:
            self.handleError(record)

    def close(self) -> None:
        with contextlib.suppress(Exception), self._lock:
            self._file.flush()
            self._file.close()
        super().close()


def configure_logging(config: LoggingSettings | None = None) -> Path | None:
    """Configure terminal logging and optional JSON log-file logging.

    Returns the JSON log-file path when file logging is enabled.
    """
    config = config or LoggingSettings()
    reset_observability_metrics()
    terminal_level = _log_level(config.terminal_level)
    log_file_level = _log_file_level(config.log_file_level)
    log_file = config.log_file
    if log_file is None and config.logs_dir is not None:
        log_file = default_log_file(config.logs_dir, run=config.run)
    root_or_package_logger = logging.getLogger(config.logger_name)
    root_or_package_logger.handlers.clear()
    root_or_package_logger.setLevel(
        min(
            terminal_level,
            log_file_level if log_file else terminal_level,
        )
    )
    root_or_package_logger.propagate = False

    terminal_handler = logging.StreamHandler()
    terminal_handler.setLevel(terminal_level)
    terminal_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    terminal_handler.addFilter(_DropStructuredEvents())
    if config.suppress_http_dependency_logs and config.logger_name == "":
        terminal_handler.addFilter(_DropHTTPDependencyLogs())
    root_or_package_logger.addHandler(terminal_handler)

    if log_file is None:
        return None

    log_file.parent.mkdir(parents=True, exist_ok=True)
    _prune_old_log_files(log_file.parent, config.retain_log_files)
    log_file_handler = JSONLogFileHandler(
        log_file,
        run=config.run,
        level=log_file_level,
    )
    if config.suppress_http_dependency_logs and config.logger_name == "":
        log_file_handler.addFilter(_DropHTTPDependencyLogs())
    root_or_package_logger.addHandler(log_file_handler)
    root_or_package_logger.info("Writing log events to %s.", log_file)
    return log_file


def reset_observability_metrics() -> None:
    """Reset process-wide HTTP counters used by `logging_context()` run summaries."""
    with _HTTP_METRICS_LOCK:
        for metric_name in _HTTP_METRICS:
            _HTTP_METRICS[metric_name] = 0


def record_http_attempt(
    *,
    request_bytes: int,
    response_bytes: int = 0,
    status_code: int | None = None,
    transport_error: bool = False,
) -> None:
    """Record one HTTP attempt for the current run summary."""
    with _HTTP_METRICS_LOCK:
        _HTTP_METRICS["http_request_attempt_count"] += 1
        _HTTP_METRICS["http_request_bytes_total"] += request_bytes
        _HTTP_METRICS["http_response_bytes_total"] += response_bytes
        if transport_error:
            _HTTP_METRICS["http_transport_error_count"] += 1
        if status_code is None:
            return
        status_group = 5 if status_code >= 500 else status_code // 100
        metric_name = {
            2: "http_2xx_count",
            3: "http_3xx_count",
            4: "http_4xx_count",
            5: "http_5xx_count",
        }.get(status_group)
        if metric_name is not None:
            _HTTP_METRICS[metric_name] += 1
        if status_code == 429:
            _HTTP_METRICS["http_429_count"] += 1


def record_http_retry() -> None:
    """Record that an HTTP attempt will be retried."""
    with _HTTP_METRICS_LOCK:
        _HTTP_METRICS["http_retry_count"] += 1


def observability_summary() -> dict[str, Any]:
    """Return process-wide counters accumulated since logging was configured."""
    with _HTTP_METRICS_LOCK:
        return dict(_HTTP_METRICS)


@contextlib.contextmanager
def logging_context(
    name: str,
    config: object | None = None,
    *,
    git_cwd: Path | str | None = None,
    logging_config: LoggingSettings | None = None,
    run_fields: Mapping[str, Any] | None = None,
    run_summary: Callable[[], Mapping[str, Any]] | None = None,
) -> Generator[Path | None]:
    """Configure logging, install command context, and emit startup metadata."""
    resolved_logging_config = logging_config or LoggingSettings(
        log_file_level=_src_log_level_from_config(config)
    )
    log_file = configure_logging(resolved_logging_config)
    sampler = _resource_sampler(resolved_logging_config)
    started = time.perf_counter()
    error: BaseException | None = None
    with log_context(command=name):
        if sampler is not None:
            sampler.start()
        start_fields = {"phase": "start", **dict(run_fields or {})}
        info("run", logger_name=resolved_logging_config.logger_name, **start_fields)
        try:
            startup_event(
                command=name,
                config=config,
                log_file=log_file,
                git_cwd=_git_cwd_path(git_cwd),
                logger_name=resolved_logging_config.logger_name,
            )
            yield log_file
        except BaseException as exception:
            error = exception
            raise
        finally:
            error_type = _run_error_type(error)
            summary: dict[str, Any] = {}
            if sampler is not None:
                summary.update(sampler.stop_and_summary())
            summary.update(observability_summary())
            summary["exit_code"] = _run_exit_code(error)
            if run_summary is not None:
                summary.update(dict(run_summary()))
            end_fields = {
                "phase": "end",
                "duration_ms": round((time.perf_counter() - started) * 1000.0),
                "status": "error" if error_type else "ok",
                "error_type": error_type,
                **dict(run_fields or {}),
                **summary,
            }
            log(
                "error" if error_type else "info",
                "run",
                logger_name=resolved_logging_config.logger_name,
                **end_fields,
            )


def default_log_file(logs_dir: Path = DEFAULT_LOGS_DIR, *, run: str = RUN) -> Path:
    """Return a timestamped log-file path under `logs_dir`."""
    timestamp = _datetime.datetime.now(_datetime.UTC).strftime("%Y-%m-%d-%H-%M-%S-%z")
    timestamp = timestamp.replace("+", "", 1)
    return logs_dir / f"{timestamp}-{run}.json"


def log(level: str, key: str, *, logger_name: str = "", **fields: Any) -> None:
    """Log one structured event through the configured logger."""
    numeric_level = _log_level(level)
    logger = logging.getLogger(logger_name)
    if not logger.isEnabledFor(numeric_level):
        return
    logger.log(
        numeric_level,
        "event=%s",
        key,
        extra={
            _STRUCTURED_EVENT_ATTR: key,
            _STRUCTURED_FIELDS_ATTR: {**_current_log_fields(), **fields},
        },
    )


def debug(key: str, *, logger_name: str = "", **fields: Any) -> None:
    """Log a DEBUG structured event."""
    log("debug", key, logger_name=logger_name, **fields)


def info(key: str, *, logger_name: str = "", **fields: Any) -> None:
    """Log an INFO structured event."""
    log("info", key, logger_name=logger_name, **fields)


def warning(key: str, *, logger_name: str = "", **fields: Any) -> None:
    """Log a WARNING structured event."""
    log("warning", key, logger_name=logger_name, **fields)


def error(key: str, *, logger_name: str = "", **fields: Any) -> None:
    """Log an ERROR structured event."""
    log("error", key, logger_name=logger_name, **fields)


def critical(key: str, *, logger_name: str = "", **fields: Any) -> None:
    """Log a CRITICAL structured event."""
    log("critical", key, logger_name=logger_name, **fields)


@contextlib.contextmanager
def log_context(**fields: Any) -> Generator[None]:
    """Add inherited structured fields for nested `log()` calls."""
    reset_token = _CONTEXT.set({**_CONTEXT.get({}), **fields})
    try:
        yield
    finally:
        _CONTEXT.reset(reset_token)


@contextlib.contextmanager
def stage(name: str, **fields: Any) -> Generator[None]:
    """Add a workflow stage field for nested logs and structured events."""
    with log_context(stage=name, **fields):
        yield


@contextlib.contextmanager
def event(
    key: str,
    *,
    level: str = "info",
    start_level: str | None = None,
    omit_success_status: bool = False,
    logger_name: str = "",
    **fields: Any,
) -> Generator[dict[str, Any]]:
    """Emit start/end structured events around a block of work."""
    parent = _SPAN_CONTEXT.get()
    span = _SpanContext(
        trace=parent.trace if parent else secrets.token_hex(TRACE_SPAN_BYTES),
        span=secrets.token_hex(TRACE_SPAN_BYTES),
        parent_span=parent.span if parent else None,
    )
    reset_token = _SPAN_CONTEXT.set(span)
    try:
        log(start_level or level, key, logger_name=logger_name, phase="start", **fields)
        started = time.perf_counter()
        extra: dict[str, Any] = {}
        error: BaseException | None = None
        try:
            yield extra
        except BaseException as exception:
            error = exception
            raise
        finally:
            end_fields = {
                **fields,
                **extra,
                "phase": "end",
                "duration_ms": round((time.perf_counter() - started) * 1000.0),
            }
            if error:
                end_fields["status"] = "error"
                end_fields["error_type"] = type(error).__name__
            elif not omit_success_status:
                end_fields["status"] = "ok"
                end_fields["error_type"] = None
            log(
                "error" if error else level,
                key,
                logger_name=logger_name,
                **end_fields,
            )
    finally:
        _SPAN_CONTEXT.reset(reset_token)


def submit_with_log_context(
    executor: Executor,
    function: Callable[..., Any],
    *args: Any,
    **kwargs: Any,
) -> Future[Any]:
    """Submit work to an executor with current logging ContextVars propagated."""
    context = contextvars.copy_context()
    return executor.submit(context.run, function, *args, **kwargs)


def sanitized_config_snapshot(config: object) -> dict[str, Any]:
    """Return a log-safe snapshot of dataclass/object/dict config values."""
    if isinstance(config, Mapping):
        items: Iterable[tuple[object, object]] = cast(Mapping[object, object], config).items()
    else:
        object_items: list[tuple[object, object]] = []
        for name in dir(config):
            if name.startswith("_"):
                continue
            object_items.append((name, getattr(config, name)))
        items = object_items
    snapshot: dict[str, Any] = {}
    for key, value in items:
        if callable(value):
            continue
        key_text = str(key)
        if any(fragment in key_text.lower() for fragment in SECRET_FIELD_FRAGMENTS):
            snapshot[key_text] = _secret_state(value)
        elif isinstance(value, Path):
            snapshot[key_text] = str(value)
        elif isinstance(value, str | int | float | bool) or value is None:
            snapshot[key_text] = value
        else:
            snapshot[key_text] = str(value)
    return snapshot


def _current_log_fields(protected: Mapping[str, Any] | None = None) -> dict[str, Any]:
    protected_keys = set(protected or {})
    fields = {key: value for key, value in _CONTEXT.get({}).items() if key not in protected_keys}
    span = _SPAN_CONTEXT.get()
    if span is None:
        return fields
    if "parent_span" not in protected_keys and span.parent_span is not None:
        fields["parent_span"] = span.parent_span
    if "span" not in protected_keys:
        fields["span"] = span.span
    if "trace" not in protected_keys:
        fields["trace"] = span.trace
    return fields


def startup_event(
    *,
    command: str,
    config: object | None = None,
    log_file: Path | None = None,
    git_commit: str | None = None,
    git_cwd: Path | None = None,
    logger_name: str = "",
) -> None:
    """Emit standard startup metadata after logging is configured."""
    fields: dict[str, Any] = {
        "command": command,
        "log_file": str(log_file) if log_file else None,
    }
    commit = git_commit or git_short_hash(git_cwd)
    if commit:
        fields["git_commit"] = commit
    if config is not None:
        config_value = config_snapshot(config) if isinstance(config, Config) else config
        fields["config"] = sanitized_config_snapshot(config_value)
    info("startup", logger_name=logger_name, **fields)


def git_short_hash(cwd: Path | None = None) -> str | None:
    """Return the current git short hash, or None outside a git checkout."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except OSError:
        return None
    except subprocess.SubprocessError:
        return None
    commit = result.stdout.strip()
    return commit if result.returncode == 0 and commit else None


def _ordered_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    ordered: dict[str, Any] = {}
    for key in LOG_FIELD_ORDER:
        if key in payload:
            ordered[key] = payload[key]
    for key in sorted(key for key in payload if key not in ordered):
        ordered[key] = payload[key]
    return ordered


def _log_file_level(configured_level: str | None) -> int:
    if configured_level is not None:
        return _log_level(configured_level)
    env_level = os.environ.get(SRC_LOG_LEVEL)
    if env_level:
        return _log_level(env_level)
    return _log_level(DEFAULT_LOG_FILE_LEVEL)


def _src_log_level_from_config(config: object | None) -> str | None:
    value = getattr(config, "src_log_level", None)
    return value if isinstance(value, str) else None


def _git_cwd_path(value: Path | str | None) -> Path | None:
    if value is None:
        return None
    path = Path(value)
    return path.parent if path.is_file() else path


def _log_level(value: int | str) -> int:
    if isinstance(value, int):
        return value
    normalized = value.strip().upper()
    if not normalized:
        return logging.INFO
    if normalized.isdecimal():
        return int(normalized)
    levels = logging.getLevelNamesMapping()
    level = levels.get(normalized)
    if level is None:
        return logging.INFO
    return level


def _structured_log_fields(record: logging.LogRecord) -> tuple[str, dict[str, Any]]:
    message = record.getMessage()
    fields: dict[str, Any] = (
        {"level": "DEBUG"}
        if record.name == "httpx" and message.startswith(_HTTPX_REQUEST_PREFIX)
        else {}
    )
    if not message.startswith(_HTTPCORE_RESPONSE_HEADERS_PREFIX):
        return message, fields
    try:
        literal_value = cast(
            object,
            ast.literal_eval(message.removeprefix(_HTTPCORE_RESPONSE_HEADERS_PREFIX)),
        )
    except (SyntaxError, ValueError):
        return message, fields
    if not isinstance(literal_value, tuple):
        return message, fields

    return_value = cast(tuple[object, ...], literal_value)
    if len(return_value) != 4:
        return message, fields
    http_version, status_code, reason_phrase, raw_headers = return_value
    headers = _http_headers(raw_headers)
    if not headers:
        return message, fields

    fields["headers"] = headers
    decoded_version = _decode_http_bytes(http_version)
    if decoded_version is not None:
        fields["http_version"] = decoded_version
    if isinstance(status_code, int):
        fields["status_code"] = status_code
    decoded_reason = _decode_http_bytes(reason_phrase)
    if decoded_reason is not None:
        fields["reason_phrase"] = decoded_reason
    return "receive_response_headers.complete", fields


def _http_headers(raw_headers: object) -> dict[str, str | list[str]]:
    if not isinstance(raw_headers, list | tuple):
        return {}
    headers: dict[str, str | list[str]] = {}
    for item in cast(Iterable[object], raw_headers):
        if not isinstance(item, tuple):
            continue
        header = cast(tuple[object, ...], item)
        if len(header) != 2:
            continue
        raw_name, raw_value = header
        name = _decode_http_bytes(raw_name)
        value = _decode_http_bytes(raw_value)
        if name is None or value is None:
            continue
        key = name.lower()
        existing = headers.get(key)
        if existing is None:
            headers[key] = value
        elif isinstance(existing, list):
            existing.append(value)
        else:
            headers[key] = [existing, value]
    return {key: headers[key] for key in sorted(headers)}


def _decode_http_bytes(value: object) -> str | None:
    if isinstance(value, bytes):
        return value.decode("latin-1", errors="replace")
    if isinstance(value, str):
        return value
    return None


def _secret_state(value: object) -> str:
    if value is None or value == "":
        return "missing"
    return "reference" if isinstance(value, str) and value.startswith("op://") else "provided"


def _resource_sampler(config: LoggingSettings) -> ResourceSampler | None:
    interval_seconds = config.resource_sample_interval_seconds
    return ResourceSampler(interval_seconds) if interval_seconds is not None else None


def _run_error_type(exception: BaseException | None) -> str | None:
    if exception is None:
        return None
    if isinstance(exception, SystemExit) and exception.code in (None, 0):
        return None
    return type(exception).__name__


def _run_exit_code(exception: BaseException | None) -> int:
    if exception is None:
        return 0
    if isinstance(exception, SystemExit):
        return exception.code if isinstance(exception.code, int) else 1
    return 1


def _resource_usage() -> Any | None:
    if sys.platform == "win32":
        return None
    return resource.getrusage(resource.RUSAGE_SELF)


def _cpu_seconds(usage: Any) -> float:
    return float(usage.ru_utime) + float(usage.ru_stime)


def _rss_bytes(usage: Any | None) -> int | None:
    current = _linux_current_rss_bytes()
    if current is not None:
        return current
    if usage is None:
        return None
    # Linux reports ru_maxrss in KiB; macOS reports bytes.
    max_rss = int(usage.ru_maxrss)
    return max_rss if sys.platform == "darwin" else max_rss * 1024


def _linux_current_rss_bytes() -> int | None:
    statm = Path("/proc/self/statm")
    if not statm.exists():
        return None
    try:
        fields = statm.read_text(encoding="utf-8").split()
        if len(fields) < 2:
            return None
        return int(fields[1]) * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError):
        return None


def _num_file_descriptors() -> int | None:
    for directory in (Path("/proc/self/fd"), Path("/dev/fd")):
        if not directory.exists():
            continue
        try:
            return len(list(directory.iterdir()))
        except OSError:
            continue
    return None


def _bytes_to_mib(byte_count: int) -> float:
    return round(byte_count / MEBIBYTE, 2)


def _prune_old_log_files(logs_dir: Path, retain_files: int) -> None:
    if retain_files <= 0 or not logs_dir.exists():
        return
    log_files = sorted(
        [*logs_dir.glob("????-??-??-??-??-??-*.json"), *logs_dir.glob("events-*.json")],
        key=lambda path: path.stat().st_mtime,
    )
    for old_file in log_files[:-retain_files]:
        with contextlib.suppress(OSError):
            old_file.unlink()
