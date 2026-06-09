"""Shared per-run state for command workflows."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Generator, Iterable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TypeVar, cast

import src_py_lib as src

from . import types as shared_types

log = logging.getLogger(__name__)
Input = TypeVar("Input")
Output = TypeVar("Output")


@dataclass(frozen=True)
class CommandData:
    """Instance data a command loaded and later commands may reuse."""

    auth_providers: list[shared_types.AuthProvider] | None = None
    saml_group_users: list[shared_types.SamlGroupUser] | None = None


@contextmanager
def thread_pool(
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
) -> Generator[ThreadPoolExecutor]:
    """Yield the run-owned worker pool or create a temporary pool."""
    if worker_pool is not None:
        yield worker_pool
        return

    with ThreadPoolExecutor(
        max_workers=parallelism, thread_name_prefix="sg-worker"
    ) as created_pool:
        yield created_pool


def parallel_map(
    function: Callable[[Input], Output],
    items: Iterable[Input],
    *,
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
    progress_label: str | None = None,
) -> list[Output]:
    """Map `function` over `items` using the run worker pool, preserving order."""
    values = list(items)
    total_count = len(values)
    if total_count == 0:
        return []

    started = time.perf_counter()
    if parallelism <= 1:
        results: list[Output] = []
        for completed, value in enumerate(values, start=1):
            results.append(function(value))
            if progress_label is not None and _parallel_progress_due(completed, total_count):
                _log_parallel_progress(progress_label, completed, total_count, started)
        return results

    results_by_index: dict[int, Output] = {}
    pending_futures: dict[Future[Output], int] = {}
    next_index = 0
    completed = 0
    max_pending = max(1, parallelism * 2)

    def submit_next(executor: ThreadPoolExecutor) -> None:
        nonlocal next_index
        while next_index < total_count and len(pending_futures) < max_pending:
            value = values[next_index]
            future = cast(
                Future[Output],
                src.submit_with_log_context(executor, function, value),
            )
            pending_futures[future] = next_index
            next_index += 1

    with thread_pool(parallelism, worker_pool) as executor:
        submit_next(executor)
        while pending_futures:
            done_futures, _ = wait(pending_futures, return_when=FIRST_COMPLETED)
            for future in done_futures:
                index = pending_futures.pop(future)
                results_by_index[index] = future.result()
                completed += 1
                if progress_label is not None and _parallel_progress_due(
                    completed,
                    total_count,
                ):
                    _log_parallel_progress(progress_label, completed, total_count, started)
            submit_next(executor)
    return [results_by_index[index] for index in range(total_count)]


def _parallel_progress_due(completed: int, total_count: int) -> bool:
    return completed == total_count or completed % max(1, total_count // 10) == 0


def _log_parallel_progress(
    progress_label: str,
    completed: int,
    total_count: int,
    started: float,
) -> None:
    elapsed = time.perf_counter() - started
    rate = completed / elapsed if elapsed > 0 else 0.0
    remaining = max(total_count - completed, 0)
    eta_seconds = remaining / rate if rate > 0 else 0.0
    log.info(
        "%s: %d / %d complete (%.0f%%) in %.0fs (%.0f/sec, ETA %.0fs).",
        progress_label,
        completed,
        total_count,
        100.0 * completed / total_count,
        elapsed,
        rate,
        eta_seconds,
    )
