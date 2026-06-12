"""Shared per-run state for command workflows."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Generator, Iterable, Sized
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Generic, TypeVar, cast

import src_py_lib as src

from . import types as shared_types

log = logging.getLogger(__name__)
InputValue = TypeVar("InputValue")
OutputValue = TypeVar("OutputValue")


@dataclass(frozen=True)
class CommandData:
    """Instance data a command loaded and later commands or callers may reuse.

    `auth_provider_views` and `code_host_views` carry the same dicts the get
    command writes to `auth-providers.yaml` and `code-hosts.yaml`, so module
    callers receive discovery data without re-parsing files.

    `saml_group_users` carries the complete user population (full set
    modes); a subsequent org sync reuses it for a full sync. Additive set
    modes instead carry their selected user subset in
    `scoped_saml_group_users`; a subsequent org sync then runs scoped to
    exactly those users (per-user additions and removals, nobody else
    touched) without streaming all users again.
    """

    auth_providers: list[shared_types.AuthProvider] | None = None
    saml_group_users: list[shared_types.SamlGroupUser] | None = None
    scoped_saml_group_users: list[shared_types.ScopedSamlGroupUser] | None = None
    auth_provider_views: list[dict[str, Any]] | None = None
    code_host_views: list[dict[str, Any]] | None = None
    maps_created: bool = False


@dataclass(frozen=True)
class ParallelResult(Generic[InputValue, OutputValue]):
    """One completed parallel item, carrying either a value or an exception."""

    item: InputValue
    value: OutputValue | None = None
    exception: Exception | None = None


@dataclass(frozen=True)
class ParallelSummary:
    """Submission counts from a bounded parallel run."""

    submitted_count: int
    unsubmitted_count: int


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
    function: Callable[[InputValue], OutputValue],
    items: Iterable[InputValue],
    *,
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
    progress_label: str | None = None,
) -> list[OutputValue]:
    """Map `function` over `items` using the run worker pool, preserving order."""
    values = list(items)
    total_count = len(values)
    if total_count == 0:
        return []

    started = time.perf_counter()
    completed = 0
    results_by_index: dict[int, OutputValue] = {}

    def run_indexed(indexed_value: tuple[int, InputValue]) -> tuple[int, OutputValue]:
        index, value = indexed_value
        return index, function(value)

    def record_result(
        result: ParallelResult[tuple[int, InputValue], tuple[int, OutputValue]],
    ) -> None:
        nonlocal completed
        if result.exception is not None:
            raise result.exception
        if result.value is None:
            raise RuntimeError("parallel map item returned no result")
        index, value = result.value
        results_by_index[index] = value
        completed += 1
        if progress_label is not None and parallel_progress_due(completed, total_count):
            log_parallel_progress(progress_label, completed, total_count, started)

    parallel_process(
        run_indexed,
        list(enumerate(values)),
        parallelism=parallelism,
        worker_pool=worker_pool,
        handle_result=record_result,
    )
    return [results_by_index[index] for index in range(total_count)]


def parallel_process(
    function: Callable[[InputValue], OutputValue],
    items: Iterable[InputValue],
    *,
    parallelism: int,
    worker_pool: ThreadPoolExecutor | None = None,
    handle_result: Callable[[ParallelResult[InputValue, OutputValue]], None],
    should_stop: Callable[[], bool] | None = None,
    max_pending: int | None = None,
) -> ParallelSummary:
    """Process items in parallel, letting callers handle each success or failure.

    Unlike `parallel_map`, this does not raise the first worker exception by
    default. The caller receives every completed item and can decide how to
    count, log, or stop after it. Work is bounded to avoid queueing thousands
    of futures at once.
    """
    known_total_count = len(items) if isinstance(items, Sized) else None
    if known_total_count == 0:
        return ParallelSummary(submitted_count=0, unsubmitted_count=0)

    item_iterator = iter(items)

    if parallelism <= 1:
        return _process_sequentially(
            function,
            item_iterator,
            known_total_count=known_total_count,
            handle_result=handle_result,
            should_stop=should_stop,
        )

    submitted_count = 0
    input_exhausted = False
    stop_submissions = False
    pending_futures: dict[Future[OutputValue], InputValue] = {}
    pending_limit = max_pending or max(1, parallelism * 2)

    def stop_requested() -> bool:
        return bool(stop_submissions or (should_stop is not None and should_stop()))

    def cancel_pending() -> None:
        for pending_future in pending_futures:
            if not pending_future.done():
                pending_future.cancel()

    def submit_next(executor: ThreadPoolExecutor) -> None:
        nonlocal input_exhausted, submitted_count, stop_submissions
        while not input_exhausted and len(pending_futures) < pending_limit and not stop_requested():
            try:
                value = next(item_iterator)
            except StopIteration:
                input_exhausted = True
                return
            future = cast(
                Future[OutputValue],
                src.submit_with_log_context(executor, function, value),
            )
            pending_futures[future] = value
            submitted_count += 1
        if stop_requested():
            stop_submissions = True
            cancel_pending()

    with thread_pool(parallelism, worker_pool) as executor:
        try:
            submit_next(executor)
            while pending_futures:
                done_futures, _ = wait(pending_futures, return_when=FIRST_COMPLETED)
                for future in done_futures:
                    value = pending_futures.pop(future)
                    try:
                        result = ParallelResult[InputValue, OutputValue](
                            item=value,
                            value=future.result(),
                        )
                    except Exception as exception:
                        result = ParallelResult[InputValue, OutputValue](
                            item=value,
                            exception=exception,
                        )
                    handle_result(result)
                    if should_stop is not None and should_stop():
                        stop_submissions = True
                        cancel_pending()
                submit_next(executor)
        except BaseException:
            cancel_pending()
            raise
    return ParallelSummary(
        submitted_count=submitted_count,
        unsubmitted_count=_unsubmitted_count(known_total_count, submitted_count),
    )


def _process_sequentially(
    function: Callable[[InputValue], OutputValue],
    values: Iterable[InputValue],
    *,
    known_total_count: int | None,
    handle_result: Callable[[ParallelResult[InputValue, OutputValue]], None],
    should_stop: Callable[[], bool] | None,
) -> ParallelSummary:
    submitted_count = 0
    for value in values:
        if should_stop is not None and should_stop():
            break
        submitted_count += 1
        try:
            result = ParallelResult[InputValue, OutputValue](
                item=value,
                value=function(value),
            )
        except Exception as exception:
            result = ParallelResult[InputValue, OutputValue](
                item=value,
                exception=exception,
            )
        handle_result(result)
    return ParallelSummary(
        submitted_count=submitted_count,
        unsubmitted_count=_unsubmitted_count(known_total_count, submitted_count),
    )


def _unsubmitted_count(known_total_count: int | None, submitted_count: int) -> int:
    if known_total_count is None:
        return 0
    return max(known_total_count - submitted_count, 0)


def parallel_progress_due(completed: int, total_count: int) -> bool:
    """Return whether a bounded parallel run should log progress now."""

    return completed == total_count or completed % max(1, total_count // 10) == 0


def log_parallel_progress(
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
