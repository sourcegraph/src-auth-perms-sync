"""Shared per-run state for command workflows."""

from __future__ import annotations

from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass

from . import types as shared_types


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
