"""Importable API for src-auth-perms-sync.

Module-mode commands never touch stdlib logging handlers; configure your own
`logging` handlers and levels (e.g. on the `src_auth_perms_sync` logger) to
see progress messages. Pass an `EventSink` (re-exported from `src_py_lib`)
to receive structured wide events programmatically.
"""

from src_py_lib import (
    CallbackEventSink,
    CompositeEventSink,
    EventSink,
    InMemoryEventSink,
    JSONLEventSink,
    NullEventSink,
)

from .cli import CommandResult, Config, Get, GetResult, Restore, Set, SyncSamlOrgs
from .permissions.types import MappingRule
from .shared.backups import RunPaths

__all__ = [
    "CallbackEventSink",
    "CommandResult",
    "CompositeEventSink",
    "Config",
    "EventSink",
    "Get",
    "GetResult",
    "InMemoryEventSink",
    "JSONLEventSink",
    "MappingRule",
    "NullEventSink",
    "Restore",
    "RunPaths",
    "Set",
    "SyncSamlOrgs",
]
