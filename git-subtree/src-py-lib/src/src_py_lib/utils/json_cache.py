"""Small on-disk JSON cache helpers."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, TypeVar, cast

Entry = TypeVar("Entry")


def load_json_cache(
    path: Path,
    parse: Callable[[Any], Entry] | None = None,
) -> dict[str, Entry]:
    """Load `path` as a string-keyed cache. Missing files return `{}`."""
    if not path.exists():
        return {}
    raw = cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    if parse is None:
        return cast(dict[str, Entry], raw)
    return {key: parse(value) for key, value in raw.items()}


def save_json_cache(path: Path, cache: Mapping[str, object]) -> None:
    """Write a string-keyed JSON cache with stable formatting."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(cache), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_json_subset(
    path: Path,
    keys: list[str],
    parse: Callable[[Any], Entry] | None = None,
) -> dict[str, Entry]:
    """Load only `keys` that are present in a string-keyed JSON cache."""
    cache = load_json_cache(path, parse=parse)
    return {key: cache[key] for key in keys if key in cache}


__all__ = ["load_json_cache", "load_json_subset", "save_json_cache"]
