"""Aligned TSV file writing."""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Final

DEFAULT_MAX_COLUMN_WIDTH: Final[int] = 100
_ZERO_WIDTH_CATEGORIES: Final[frozenset[str]] = frozenset({"Cf", "Me", "Mn"})


def write_tsv(
    path: Path,
    rows: Iterable[Mapping[str, object]],
    *,
    max_column_width: int = DEFAULT_MAX_COLUMN_WIDTH,
) -> None:
    """Write rows as a padded TSV table, inferring the header from row keys."""
    data_rows = list(rows)
    fieldnames = list(data_rows[0]) if data_rows else []
    table: list[Mapping[str, object]] = []
    if fieldnames:
        table.append(dict(zip(fieldnames, fieldnames, strict=True)))
    table.extend(data_rows)

    widths = {
        field: max(
            display_width(
                format_tsv_value(
                    row.get(field, ""),
                    field,
                    max_column_width=max_column_width,
                )
            )
            for row in table
        )
        for field in fieldnames
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        for row in table:
            values = [
                pad_display(
                    format_tsv_value(
                        row.get(field, ""),
                        field,
                        max_column_width=max_column_width,
                    ),
                    widths[field],
                )
                for field in fieldnames
            ]
            file.write("\t".join(values) + "\n")


def format_tsv_value(
    value: object,
    field: str,
    *,
    max_column_width: int = DEFAULT_MAX_COLUMN_WIDTH,
) -> str:
    """Return a single-line TSV cell value, truncating non-URL fields."""
    text = str(value).replace("\r", " ").replace("\n", " ").replace("\t", " ")
    if field == "url" or field.endswith("_url"):
        return text
    return text[:max_column_width]


def display_width(value: str) -> int:
    """Return terminal display width for padding aligned text columns."""
    width = 0
    for character in value:
        if unicodedata.combining(character):
            continue
        if unicodedata.category(character) in _ZERO_WIDTH_CATEGORIES:
            continue
        width += 2 if unicodedata.east_asian_width(character) in {"F", "W"} else 1
    return width


def pad_display(value: str, width: int) -> str:
    """Pad text to a target display width."""
    return value + " " * max(width - display_width(value), 0)


__all__ = [
    "DEFAULT_MAX_COLUMN_WIDTH",
    "display_width",
    "format_tsv_value",
    "pad_display",
    "write_tsv",
]
