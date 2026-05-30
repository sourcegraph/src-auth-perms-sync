#!/usr/bin/env python3
"""Fit a Sourcegraph permissions memory model from e2e result JSON.

The model is intentionally small and dependency-free:

    peak RSS MiB = intercept + users*b1 + repos*b2 + grants*b3

Use one command mode per fit. Mixing backup, no-backup, get, set, and restore
runs makes the per-grant coefficient much less useful.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

FEATURE_NAMES = ("users", "repos", "grants")
COEFFICIENT_SCALE = {
    "users": "bytes/user",
    "repos": "bytes/repo",
    "grants": "bytes/grant",
}


@dataclass(frozen=True)
class WorkloadDimensions:
    """Canonical workload dimensions used by the memory model."""

    users: float | None
    repos: float | None
    grants: float | None


@dataclass(frozen=True)
class MemoryObservation:
    """One e2e command result with peak memory and workload dimensions."""

    source_path: str
    variant: str
    case_name: str
    command: str
    iteration: int
    peak_resident_megabytes: float
    dimensions: WorkloadDimensions


@dataclass(frozen=True)
class MemoryModel:
    """Fitted linear memory model."""

    feature_names: tuple[str, ...]
    coefficients_megabytes: dict[str, float]
    observation_count: int
    r_squared: float | None
    mean_absolute_error_megabytes: float
    p95_absolute_error_megabytes: float
    max_absolute_error_megabytes: float


@dataclass(frozen=True)
class MemoryEstimate:
    """Predicted memory for a proposed users x repos workload."""

    dimensions: WorkloadDimensions
    peak_resident_megabytes: float
    peak_resident_megabytes_with_headroom: float
    headroom_percent: float


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fit a fixed + users + repos + grants memory model from e2e JSON.",
    )
    parser.add_argument(
        "results_json",
        nargs="+",
        type=Path,
        help="One or more JSON files written by dev/test-end-to-end.py --results-json.",
    )
    parser.add_argument(
        "--variant",
        help="Only include one variant, e.g. candidate or baseline.",
    )
    parser.add_argument(
        "--command",
        help="Only include one structured command, e.g. set_full or get.",
    )
    parser.add_argument(
        "--case-regex",
        help="Only include cases whose e2e case name matches this regular expression.",
    )
    parser.add_argument(
        "--features",
        default="users,repos,grants",
        help="Comma-separated model features from users,repos,grants (default: all).",
    )
    parser.add_argument(
        "--min-grants",
        type=float,
        default=1.0,
        help="Drop observations below this grant count (default: 1).",
    )
    parser.add_argument(
        "--estimate-users",
        type=float,
        help="Estimate memory for this many users.",
    )
    parser.add_argument(
        "--estimate-repos",
        type=float,
        help="Estimate memory for this many repos.",
    )
    parser.add_argument(
        "--estimate-grants",
        type=float,
        help="Estimate memory for this many grants; defaults to users * repos.",
    )
    parser.add_argument(
        "--headroom-percent",
        type=float,
        default=30.0,
        help="Headroom to add to estimates (default: 30).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Write machine-readable JSON instead of a text report.",
    )
    arguments = parser.parse_args()

    feature_names = parse_feature_names(arguments.features)
    observations = load_observations(arguments.results_json)
    filtered_observations = filter_observations(
        observations,
        variant=arguments.variant,
        command=arguments.command,
        case_regex=arguments.case_regex,
        min_grants=arguments.min_grants,
    )
    model_observations = observations_with_features(filtered_observations, feature_names)
    minimum_observations = len(feature_names) + 1
    if len(model_observations) < minimum_observations:
        print(
            "Need at least "
            f"{minimum_observations} observations with {', '.join(feature_names)} "
            f"to fit this model; found {len(model_observations)}.",
            file=sys.stderr,
        )
        return 2

    try:
        model = fit_memory_model(model_observations, feature_names)
    except ValueError as error:
        print(f"Could not fit memory model: {error}", file=sys.stderr)
        print(
            "Try filtering to one command mode, adding varied users x repos shapes, "
            "or using fewer --features.",
            file=sys.stderr,
        )
        return 2

    estimate = build_estimate(
        model,
        feature_names,
        estimate_users=arguments.estimate_users,
        estimate_repos=arguments.estimate_repos,
        estimate_grants=arguments.estimate_grants,
        headroom_percent=arguments.headroom_percent,
    )
    if arguments.json:
        write_json_report(model, model_observations, estimate)
    else:
        write_text_report(model, model_observations, estimate)
    return 0


def parse_feature_names(raw_features: str) -> tuple[str, ...]:
    names = tuple(name.strip() for name in raw_features.split(",") if name.strip())
    invalid = sorted(set(names) - set(FEATURE_NAMES))
    if invalid:
        raise SystemExit(f"Unknown feature(s): {', '.join(invalid)}")
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise SystemExit(f"Duplicate feature(s): {', '.join(duplicates)}")
    if not names:
        raise SystemExit("At least one feature is required.")
    return names


def load_observations(paths: list[Path]) -> list[MemoryObservation]:
    observations: list[MemoryObservation] = []
    for path in paths:
        with path.open(encoding="utf-8") as input_file:
            payload: object = json.load(input_file)
        for result in result_mappings(payload):
            observation = observation_from_result(path, result)
            if observation is not None:
                observations.append(observation)
    return observations


def result_mappings(payload: object) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        mapping = cast(dict[str, Any], payload)
        results = mapping.get("results")
        if isinstance(results, list):
            return mapping_items(cast(list[object], results))
        if "memory" in mapping and "workload" in mapping:
            return [mapping]
    if isinstance(payload, list):
        return mapping_items(cast(list[object], payload))
    return []


def mapping_items(values: list[object]) -> list[dict[str, Any]]:
    """Return only dict-like JSON objects from a JSON list."""
    return [cast(dict[str, Any], value) for value in values if isinstance(value, dict)]


def observation_from_result(path: Path, result: dict[str, Any]) -> MemoryObservation | None:
    memory = object_mapping(result.get("memory"))
    workload = object_mapping(result.get("workload"))
    if memory is None or workload is None:
        return None
    peak_resident_megabytes = first_number(memory, ("peak_rss_mb", "external_peak_rss_mb"))
    if peak_resident_megabytes is None:
        return None
    return MemoryObservation(
        source_path=str(path),
        variant=string_value(result.get("variant")),
        case_name=string_value(result.get("case")),
        command=string_value(result.get("command")),
        iteration=integer_value(result.get("iteration")),
        peak_resident_megabytes=peak_resident_megabytes,
        dimensions=WorkloadDimensions(
            users=first_number(
                workload,
                (
                    "memory_model_user_count",
                    "selected_user_count",
                    "captured_user_count",
                    "snapshot_user_count_max",
                    "user_count",
                    "total_users_scanned",
                    "sourcegraph_user_count",
                    "total_users",
                ),
            ),
            repos=first_number(
                workload,
                (
                    "memory_model_repo_count",
                    "planned_repo_count",
                    "restore_snapshot_repo_count",
                    "snapshot_repos_with_explicit_grants_max",
                    "repos_with_explicit_grants",
                    "loaded_repo_count",
                    "repo_count",
                ),
            ),
            grants=first_number(
                workload,
                (
                    "memory_model_grant_count",
                    "planned_total_grants",
                    "restore_snapshot_total_grants",
                    "selected_total_grants",
                    "snapshot_total_grants_max",
                    "total_grants",
                    "apply_payload_grant_count",
                ),
            ),
        ),
    )


def filter_observations(
    observations: list[MemoryObservation],
    *,
    variant: str | None,
    command: str | None,
    case_regex: str | None,
    min_grants: float,
) -> list[MemoryObservation]:
    pattern = re.compile(case_regex) if case_regex else None
    filtered: list[MemoryObservation] = []
    for observation in observations:
        if variant is not None and observation.variant != variant:
            continue
        if command is not None and observation.command != command:
            continue
        if pattern is not None and pattern.search(observation.case_name) is None:
            continue
        if observation.dimensions.grants is None or observation.dimensions.grants < min_grants:
            continue
        filtered.append(observation)
    return filtered


def observations_with_features(
    observations: list[MemoryObservation], feature_names: tuple[str, ...]
) -> list[MemoryObservation]:
    return [
        observation
        for observation in observations
        if all(feature_value(observation.dimensions, name) is not None for name in feature_names)
    ]


def fit_memory_model(
    observations: list[MemoryObservation], feature_names: tuple[str, ...]
) -> MemoryModel:
    feature_scales = feature_scale_by_name(observations, feature_names)
    matrix = [
        [1.0]
        + [
            required_feature_value(observation.dimensions, feature_name)
            / feature_scales[feature_name]
            for feature_name in feature_names
        ]
        for observation in observations
    ]
    targets = [observation.peak_resident_megabytes for observation in observations]
    scaled_coefficients = solve_normal_equations(matrix, targets)
    coefficients = {"intercept": scaled_coefficients[0]}
    for feature_index, feature_name in enumerate(feature_names, start=1):
        coefficients[feature_name] = (
            scaled_coefficients[feature_index] / feature_scales[feature_name]
        )
    predictions = [
        predict_megabytes(coefficients, observation.dimensions) for observation in observations
    ]
    residuals = [
        target - prediction for target, prediction in zip(targets, predictions, strict=True)
    ]
    absolute_residuals = [abs(residual) for residual in residuals]
    target_mean = statistics.fmean(targets)
    residual_sum_squares = sum(residual * residual for residual in residuals)
    total_sum_squares = sum((target - target_mean) ** 2 for target in targets)
    return MemoryModel(
        feature_names=feature_names,
        coefficients_megabytes=coefficients,
        observation_count=len(observations),
        r_squared=(
            None if total_sum_squares == 0 else 1.0 - residual_sum_squares / total_sum_squares
        ),
        mean_absolute_error_megabytes=statistics.fmean(absolute_residuals),
        p95_absolute_error_megabytes=percentile(absolute_residuals, 95.0),
        max_absolute_error_megabytes=max(absolute_residuals),
    )


def feature_scale_by_name(
    observations: list[MemoryObservation], feature_names: tuple[str, ...]
) -> dict[str, float]:
    scales: dict[str, float] = {}
    for feature_name in feature_names:
        maximum = max(
            abs(required_feature_value(observation.dimensions, feature_name))
            for observation in observations
        )
        scales[feature_name] = maximum if maximum > 0 else 1.0
    return scales


def solve_normal_equations(matrix: list[list[float]], targets: list[float]) -> list[float]:
    column_count = len(matrix[0])
    normal_matrix = [[0.0 for _ in range(column_count)] for _ in range(column_count)]
    normal_targets = [0.0 for _ in range(column_count)]
    for row, target in zip(matrix, targets, strict=True):
        for row_index in range(column_count):
            normal_targets[row_index] += row[row_index] * target
            for column_index in range(column_count):
                normal_matrix[row_index][column_index] += row[row_index] * row[column_index]
    return solve_linear_system(normal_matrix, normal_targets)


def solve_linear_system(matrix: list[list[float]], values: list[float]) -> list[float]:
    size = len(values)
    augmented = [matrix[row_index][:] + [values[row_index]] for row_index in range(size)]
    for pivot_index in range(size):
        pivot_row = max(
            range(pivot_index, size),
            key=lambda row_index: abs(augmented[row_index][pivot_index]),
        )
        pivot_value = augmented[pivot_row][pivot_index]
        if abs(pivot_value) < 1e-12:
            raise ValueError("features are collinear or the sample is too small")
        augmented[pivot_index], augmented[pivot_row] = augmented[pivot_row], augmented[pivot_index]
        for column_index in range(pivot_index, size + 1):
            augmented[pivot_index][column_index] /= pivot_value
        for row_index in range(size):
            if row_index == pivot_index:
                continue
            factor = augmented[row_index][pivot_index]
            for column_index in range(pivot_index, size + 1):
                augmented[row_index][column_index] -= factor * augmented[pivot_index][column_index]
    return [augmented[row_index][size] for row_index in range(size)]


def build_estimate(
    model: MemoryModel,
    feature_names: tuple[str, ...],
    *,
    estimate_users: float | None,
    estimate_repos: float | None,
    estimate_grants: float | None,
    headroom_percent: float,
) -> MemoryEstimate | None:
    if estimate_users is None and estimate_repos is None and estimate_grants is None:
        return None
    if "users" in feature_names and estimate_users is None:
        raise SystemExit("--estimate-users is required because users is in --features.")
    if "repos" in feature_names and estimate_repos is None:
        raise SystemExit("--estimate-repos is required because repos is in --features.")
    if "grants" in feature_names and estimate_grants is None:
        if estimate_users is None or estimate_repos is None:
            raise SystemExit(
                "--estimate-grants is required unless --estimate-users and --estimate-repos "
                "are both set."
            )
        estimate_grants = estimate_users * estimate_repos
    dimensions = WorkloadDimensions(
        users=estimate_users,
        repos=estimate_repos,
        grants=estimate_grants,
    )
    peak_resident_megabytes = predict_megabytes(model.coefficients_megabytes, dimensions)
    return MemoryEstimate(
        dimensions=dimensions,
        peak_resident_megabytes=peak_resident_megabytes,
        peak_resident_megabytes_with_headroom=peak_resident_megabytes
        * (1.0 + headroom_percent / 100.0),
        headroom_percent=headroom_percent,
    )


def predict_megabytes(
    coefficients_megabytes: dict[str, float], dimensions: WorkloadDimensions
) -> float:
    prediction = coefficients_megabytes["intercept"]
    for feature_name in FEATURE_NAMES:
        coefficient = coefficients_megabytes.get(feature_name)
        value = feature_value(dimensions, feature_name)
        if coefficient is not None and value is not None:
            prediction += coefficient * value
    return prediction


def write_text_report(
    model: MemoryModel, observations: list[MemoryObservation], estimate: MemoryEstimate | None
) -> None:
    print(f"Observations used: {model.observation_count}")
    print(f"Features: {', '.join(model.feature_names)}")
    print("\nCoefficients:")
    print(f"  intercept: {model.coefficients_megabytes['intercept']:.3f} MiB")
    for feature_name in model.feature_names:
        coefficient_megabytes = model.coefficients_megabytes[feature_name]
        coefficient_bytes = coefficient_megabytes * 1024.0 * 1024.0
        print(
            f"  {feature_name}: {coefficient_megabytes:.9f} MiB/unit "
            f"({coefficient_bytes:.1f} {COEFFICIENT_SCALE[feature_name]})"
        )
    r_squared = "n/a" if model.r_squared is None else f"{model.r_squared:.4f}"
    print("\nFit quality:")
    print(f"  R²: {r_squared}")
    print(f"  mean absolute error: {model.mean_absolute_error_megabytes:.2f} MiB")
    print(f"  p95 absolute error: {model.p95_absolute_error_megabytes:.2f} MiB")
    print(f"  max absolute error: {model.max_absolute_error_megabytes:.2f} MiB")
    print("\nObserved range:")
    print_dimension_range(observations, "users")
    print_dimension_range(observations, "repos")
    print_dimension_range(observations, "grants")
    if estimate is not None:
        print("\nEstimate:")
        print(f"  users: {format_optional_number(estimate.dimensions.users)}")
        print(f"  repos: {format_optional_number(estimate.dimensions.repos)}")
        print(f"  grants: {format_optional_number(estimate.dimensions.grants)}")
        print(f"  peak RSS: {estimate.peak_resident_megabytes:.1f} MiB")
        print(
            f"  with {estimate.headroom_percent:g}% headroom: "
            f"{estimate.peak_resident_megabytes_with_headroom:.1f} MiB"
        )


def write_json_report(
    model: MemoryModel, observations: list[MemoryObservation], estimate: MemoryEstimate | None
) -> None:
    report: dict[str, Any] = {
        "observation_count": model.observation_count,
        "features": list(model.feature_names),
        "coefficients_mib": model.coefficients_megabytes,
        "coefficients_bytes": {
            feature_name: model.coefficients_megabytes[feature_name] * 1024.0 * 1024.0
            for feature_name in model.feature_names
        },
        "fit": {
            "r_squared": model.r_squared,
            "mean_absolute_error_mib": model.mean_absolute_error_megabytes,
            "p95_absolute_error_mib": model.p95_absolute_error_megabytes,
            "max_absolute_error_mib": model.max_absolute_error_megabytes,
        },
        "observed_range": observed_range_to_json(observations),
        "estimate": estimate_to_json(estimate),
    }
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def print_dimension_range(observations: list[MemoryObservation], feature_name: str) -> None:
    values = [
        value
        for observation in observations
        if (value := feature_value(observation.dimensions, feature_name)) is not None
    ]
    if not values:
        print(f"  {feature_name}: n/a")
        return
    print(f"  {feature_name}: {format_number(min(values))} .. {format_number(max(values))}")


def observed_range_to_json(observations: list[MemoryObservation]) -> dict[str, dict[str, float]]:
    ranges: dict[str, dict[str, float]] = {}
    for feature_name in FEATURE_NAMES:
        values = [
            value
            for observation in observations
            if (value := feature_value(observation.dimensions, feature_name)) is not None
        ]
        if values:
            ranges[feature_name] = {"min": min(values), "max": max(values)}
    return ranges


def estimate_to_json(estimate: MemoryEstimate | None) -> dict[str, Any] | None:
    if estimate is None:
        return None
    return {
        "users": estimate.dimensions.users,
        "repos": estimate.dimensions.repos,
        "grants": estimate.dimensions.grants,
        "peak_rss_mib": estimate.peak_resident_megabytes,
        "headroom_percent": estimate.headroom_percent,
        "peak_rss_mib_with_headroom": estimate.peak_resident_megabytes_with_headroom,
    }


def object_mapping(value: object) -> dict[str, Any] | None:
    return cast(dict[str, Any], value) if isinstance(value, dict) else None


def first_number(mapping: dict[str, Any], names: tuple[str, ...]) -> float | None:
    for name in names:
        value = mapping.get(name)
        if isinstance(value, bool):
            continue
        if isinstance(value, int | float):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                continue
    return None


def string_value(value: object) -> str:
    return value if isinstance(value, str) else ""


def integer_value(value: object) -> int:
    if isinstance(value, bool):
        return 0
    return value if isinstance(value, int) else 0


def feature_value(dimensions: WorkloadDimensions, feature_name: str) -> float | None:
    if feature_name == "users":
        return dimensions.users
    if feature_name == "repos":
        return dimensions.repos
    if feature_name == "grants":
        return dimensions.grants
    raise ValueError(f"Unknown feature: {feature_name}")


def required_feature_value(dimensions: WorkloadDimensions, feature_name: str) -> float:
    value = feature_value(dimensions, feature_name)
    if value is None:
        raise ValueError(f"Observation is missing feature: {feature_name}")
    return value


def percentile(values: list[float], percentile_value: float) -> float:
    if not values:
        return math.nan
    sorted_values = sorted(values)
    index = math.ceil((percentile_value / 100.0) * len(sorted_values)) - 1
    return sorted_values[min(max(index, 0), len(sorted_values) - 1)]


def format_optional_number(value: float | None) -> str:
    return "n/a" if value is None else format_number(value)


def format_number(value: float) -> str:
    return f"{value:.0f}" if value.is_integer() else f"{value:.3f}"


if __name__ == "__main__":
    raise SystemExit(main())
