from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tests.e2e.test_permission_fixture_cases import FixtureRunResult

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _format_delta(before: int, after: int) -> str:
    return f"{after - before:+d}"


def _format_expected(value: int | None) -> str:
    if value is None:
        return "n/a"
    return str(value)


def _print_result(result: FixtureRunResult) -> None:
    status = "PASS" if result.passed else "FAIL"
    permission_pair_delta = _format_delta(
        result.before_counts.permission_pairs,
        result.actual_counts.permission_pairs,
    )
    print(f"{status} {result.name} — {result.description}")
    print(f"  scope: users={result.before_counts.users} repos={result.before_counts.repos}")
    print(
        "  permission pairs: "
        f"before={result.before_counts.permission_pairs} "
        f"expected={result.expected_counts.permission_pairs} "
        f"actual={result.actual_counts.permission_pairs} "
        f"delta={permission_pair_delta}"
    )
    print(
        "  changed repos: "
        f"expected={result.expected_changed_repos} "
        f"actual={result.actual_changed_repos}"
    )
    print(
        "  mutations: "
        f"expected={_format_expected(result.expected_mutations)} "
        f"actual={result.actual_mutations}"
    )
    if result.failure is not None:
        print(f"  failure: {result.failure}")
    print()


def main() -> int:
    from tests.e2e.test_permission_fixture_cases import fixture_case_dirs, run_fixture_case

    results = [run_fixture_case(case_dir) for case_dir in fixture_case_dirs()]
    for result in results:
        _print_result(result)

    passed = sum(1 for result in results if result.passed)
    failed = len(results) - passed
    print(f"Summary: {passed} passed, {failed} failed, {len(results)} total.")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
