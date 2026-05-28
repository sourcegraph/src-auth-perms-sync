"""Small 1Password CLI client."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass

from src_py_lib.utils.json_types import JSONDict, json_dict


class OnePasswordError(RuntimeError):
    """Raised when resolving a 1Password reference fails."""


@dataclass(frozen=True)
class OnePasswordClient:
    """Resolve `op://...` references through the `op` CLI."""

    op_binary: str = "op"

    def signin(self) -> JSONDict:
        """Run an interactive 1Password CLI sign-in, then return account info."""
        try:
            subprocess.run([self.op_binary, "signin"], check=True)
        except FileNotFoundError as exception:
            raise OnePasswordError("1Password CLI (`op`) was not found on PATH.") from exception
        except subprocess.CalledProcessError as exception:
            stderr = exception.stderr.strip() if isinstance(exception.stderr, str) else ""
            raise OnePasswordError(
                f"Failed to sign in to 1Password CLI (`op`): {stderr or exception}"
            ) from exception

        return self.validate()

    def validate(self) -> JSONDict:
        """Validate that the 1Password CLI is authenticated and return account info."""
        try:
            result = subprocess.run(
                [self.op_binary, "whoami", "--format", "json"],
                check=True,
                text=True,
                capture_output=True,
            )
        except FileNotFoundError as exception:
            raise OnePasswordError("1Password CLI (`op`) was not found on PATH.") from exception
        except subprocess.CalledProcessError as exception:
            stderr = exception.stderr.strip()
            raise OnePasswordError(
                f"1Password CLI (`op`) is not authenticated: {stderr or exception}"
            ) from exception

        try:
            account = json_dict(json.loads(result.stdout))
        except json.JSONDecodeError as exception:
            raise OnePasswordError("`op whoami --format json` returned invalid JSON") from exception
        if not account:
            raise OnePasswordError("`op whoami --format json` returned an empty account")
        return account

    def read(self, secret_ref: str) -> str:
        """Return the resolved value for one `op://...` reference."""
        try:
            result = subprocess.run(
                [self.op_binary, "read", secret_ref],
                check=True,
                text=True,
                capture_output=True,
            )
        except FileNotFoundError as exception:
            raise OnePasswordError("1Password CLI (`op`) was not found on PATH.") from exception
        except subprocess.CalledProcessError as exception:
            stderr = exception.stderr.strip()
            raise OnePasswordError(
                f"Failed to resolve 1Password reference: {stderr or exception}"
            ) from exception

        secret = result.stdout.strip()
        if not secret:
            raise OnePasswordError(f"`op read {secret_ref}` returned an empty value")
        return secret


def resolve_op_secret_ref(value: str, *, client: OnePasswordClient | None = None) -> str:
    """Resolve `value` if it is an `op://...` reference; otherwise return it.

    This is useful for config values that may be either a raw value or a
    1Password reference. The resolved value is returned, not logged.
    """
    stripped = value.strip()
    if not stripped:
        raise OnePasswordError("1Password reference value is empty")
    if not stripped.startswith("op://"):
        return stripped
    return (client or OnePasswordClient()).read(stripped)
