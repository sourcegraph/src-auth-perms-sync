"""Shared HTTP transport with timeouts, retries, and useful errors."""

from __future__ import annotations

import json
import logging
import random
import time
import urllib.parse
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Final, cast

import httpx

from src_py_lib.utils.json_types import JSONDict, json_dict
from src_py_lib.utils.logging import event, record_http_attempt, record_http_retry

DEFAULT_TIMEOUT_SECONDS: Final[float] = 30.0
DEFAULT_MAX_CONNECTIONS: Final[int] = 20
DEFAULT_MAX_ATTEMPTS: Final[int] = 3
DEFAULT_RETRY_BASE_DELAY_SECONDS: Final[float] = 0.5
DEFAULT_RETRY_MAX_DELAY_SECONDS: Final[float] = 30.0
RETRYABLE_STATUS_CODES: Final[frozenset[int]] = frozenset({408, 429, 500, 502, 503, 504})
ERROR_BODY_PREVIEW_CHARS: Final[int] = 500
REDACTED_HEADER_VALUE: Final[str] = "[redacted]"
SENSITIVE_HEADER_FRAGMENTS: Final[tuple[str, ...]] = (
    "api-key",
    "api_key",
    "authorization",
    "cookie",
    "password",
    "secret",
    "token",
)

logger = logging.getLogger(__name__)


class HTTPClientError(RuntimeError):
    """Raised when an HTTP request fails after retries."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        body: str = "",
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body
        self.headers = {key.lower(): value for key, value in dict(headers or {}).items()}


@dataclass
class HTTPClient:
    """HTTPX-backed HTTP client for JSON APIs with pooled connections."""

    timeout: float | httpx.Timeout = DEFAULT_TIMEOUT_SECONDS
    user_agent: str = "src-py-lib"
    max_connections: int = DEFAULT_MAX_CONNECTIONS
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    retry_base_delay_seconds: float = DEFAULT_RETRY_BASE_DELAY_SECONDS
    retry_max_delay_seconds: float = DEFAULT_RETRY_MAX_DELAY_SECONDS
    retryable_status_codes: frozenset[int] = RETRYABLE_STATUS_CODES
    transport: httpx.BaseTransport | None = field(default=None, repr=False)
    _client: httpx.Client = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.max_connections < 1:
            raise ValueError("max_connections must be at least 1")
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        self._client = httpx.Client(
            timeout=self.timeout,
            limits=httpx.Limits(
                max_connections=self.max_connections,
                max_keepalive_connections=self.max_connections,
            ),
            transport=self.transport,
        )

    def __enter__(self) -> HTTPClient:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying pooled HTTP transport."""
        self._client.close()

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        query: Mapping[str, str | int | float | bool | None] | None = None,
        json_body: object | None = None,
        data: bytes | None = None,
    ) -> bytes:
        """Make an HTTP request and return raw response bytes."""
        request_url = _with_query(url, query)
        body = data
        request_headers = {"User-Agent": self.user_agent, **dict(headers or {})}
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        for attempt in range(1, self.max_attempts + 1):
            try:
                with event(
                    "http_request",
                    level="debug",
                    method=method,
                    url=_safe_url(request_url),
                    attempt=attempt,
                    request_headers=_headers_for_log(request_headers),
                    request_bytes=len(body or b""),
                ) as fields:
                    response = self._client.request(
                        method,
                        request_url,
                        headers=request_headers,
                        content=body,
                    )
                    payload = response.content
                    fields["status_code"] = response.status_code
                    fields["reason_phrase"] = response.reason_phrase
                    fields["response_headers"] = _headers_for_log(response.headers)
                    fields["response_bytes"] = len(payload)
                    http_version = _response_http_version(response)
                    if http_version is not None:
                        fields["http_version"] = http_version
                    record_http_attempt(
                        request_bytes=len(body or b""),
                        response_bytes=len(payload),
                        status_code=response.status_code,
                    )
                    if response.status_code >= 400:
                        body_text = _body_preview(payload)
                        if not self._should_retry(response.status_code, attempt):
                            raise HTTPClientError(
                                f"HTTP {response.status_code} for {method} "
                                f"{_safe_url(request_url)}: {body_text}",
                                status_code=response.status_code,
                                body=body_text,
                                headers=dict(response.headers),
                            )
                        record_http_retry()
                        self._sleep_before_retry(attempt, response.headers.get("Retry-After"))
                    else:
                        return payload
            except HTTPClientError:
                raise
            except httpx.TransportError as exception:
                record_http_attempt(request_bytes=len(body or b""), transport_error=True)
                if not self._should_retry(None, attempt):
                    failure = (
                        "timed out" if isinstance(exception, httpx.TimeoutException) else "failed"
                    )
                    raise HTTPClientError(
                        f"HTTP request {failure} for {method} {_safe_url(request_url)}: "
                        f"{_exception_message(exception)}"
                    ) from exception
                record_http_retry()
                self._sleep_before_retry(attempt, None)
        raise AssertionError("HTTP retry loop exited without returning or raising")

    def json(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        query: Mapping[str, str | int | float | bool | None] | None = None,
        json_body: object | None = None,
    ) -> JSONDict:
        """Make an HTTP request and decode a JSON object response."""
        raw = self.request(method, url, headers=headers, query=query, json_body=json_body)
        try:
            return json_dict(json.loads(raw.decode("utf-8")) if raw else {})
        except json.JSONDecodeError as exception:
            raise HTTPClientError(
                f"Invalid JSON response from {method} {_safe_url(url)}"
            ) from exception

    def _should_retry(self, status_code: int | None, attempt: int) -> bool:
        if attempt >= self.max_attempts:
            return False
        return status_code is None or status_code in self.retryable_status_codes

    def _sleep_before_retry(self, attempt: int, retry_after: str | None) -> None:
        delay = retry_after_seconds(retry_after)
        if delay is None:
            delay = min(
                self.retry_base_delay_seconds * (2 ** (attempt - 1)),
                self.retry_max_delay_seconds,
            ) * random.uniform(0.5, 1.5)
        logger.warning("HTTP request failed; retrying in %.2fs (attempt %d).", delay, attempt + 1)
        time.sleep(delay)


def _with_query(
    url: str,
    query: Mapping[str, str | int | float | bool | None] | None,
) -> str:
    if not query:
        return url
    filtered = {key: value for key, value in query.items() if value is not None}
    separator = "&" if urllib.parse.urlsplit(url).query else "?"
    return f"{url}{separator}{urllib.parse.urlencode(filtered)}"


def _safe_url(url: str) -> str:
    split = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((split.scheme, split.netloc, split.path, split.query, ""))


def _headers_for_log(headers: Mapping[str, str] | httpx.Headers) -> dict[str, str | list[str]]:
    values: dict[str, str | list[str]] = {}
    for name, value in _header_items(headers):
        key = name.lower()
        logged_value = REDACTED_HEADER_VALUE if _is_sensitive_header(key) else value
        existing = values.get(key)
        if existing is None:
            values[key] = logged_value
        elif isinstance(existing, list):
            existing.append(logged_value)
        else:
            values[key] = [existing, logged_value]
    return {key: values[key] for key in sorted(values)}


def _header_items(headers: Mapping[str, str] | httpx.Headers) -> Iterable[tuple[str, str]]:
    if isinstance(headers, httpx.Headers):
        return headers.multi_items()
    return headers.items()


def _is_sensitive_header(name: str) -> bool:
    lowered = name.lower()
    return any(fragment in lowered for fragment in SENSITIVE_HEADER_FRAGMENTS)


def _response_http_version(response: httpx.Response) -> str | None:
    version = response.extensions.get("http_version")
    if isinstance(version, bytes):
        return version.decode("latin-1", errors="replace")
    if isinstance(version, str):
        return version
    return None


def _body_preview(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="replace").strip()
    if len(text) <= ERROR_BODY_PREVIEW_CHARS:
        return text
    return f"{text[:ERROR_BODY_PREVIEW_CHARS]}... (+{len(text) - ERROR_BODY_PREVIEW_CHARS} chars)"


def _exception_message(exception: Exception) -> str:
    return str(exception) or type(exception).__name__


def retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(float(value), 0.0)
    except ValueError:
        return None


def cast_json_dict(value: object) -> JSONDict:
    """Compatibility wrapper for call sites that want an explicit boundary cast."""
    return cast(JSONDict, value) if isinstance(value, dict) else {}
