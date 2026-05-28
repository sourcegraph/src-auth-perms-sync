"""Slack Web API client with cursor pagination and rate-limit handling."""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Final, cast

from src_py_lib.utils.config import Config, config_field
from src_py_lib.utils.http import HTTPClient, HTTPClientError, retry_after_seconds
from src_py_lib.utils.json_types import JSONDict, json_dict, json_list, json_str

SLACK_API_URL: Final[str] = "https://slack.com/api"
DEFAULT_PAGE_LIMIT: Final[int] = 200
DEFAULT_METHOD_INTERVAL_SECONDS: Final[float] = 1.3

logger = logging.getLogger(__name__)


class SlackError(RuntimeError):
    """Raised for Slack API errors."""


class SlackClientConfig(Config):
    """Config fields needed to build a Slack API client."""

    slack_bot_token: str = config_field(
        default="",
        env_var="SLACK_BOT_TOKEN",
        cli_flag="--slack-bot-token",
        metavar="TOKEN",
        help="Slack bot token or op:// secret reference",
        secret=True,
        required=True,
    )


@dataclass
class SlackPacer:
    """Reserve spaced request slots per Slack method to avoid 429 bursts."""

    default_interval_seconds: float = DEFAULT_METHOD_INTERVAL_SECONDS
    method_intervals: dict[str, float] = field(default_factory=lambda: cast(dict[str, float], {}))
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    _next_slot: dict[str, float] = field(
        default_factory=lambda: cast(dict[str, float], {}), init=False
    )

    def wait_for_slot(self, method: str) -> None:
        interval = self.method_intervals.get(method, self.default_interval_seconds)
        with self._lock:
            now = time.time()
            slot = max(self._next_slot.get(method, 0.0), now)
            self._next_slot[method] = slot + interval
        delay = slot - time.time()
        if delay > 0:
            time.sleep(delay)

    def bump_after_rate_limit(self, method: str, wait_seconds: float) -> None:
        with self._lock:
            self._next_slot[method] = max(
                self._next_slot.get(method, 0.0), time.time() + wait_seconds
            )


@dataclass
class SlackClient:
    token: str
    http: HTTPClient = field(default_factory=lambda: HTTPClient(max_attempts=1))
    pacer: SlackPacer = field(default_factory=SlackPacer)

    def get(self, method: str, params: dict[str, Any] | None = None) -> JSONDict:
        while True:
            self.pacer.wait_for_slot(method)
            try:
                data = self.http.json(
                    "GET",
                    f"{SLACK_API_URL}/{method}",
                    headers={"Authorization": f"Bearer {self.token}"},
                    query=params or {},
                )
            except HTTPClientError as exception:
                if exception.status_code == 429:
                    wait_seconds = retry_after_seconds(exception.headers.get("retry-after")) or 5.0
                    logger.warning("Slack %s rate-limited; sleeping %.0fs.", method, wait_seconds)
                    self.pacer.bump_after_rate_limit(method, wait_seconds)
                    continue
                raise SlackError(f"Slack request to {method} failed: {exception}") from exception
            if data.get("ok") is True:
                return data
            if data.get("error") == "ratelimited":
                self.pacer.bump_after_rate_limit(method, 5)
                continue
            raise SlackError(f"Slack API error on {method}: {data.get('error')}")

    def paginate(
        self,
        method: str,
        *,
        collection_key: str,
        params: dict[str, Any] | None = None,
        limit: int = DEFAULT_PAGE_LIMIT,
    ) -> list[JSONDict]:
        out: list[JSONDict] = []
        cursor = ""
        while True:
            page_params = {**(params or {}), "limit": limit}
            if cursor:
                page_params["cursor"] = cursor
            data = self.get(method, page_params)
            out.extend(json_dict(item) for item in json_list(data.get(collection_key)))
            cursor = json_str(json_dict(data.get("response_metadata")), "next_cursor")
            if not cursor:
                return out

    def list_users(self) -> list[JSONDict]:
        return self.paginate("users.list", collection_key="members")

    def validate(self) -> JSONDict:
        """Validate the token with Slack auth.test and return the response."""
        data = self.get("auth.test")
        if not json_str(data, "user_id"):
            raise SlackError("Slack auth.test response did not include user_id.")
        return data

    def workspace_url(self) -> str:
        url = json_str(self.get("auth.test"), "url").strip().rstrip("/")
        if not url:
            raise SlackError("Slack auth.test response did not include workspace URL.")
        return url


def slack_client_from_config(
    config: SlackClientConfig,
    *,
    http: HTTPClient | None = None,
    pacer: SlackPacer | None = None,
) -> SlackClient:
    """Return a Slack API client from shared Slack Config fields."""
    return SlackClient(
        config.slack_bot_token,
        http=http or HTTPClient(max_attempts=1),
        pacer=pacer or SlackPacer(),
    )
