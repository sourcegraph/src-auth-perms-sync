"""Google Sheets API client using an already-available OAuth access token."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from src_py_lib.utils.http import HTTPClient, HTTPClientError
from src_py_lib.utils.json_types import JSONDict, json_dict, json_int, json_list, json_str

SHEETS_API_URL = "https://sheets.googleapis.com/v4/spreadsheets"
DEFAULT_ADC_FILE = Path("~/.config/gcloud/application_default_credentials.json").expanduser()


class GoogleSheetsError(RuntimeError):
    """Raised for Google Sheets client errors."""


@dataclass(frozen=True)
class LinkRun:
    start: int
    end: int
    uri: str


@dataclass(frozen=True)
class Cell:
    text: str
    links: tuple[LinkRun, ...] = ()


CellValue = str | Cell


@dataclass
class GoogleSheetsClient:
    spreadsheet_id: str
    access_token: str
    quota_project: str | None = None
    http: HTTPClient = field(default_factory=HTTPClient)

    @classmethod
    def from_gcloud_adc(
        cls,
        spreadsheet_id: str,
        *,
        credentials_file: Path = DEFAULT_ADC_FILE,
        http: HTTPClient | None = None,
    ) -> GoogleSheetsClient:
        return cls(
            spreadsheet_id=spreadsheet_id,
            access_token=gcloud_adc_access_token(credentials_file),
            quota_project=quota_project_from_adc(credentials_file),
            http=http or HTTPClient(),
        )

    def request(self, method: str, path: str, body: JSONDict | None = None) -> JSONDict:
        headers = {"Authorization": f"Bearer {self.access_token}"}
        if self.quota_project:
            headers["X-Goog-User-Project"] = self.quota_project
        try:
            return self.http.json(
                method,
                f"{SHEETS_API_URL}/{self.spreadsheet_id}{path}",
                headers=headers,
                json_body=body,
            )
        except HTTPClientError as exception:
            raise GoogleSheetsError(
                f"Google Sheets {method} {path} failed: {exception}"
            ) from exception

    def metadata(self) -> JSONDict:
        return self.request("GET", "?fields=sheets.properties(sheetId,title,gridProperties)")

    def validate(self) -> JSONDict:
        """Validate spreadsheet access and return spreadsheet metadata."""
        metadata = self.metadata()
        if not isinstance(metadata.get("sheets"), list):
            raise GoogleSheetsError("Google Sheets metadata response did not include sheets.")
        return metadata

    def tab_ids_by_title(self) -> dict[str, int]:
        return {
            json_str(properties, "title"): json_int(properties, "sheetId")
            for sheet in json_list(self.metadata().get("sheets"))
            if (properties := json_dict(json_dict(sheet).get("properties")))
        }

    def batch_update(self, requests: list[JSONDict]) -> JSONDict:
        return self.request("POST", ":batchUpdate", cast(JSONDict, {"requests": requests}))


def hyperlink_cell(url: str, text: str) -> CellValue:
    if not url:
        return ""
    return Cell(text=text, links=(LinkRun(0, len(text), url),))


def quota_project_from_adc(credentials_file: Path = DEFAULT_ADC_FILE) -> str:
    if not credentials_file.exists():
        raise GoogleSheetsError(f"Application Default Credentials not found at {credentials_file}.")
    data = json_dict(json.loads(credentials_file.read_text(encoding="utf-8")))
    quota_project = json_str(data, "quota_project_id")
    if not quota_project:
        raise GoogleSheetsError(f"{credentials_file} does not contain quota_project_id.")
    return quota_project


def gcloud_adc_access_token(credentials_file: Path = DEFAULT_ADC_FILE) -> str:
    env = os.environ.copy()
    env["GOOGLE_APPLICATION_CREDENTIALS"] = str(credentials_file)
    try:
        result = subprocess.run(
            ["gcloud", "auth", "application-default", "print-access-token"],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exception:
        raise GoogleSheetsError("Could not run gcloud to fetch an ADC access token.") from exception
    token = result.stdout.strip()
    if result.returncode != 0 or not token:
        raise GoogleSheetsError(result.stderr.strip() or "gcloud did not return an access token.")
    return token
