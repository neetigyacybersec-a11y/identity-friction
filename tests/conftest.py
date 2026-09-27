"""Shared fixtures.

Two rules for this suite:

1. **No network, ever.** Every model call and every Graph call is driven through
   an injected fake. A test that needs a real key is not a test.
2. **No shared state.** Each test gets its own temporary database and its own
   Settings, because `get_settings` is cached and thresholds leak between tests
   otherwise.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from app.config import Settings, reset_settings_cache
from app.database.repository import Repository
from app.models.event import DataOrigin
from app.normalize import normalize_many_strict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_DIR = PROJECT_ROOT / "data" / "sample"


@pytest.fixture(autouse=True)
def clear_settings_cache():
    """Drop the cached settings around every test.

    Tests that set environment variables would otherwise affect whichever test
    happens to run next through the module-level cache.
    """
    reset_settings_cache()
    yield
    reset_settings_cache()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Settings pointed at a throwaway database, with no credentials.

    The temp database matters more than it looks: several tests assert on row
    counts, and a shared file would make them order-dependent.
    """
    return Settings(
        mode="demo",
        database_path=tmp_path / "test.db",
        sample_data_dir=SAMPLE_DIR,
        openrouter_api_key="",
    )


@pytest.fixture
def repository(settings: Settings) -> Repository:
    return Repository(settings.database_path)


@pytest.fixture
def sample_files() -> dict[str, list[dict[str, Any]]]:
    """Every bundled sample file, keyed by its scenario name.

    Reading from disk rather than rebuilding events in code means the tests
    assert against the same data a user gets, so a broken sample file fails a
    test instead of quietly only affecting the demo.
    """
    files: dict[str, list[dict[str, Any]]] = {}
    for path in sorted(SAMPLE_DIR.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        files[path.stem] = payload.get("events", [])
    return files


@pytest.fixture
def events_from(sample_files) -> dict[str, list]:
    """Sample payloads normalized into events, keyed by scenario name."""
    return {
        name: normalize_many_strict(payloads, DataOrigin.SYNTHETIC)
        for name, payloads in sample_files.items()
    }


class FakeResponse:
    """The minimum of `httpx.Response` the adapters use."""

    def __init__(self, status_code: int, body: Any = None) -> None:
        self.status_code = status_code
        self._body = body

    def json(self) -> Any:
        if self._body is None:
            raise ValueError("response body is not JSON")
        return self._body


class FakePostClient:
    """Stands in for `httpx.Client` in POST-based adapters."""

    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.requests: list[dict[str, Any]] = []

    def post(self, url: str, headers: dict | None = None, json: Any = None):
        self.requests.append({"url": url, "headers": headers, "json": json})
        return self.response

    def content_of_last_request(self) -> Any:
        return self.requests[-1]["json"]


class FakeGetClient:
    """Stands in for `httpx.Client` in the Graph collector.

    `responses` is consumed one per GET, so a test can script a multi-page
    sequence. Anything left over returns an empty page, which keeps a test that
    under-specifies its script from raising an IndexError.
    """

    def __init__(self, responses: list[Any]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def get(self, url: str, headers: dict | None = None, params: dict | None = None):
        self.calls.append({"url": url, "headers": headers, "params": params})
        if not self.responses:
            return FakeResponse(200, {"value": []})
        nxt = self.responses.pop(0)
        if isinstance(nxt, FakeResponse):
            return nxt
        if isinstance(nxt, Exception):
            raise nxt
        return FakeResponse(200, nxt)


def openrouter_body(content: str) -> dict[str, Any]:
    """A well-formed OpenRouter envelope carrying `content`."""
    return {"choices": [{"message": {"role": "assistant", "content": content}}]}
