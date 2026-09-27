"""Application configuration.

Every detection threshold lives here. Detectors read these values and never
inline a number, because each threshold encodes a judgement about what counts
as normal activity. Those judgements should be arguable in one place, not
scattered through detector code.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any

from pydantic import BeforeValidator, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _split_comma_list(value: Any) -> Any:
    """Accept `a,b,c` as well as `["a","b","c"]` for list settings.

    pydantic-settings JSON-decodes a complex field only when it comes from an
    environment variable, and rejects a plain comma-separated string by default.
    Comma-separated is what a .env file invites someone to write, and OAuth
    activity names contain spaces. Both forms are parsed here so the value means
    the same thing whether it arrives from the environment, from a .env file or
    from a test.
    """
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text:
        return []
    if text.startswith("["):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # A bracket that is not valid JSON is treated as ordinary text.
            pass
    return [part.strip() for part in text.split(",") if part.strip()]


def _split_comma_ints(value: Any) -> Any:
    parts = _split_comma_list(value)
    if isinstance(parts, list):
        return [int(part) for part in parts]
    return parts


StringList = Annotated[list[str], BeforeValidator(_split_comma_list)]
IntList = Annotated[list[int], BeforeValidator(_split_comma_ints)]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # -- runtime ---------------------------------------------------------
    mode: str = "demo"
    database_path: Path = PROJECT_ROOT / "data" / "entra_defense.db"
    sample_data_dir: Path = PROJECT_ROOT / "data" / "sample"
    log_level: str = "INFO"

    # -- Microsoft Graph (live mode) -------------------------------------
    graph_tenant_id: str = ""
    graph_client_id: str = ""
    graph_client_secret: str = ""
    graph_lookback_hours: int = 24
    graph_page_size: int = 100

    # -- System One: JEV ------------------------------------------------
    openrouter_api_key: str = ""
    jev_model_name: str = "typesafe/jev-router"
    jev_high_confidence: float = 0.80
    jev_medium_confidence: float = 0.60

    # -- System Two: investigation LLM -----------------------------------
    llm_model_name: str = "openai/gpt-4o-mini"
    llm_temperature: float = 0.0
    llm_max_tokens: int = 1200

    # -- detection thresholds -------------------------------------------
    spray_failed_login_threshold: int = 10
    spray_unique_user_threshold: int = 5
    spray_window_minutes: int = 10

    mfa_failure_threshold: int = 3
    mfa_window_minutes: int = 15
    mfa_success_lookahead_minutes: int = 10

    impossible_travel_speed_kmh: float = 900.0
    impossible_travel_lookback_hours: int = 24
    impossible_travel_min_distance_km: float = 200.0

    oauth_suspicious_activities: StringList = Field(
        default_factory=lambda: [
            "Consent to application",
            "Add delegated permission grant",
            "Add member to role",
            "Add eligible member to role",
            "Add scoped member to role",
        ]
    )
    oauth_sensitive_scopes: StringList = Field(
        default_factory=lambda: [
            "Mail.Read",
            "Mail.ReadWrite",
            "Files.ReadWrite.All",
            "Directory.ReadWrite.All",
            "User.ReadWrite.All",
            "offline_access",
            "Application.ReadWrite.All",
            "RoleManagement.ReadWrite.Directory",
        ]
    )

    # Entra sign-in error codes the detectors recognise. Kept in configuration
    # because they are external facts, not project decisions, and because they
    # are worth checking against your own tenant's logs.
    # Source: Microsoft "Microsoft Entra sign-in logs" error code table.
    mfa_denial_error_codes: IntList = Field(
        default_factory=lambda: [53001, 53002, 53009, 53012]
    )
    invalid_credentials_error_codes: IntList = Field(default_factory=lambda: [50126])
    mfa_method_types: StringList = Field(
        default_factory=lambda: [
            "Phone",
            "MicrosoftAuthenticatorPush",
            "SoftwareOath",
            "Fido2Passkey",
            "TemporaryAccessPassOneTimePasscode",
            "DeviceBasedPush",
        ]
    )

    # -- correlation -----------------------------------------------------
    incident_window_minutes: int = 60

    # -- derived helpers -------------------------------------------------
    @property
    def is_live_mode(self) -> bool:
        return self.mode.lower() == "live"

    @property
    def graph_configured(self) -> bool:
        """Live collection needs all three app-registration values."""
        return bool(self.graph_tenant_id and self.graph_client_id and self.graph_client_secret)

    @property
    def openrouter_configured(self) -> bool:
        return bool(self.openrouter_api_key)

    def ensure_directories(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.sample_data_dir.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """Tests mutate environment variables, so they need to drop the cached instance."""
    get_settings.cache_clear()


def configure_logging(settings: Settings | None = None) -> None:
    """Standard-library logging. Nothing here ever receives a secret.

    The formatter deliberately omits anything credential-shaped: callers pass
    message text, and the project never interpolates a token, client secret or
    API key into a log call.
    """
    import logging

    settings = settings or get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        force=True,
    )


# Environment variable names the live collector needs. Kept as a list so the
# /health endpoint can tell a user exactly what is missing.
GRAPH_ENV_VARS = [
    "GRAPH_TENANT_ID",
    "GRAPH_CLIENT_ID",
    "GRAPH_CLIENT_SECRET",
]


def missing_graph_env_vars() -> list[str]:
    return [name for name in GRAPH_ENV_VARS if not os.environ.get(name)]
