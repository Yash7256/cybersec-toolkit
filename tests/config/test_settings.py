"""
Unit and property-based tests for Settings DATABASE_SYNC_URL field.

Validates: Requirements 1.1, 1.2, 1.4

Coverage:
  - Settings() with no env returns DATABASE_SYNC_URL == ""  (Req 1.1, 1.3)
  - Settings() with no env still returns the correct asyncpg default for
    DATABASE_URL  (Req 1.2)
  - Property 4: Settings field isolation — for any string passed as
    DATABASE_SYNC_URL env var, settings.DATABASE_SYNC_URL equals that string
    exactly, and DATABASE_URL is unaffected  (Req 1.4)
"""
import os
import pytest
from hypothesis import given, settings as hyp_settings
from hypothesis import strategies as st

from cybersec.config.settings import Settings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ASYNCPG_DEFAULT = "postgresql+asyncpg://postgres:postgres@localhost:5432/cybersec"

def _settings_no_env(**overrides) -> Settings:
    """Instantiate Settings without loading any .env file.

    Any keyword arguments are passed as field overrides, allowing tests to
    inject specific env-var values without touching the actual environment.
    """
    return Settings(_env_file=None, **overrides)


# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------

class TestDatabaseSyncUrlDefault:
    """Req 1.1 / 1.3 — DATABASE_SYNC_URL defaults to empty string."""

    def test_default_is_empty_string(self):
        """With no env and no .env file, DATABASE_SYNC_URL must be ''."""
        s = _settings_no_env()
        assert s.DATABASE_SYNC_URL == ""

    def test_default_type_is_str(self):
        """DATABASE_SYNC_URL must be of type str, not None or anything else."""
        s = _settings_no_env()
        assert isinstance(s.DATABASE_SYNC_URL, str)

    def test_no_validation_error_without_env(self):
        """Settings must instantiate cleanly when DATABASE_SYNC_URL is absent."""
        try:
            _settings_no_env()
        except Exception as exc:
            pytest.fail(f"Settings() raised unexpectedly: {exc}")


class TestDatabaseUrlUnchanged:
    """Req 1.2 — DATABASE_URL retains its existing asyncpg default."""

    def test_database_url_default_is_asyncpg(self):
        """DATABASE_URL default must remain the asyncpg connection string."""
        s = _settings_no_env()
        assert s.DATABASE_URL == _ASYNCPG_DEFAULT

    def test_database_url_unchanged_when_sync_url_set(self):
        """Setting DATABASE_SYNC_URL must not alter DATABASE_URL."""
        s = _settings_no_env(DATABASE_SYNC_URL="postgresql+psycopg2://user:pass@host/db")
        assert s.DATABASE_URL == _ASYNCPG_DEFAULT


class TestDatabaseSyncUrlFromEnv:
    """Req 1.4 — DATABASE_SYNC_URL is returned exactly as provided in the env."""

    def test_psycopg2_url_returned_exactly(self):
        """A psycopg2 URL passed in env is returned unchanged."""
        url = "postgresql+psycopg2://user:secret@db.example.com:5432/mydb"
        s = _settings_no_env(DATABASE_SYNC_URL=url)
        assert s.DATABASE_SYNC_URL == url

    def test_arbitrary_string_returned_exactly(self):
        """Settings performs no transformation on the raw string value."""
        url = "sqlite:///local.db"
        s = _settings_no_env(DATABASE_SYNC_URL=url)
        assert s.DATABASE_SYNC_URL == url

    def test_empty_string_override_returns_empty(self):
        """Explicitly passing '' still yields ''."""
        s = _settings_no_env(DATABASE_SYNC_URL="")
        assert s.DATABASE_SYNC_URL == ""


# ---------------------------------------------------------------------------
# Property-based test
# ---------------------------------------------------------------------------

class TestSettingsFieldIsolation:
    """Property 4: Settings field isolation.

    **Validates: Requirements 1.1, 1.2**

    For any string passed as DATABASE_SYNC_URL env var:
      - settings.DATABASE_SYNC_URL must equal that string exactly
      - settings.DATABASE_URL must remain the asyncpg default
    """

    @given(sync_url=st.text(min_size=0, max_size=256))
    @hyp_settings(max_examples=200, deadline=None)
    def test_field_isolation(self, sync_url: str):
        """DATABASE_SYNC_URL field isolation across arbitrary string inputs."""
        s = _settings_no_env(DATABASE_SYNC_URL=sync_url)
        # The sync URL must be preserved exactly
        assert s.DATABASE_SYNC_URL == sync_url
        # The async URL must be unaffected
        assert s.DATABASE_URL == _ASYNCPG_DEFAULT
