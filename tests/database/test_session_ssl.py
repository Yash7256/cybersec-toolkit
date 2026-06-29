"""
Unit and property-based tests for async engine SSL configuration.

Validates: Requirements 2.1, 2.2

Coverage:
  - engine connect_args contains {"ssl": "require"}  (Req 2.1)
  - engine pool configuration is unchanged  (Req 2.2)
  - Property 1: Async engine always uses SSL — for any engine created from
    session.py, connect_args must include {"ssl": "require"}  (Req 2.1)
"""
import pytest
from unittest.mock import patch, MagicMock
from hypothesis import given, settings as hyp_settings
from hypothesis import strategies as st


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_engine(database_url: str):
    """Create an async engine using the same call as session.py,
    but with a caller-supplied URL (avoids loading real .env).

    Returns the captured kwargs passed to create_async_engine so tests can
    inspect connect_args and pool configuration without making a real
    DB connection.
    """
    from sqlalchemy.ext.asyncio import create_async_engine
    captured = {}

    original_create = create_async_engine.__wrapped__ if hasattr(
        create_async_engine, "__wrapped__"
    ) else None

    def fake_create_async_engine(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        # Return a lightweight mock — we only need the creation args
        return MagicMock()

    with patch(
        "cybersec.database.session.create_async_engine",
        side_effect=fake_create_async_engine,
    ):
        # Re-execute just the engine-creation portion by importing fresh
        import importlib
        import cybersec.database.session as session_mod
        with patch("cybersec.config.settings.DATABASE_URL", database_url, create=True):
            # Trigger a fresh engine creation call matching session.py
            from sqlalchemy.ext.asyncio import create_async_engine as real_cae
            fake_create_async_engine(
                database_url,
                connect_args={"ssl": "require"},
                pool_size=1,
                max_overflow=2,
                pool_pre_ping=True,
                pool_recycle=300,
            )

    return captured


# ---------------------------------------------------------------------------
# Unit tests — SSL connect_args (Req 2.1)
# ---------------------------------------------------------------------------

class TestEngineSSLConnectArgs:
    """Req 2.1 — connect_args must include ssl: 'require'."""

    def test_engine_has_connect_args_ssl_require(self):
        """The module-level engine must be created with connect_args={"ssl": "require"}."""
        # Inspect the live engine object created at module import time.
        # SQLAlchemy stores connect_args on the dialect's creator / pool.
        # The most reliable cross-version approach is to inspect the engine's
        # dialect._connect_args or the engine's pool._creator closure, but
        # the cleanest is to patch create_async_engine at import and capture.
        captured_kwargs = {}

        def fake_create(url, **kwargs):
            captured_kwargs.update(kwargs)
            return MagicMock()

        with patch("sqlalchemy.ext.asyncio.create_async_engine", side_effect=fake_create):
            import importlib
            import cybersec.database.session
            importlib.reload(cybersec.database.session)

        assert "connect_args" in captured_kwargs, (
            "create_async_engine was not called with connect_args"
        )
        assert captured_kwargs["connect_args"] == {"ssl": "require"}, (
            f"Expected connect_args={{'ssl': 'require'}}, got {captured_kwargs['connect_args']}"
        )

    def test_connect_args_ssl_value_is_string_require(self):
        """ssl value must be the string 'require', not a boolean or other type."""
        captured_kwargs = {}

        def fake_create(url, **kwargs):
            captured_kwargs.update(kwargs)
            return MagicMock()

        with patch("sqlalchemy.ext.asyncio.create_async_engine", side_effect=fake_create):
            import importlib
            import cybersec.database.session
            importlib.reload(cybersec.database.session)

        ssl_value = captured_kwargs.get("connect_args", {}).get("ssl")
        assert ssl_value == "require", (
            f"ssl must be the string 'require', got {ssl_value!r}"
        )

    def test_connect_args_contains_only_ssl_key(self):
        """connect_args should be exactly {"ssl": "require"} — no extra keys."""
        captured_kwargs = {}

        def fake_create(url, **kwargs):
            captured_kwargs.update(kwargs)
            return MagicMock()

        with patch("sqlalchemy.ext.asyncio.create_async_engine", side_effect=fake_create):
            import importlib
            import cybersec.database.session
            importlib.reload(cybersec.database.session)

        connect_args = captured_kwargs.get("connect_args", {})
        assert set(connect_args.keys()) == {"ssl"}, (
            f"connect_args has unexpected keys: {set(connect_args.keys())}"
        )


# ---------------------------------------------------------------------------
# Unit tests — pool configuration (Req 2.2)
# ---------------------------------------------------------------------------

class TestEnginePoolConfiguration:
    """Req 2.2 — pool settings must remain at their specified values."""

    def _capture_engine_kwargs(self):
        captured_kwargs = {}

        def fake_create(url, **kwargs):
            captured_kwargs.update(kwargs)
            return MagicMock()

        with patch("sqlalchemy.ext.asyncio.create_async_engine", side_effect=fake_create):
            import importlib
            import cybersec.database.session
            importlib.reload(cybersec.database.session)

        return captured_kwargs

    def test_pool_size_is_one(self):
        """pool_size must be 1."""
        kwargs = self._capture_engine_kwargs()
        assert kwargs.get("pool_size") == 1, (
            f"Expected pool_size=1, got {kwargs.get('pool_size')}"
        )

    def test_max_overflow_is_two(self):
        """max_overflow must be 2."""
        kwargs = self._capture_engine_kwargs()
        assert kwargs.get("max_overflow") == 2, (
            f"Expected max_overflow=2, got {kwargs.get('max_overflow')}"
        )

    def test_pool_pre_ping_is_true(self):
        """pool_pre_ping must be True."""
        kwargs = self._capture_engine_kwargs()
        assert kwargs.get("pool_pre_ping") is True, (
            f"Expected pool_pre_ping=True, got {kwargs.get('pool_pre_ping')}"
        )

    def test_pool_recycle_is_300(self):
        """pool_recycle must be 300 (5 minutes)."""
        kwargs = self._capture_engine_kwargs()
        assert kwargs.get("pool_recycle") == 300, (
            f"Expected pool_recycle=300, got {kwargs.get('pool_recycle')}"
        )

    def test_all_pool_settings_present(self):
        """All four pool settings must be explicitly specified."""
        kwargs = self._capture_engine_kwargs()
        expected_pool_keys = {"pool_size", "max_overflow", "pool_pre_ping", "pool_recycle"}
        missing = expected_pool_keys - set(kwargs.keys())
        assert not missing, f"Missing pool settings: {missing}"


# ---------------------------------------------------------------------------
# Property-based test
# ---------------------------------------------------------------------------

class TestEngineAlwaysUsesSSL:
    """Property 1: Async engine always uses SSL.

    **Validates: Requirements 2.1**

    For any URL string passed as DATABASE_URL, when session.py's
    create_async_engine is called, connect_args must include {"ssl": "require"}.
    """

    @given(
        database_url=st.from_regex(
            r"postgresql\+asyncpg://[a-z]{1,10}:[a-z]{1,10}@[a-z]{1,20}(:[0-9]{4,5})?/[a-z]{1,10}",
            fullmatch=True,
        )
    )
    @hyp_settings(max_examples=50, deadline=None)
    def test_ssl_required_for_any_url(self, database_url: str):
        """SSL connect_args must be present regardless of the DATABASE_URL value.

        **Validates: Requirements 2.1**
        """
        captured_kwargs = {}

        def fake_create(url, **kwargs):
            captured_kwargs["url"] = url
            captured_kwargs["kwargs"] = kwargs
            return MagicMock()

        with patch("sqlalchemy.ext.asyncio.create_async_engine", side_effect=fake_create), \
             patch("cybersec.config.settings.DATABASE_URL", database_url, create=True):
            import importlib
            import cybersec.database.session
            importlib.reload(cybersec.database.session)

        assert captured_kwargs["kwargs"].get("connect_args") == {"ssl": "require"}, (
            f"Expected connect_args={{'ssl': 'require'}} for URL {database_url!r}, "
            f"got {captured_kwargs['kwargs'].get('connect_args')!r}"
        )
