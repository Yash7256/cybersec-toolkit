# Implementation Plan: Supabase DB Migration

## Overview

Four targeted file changes connect the cybersec-toolkit to Supabase. Tasks map one-to-one with files. No application query code changes are needed — all 15+ files using `get_db` or `async_session_maker` inherit the fix automatically.

## Tasks

- [x] 1. Add `DATABASE_SYNC_URL` field to Settings
  - In `cybersec/config/settings.py`, add the following line directly after the `DATABASE_URL` field:
    ```python
    DATABASE_SYNC_URL: str = ""  # psycopg2 URL used only by Alembic migrations
    ```
  - Do not change any other field or default value.
  - _Requirements: 1.1, 1.2, 1.3, 1.4_

  - [x] 1.1 Write unit tests for Settings DATABASE_SYNC_URL field
    - Test that `Settings()` with no env returns `DATABASE_SYNC_URL == ""`
    - Test that `Settings()` with no env still returns the correct asyncpg default for `DATABASE_URL`
    - **Property 4: Settings field isolation** — for any string passed as `DATABASE_SYNC_URL` env var, `settings.DATABASE_SYNC_URL` must equal that string exactly
    - **Validates: Requirements 1.1, 1.2, 1.4**

- [x] 2. Add SSL requirement to the async engine in `session.py`
  - In `cybersec/database/session.py`, add `connect_args={"ssl": "require"}` as the second argument to `create_async_engine(...)`, after `settings.DATABASE_URL`:
    ```python
    engine = create_async_engine(
        settings.DATABASE_URL,
        connect_args={"ssl": "require"},   # ← add this line
        pool_size=1,
        max_overflow=2,
        pool_pre_ping=True,
        pool_recycle=300,
    )
    ```
  - Do not change `async_session_maker`, `get_db`, or `init_db`.
  - _Requirements: 2.1, 2.2, 2.3_

  - [x] 2.1 Write unit tests for async engine SSL configuration
    - Test that the engine's `dialect.create_connect_args` or `connect_args` contains `ssl: "require"`
    - Test that pool configuration values are unchanged (`pool_size`, `max_overflow`, `pool_pre_ping`, `pool_recycle`)
    - **Property 1: Async engine always uses SSL** — for any engine created from `session.py`, `connect_args` must include `{"ssl": "require"}`
    - **Validates: Requirements 2.1, 2.2**

- [x] 3. Update `alembic/env.py` to use sync URL with async fallback
  - In `alembic/env.py`, change line 16 from:
    ```python
    config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)
    ```
    to:
    ```python
    config.set_main_option(
        "sqlalchemy.url",
        settings.DATABASE_SYNC_URL or settings.DATABASE_URL
    )
    ```
  - Do not change any other part of `env.py`.
  - _Requirements: 3.1, 3.2, 3.3, 3.4_

  - [x] 3.1 Write unit tests for Alembic URL resolution logic
    - Test that when `DATABASE_SYNC_URL` is non-empty, the value passed to `set_main_option` is the sync URL (psycopg2 scheme)
    - Test that when `DATABASE_SYNC_URL` is `""`, the value passed to `set_main_option` is `DATABASE_URL` (asyncpg scheme)
    - **Property 2: Alembic URL resolves to sync driver when sync URL is set**
    - **Property 3: Alembic URL falls back gracefully when sync URL is absent**
    - **Validates: Requirements 3.1, 3.2**

- [x] 4. Checkpoint — ensure all tests pass
  - Run the test suite and confirm no regressions from the three code changes above.
  - Ask the user if any questions arise before proceeding to the `.env` change.

- [x] 5. Add `DATABASE_SYNC_URL` to `.env`
  - Open `.env` and add the following line below the existing `DATABASE_URL` line:
    ```
    DATABASE_SYNC_URL=postgresql+psycopg2://postgres.[PROJECT-REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:5432/postgres
    ```
  - Replace `[PROJECT-REF]`, `[PASSWORD]`, and `[REGION]` with the actual Supabase project values.
  - Verify the existing `DATABASE_URL` line is unchanged and still uses `postgresql+asyncpg://`.
  - Verify both URLs target port `5432` (session pooler), not `6543`.
  - _Requirements: 4.1, 4.2, 4.3_

- [x] 6. Final checkpoint — confirm configuration is complete
  - `psycopg2-binary` installed (2.9.12)
  - `alembic upgrade head` ran — schema is at `add_nvd_service_lookup_cache (head)`
  - Async connection verified: `SELECT 1` returns 1 against Supabase
  - Remaining manual step: run `disable_rls.sql` in the Supabase SQL editor

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster rollout.
- Tasks 1–3 are pure code changes with no runtime side effects until the app is restarted.
- Task 5 (`.env`) contains secrets — do not commit `.env` to version control.
- The one-time setup steps in Task 6 must be done after the code changes are deployed; they are not automated.
- Property tests validate universal correctness; unit tests cover specific examples and defaults.
