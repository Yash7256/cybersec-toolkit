# Requirements Document

## Introduction

This document specifies the requirements for migrating the cybersec-toolkit application's database connection from a local PostgreSQL instance to Supabase (hosted Postgres). The migration involves four targeted code changes and three one-time manual setup steps. No application-level query code changes are required.

## Glossary

- **Settings**: The `Settings` Pydantic model in `cybersec/config/settings.py` that loads all application configuration from environment variables.
- **Async Engine**: The SQLAlchemy `AsyncEngine` created in `cybersec/database/session.py` using `create_async_engine`, consumed by all FastAPI route handlers via `get_db()`.
- **Alembic Environment**: The `alembic/env.py` file that configures the database URL and migration execution strategy for Alembic.
- **DATABASE_URL**: The asyncpg-scheme connection URL used by the FastAPI async runtime (`postgresql+asyncpg://...`).
- **DATABASE_SYNC_URL**: The psycopg2-scheme connection URL used exclusively by Alembic for synchronous migrations (`postgresql+psycopg2://...`).
- **Session Pooler**: The Supabase connection pooler endpoint on port 5432, which maintains persistent connections — required for Alembic.
- **RLS**: Row-Level Security, a Supabase feature that must be disabled for all application tables since the app uses its own JWT-based auth.

## Requirements

### Requirement 1: Add DATABASE_SYNC_URL Setting

**User Story:** As a developer, I want a dedicated sync database URL setting, so that Alembic can use a psycopg2 driver without interfering with the async runtime URL.

#### Acceptance Criteria

1. THE Settings SHALL expose a `DATABASE_SYNC_URL` field of type `str` with a default value of `""` (empty string).
2. THE Settings SHALL continue to expose `DATABASE_URL` with its existing default of `"postgresql+asyncpg://postgres:postgres@localhost:5432/cybersec"`, unchanged by this addition.
3. WHEN `DATABASE_SYNC_URL` is not present in the environment, THE Settings SHALL return `""` for that field without raising a validation error.
4. WHEN `DATABASE_SYNC_URL` is set in the environment, THE Settings SHALL return its value exactly as provided.

---

### Requirement 2: Require SSL on the Async Engine

**User Story:** As a developer, I want the SQLAlchemy async engine to enforce SSL, so that connections to Supabase are not rejected for missing SSL negotiation.

#### Acceptance Criteria

1. WHEN `create_async_engine` is called in `cybersec/database/session.py`, THE Async Engine SHALL be created with `connect_args={"ssl": "require"}`.
2. THE Async Engine SHALL retain all existing pool configuration: `pool_size=1`, `max_overflow=2`, `pool_pre_ping=True`, `pool_recycle=300`.
3. THE `get_db()` dependency and `async_session_maker` SHALL remain unchanged in signature and behaviour — no callers require modification.

---

### Requirement 3: Configure Alembic to Use Sync URL with Async Fallback

**User Story:** As a developer, I want Alembic to use the psycopg2 sync URL when available, so that migrations succeed against Supabase, while still working locally when only the asyncpg URL is set.

#### Acceptance Criteria

1. WHEN `settings.DATABASE_SYNC_URL` is non-empty, THE Alembic Environment SHALL set `sqlalchemy.url` to `settings.DATABASE_SYNC_URL` (a `postgresql+psycopg2://` URL).
2. WHEN `settings.DATABASE_SYNC_URL` is empty, THE Alembic Environment SHALL set `sqlalchemy.url` to `settings.DATABASE_URL` as a fallback, preserving existing local-dev behaviour.
3. THE Alembic Environment SHALL implement this via the expression `settings.DATABASE_SYNC_URL or settings.DATABASE_URL` on the single `config.set_main_option` call at module level (line 16).
4. THE `run_migrations_offline()` and `run_migrations_online()` functions SHALL remain structurally unchanged — only the URL source changes.

---

### Requirement 4: Add DATABASE_SYNC_URL to Environment File

**User Story:** As a developer, I want the `.env` file to include the psycopg2 sync URL, so that Alembic can read it at migration time without manual intervention.

#### Acceptance Criteria

1. THE `.env` file SHALL contain a `DATABASE_SYNC_URL` entry using the `postgresql+psycopg2://` scheme.
2. THE `DATABASE_SYNC_URL` entry SHALL target the Supabase session pooler on port `5432` (not the transaction pooler on port 6543).
3. WHEN the `DATABASE_URL` entry already exists in `.env`, THE `.env` file SHALL retain it unchanged alongside the new `DATABASE_SYNC_URL` entry.

---

### Requirement 5: Document One-Time Setup Steps

**User Story:** As a developer performing the migration, I want the setup steps documented, so that I can complete the migration without missing a required manual action.

#### Acceptance Criteria

1. THE design document SHALL document the `pip install psycopg2-binary` step as required before running migrations.
2. THE design document SHALL document `alembic upgrade head` as the command to create all 8 tables on Supabase.
3. THE design document SHALL document the SQL statements required to disable RLS on all 8 application tables via the Supabase dashboard.
4. THE design document SHALL document the port selection rationale: session pooler (port 5432) for both URLs because Alembic requires persistent connections.
