# Design Document: Supabase DB Migration

## Overview

Migrate the cybersec-toolkit's database connection from a local PostgreSQL instance to Supabase (hosted Postgres) without altering any application-level query code. The change touches exactly four files: the settings model, the SQLAlchemy engine factory, the Alembic environment, and the `.env` file.

The guiding principle is strict driver separation: `asyncpg` drives the FastAPI runtime and `psycopg2` drives Alembic migrations. Neither driver is used in the other context.

---

## Architecture

```mermaid
graph TD
    subgraph Runtime ["FastAPI Runtime (asyncpg)"]
        A[settings.DATABASE_URL<br/>postgresql+asyncpg://...] --> B[session.py engine<br/>ssl=require]
        B --> C[async_session_maker]
        C --> D[get_db / async_session_maker<br/>15+ route handlers]
    end

    subgraph Migrations ["Alembic Migrations (psycopg2)"]
        E[settings.DATABASE_SYNC_URL<br/>postgresql+psycopg2://...] --> F[alembic/env.py<br/>set_main_option fallback]
        F --> G[alembic upgrade head]
    end

    subgraph Supabase ["Supabase (hosted Postgres)"]
        H[(Session Pooler<br/>port 5432)]
    end

    B -->|SSL required| H
    G -->|SSL default| H
```

### Connection Routing

| Context | Driver | URL Setting | SSL |
|---|---|---|---|
| FastAPI runtime | asyncpg | `DATABASE_URL` | `connect_args={"ssl": "require"}` |
| Alembic migrations | psycopg2 | `DATABASE_SYNC_URL` | Supabase default (on) |
| Local dev (no sync URL set) | asyncpg | `DATABASE_URL` fallback | via env flag |

---

## Components and Interfaces

### Component 1: Settings (`cybersec/config/settings.py`)

**Purpose**: Expose both async and sync database URLs to consumers. Runtime code reads only `DATABASE_URL`; Alembic reads only `DATABASE_SYNC_URL`.

**Change**: Add one field after `DATABASE_URL`:

```python
DATABASE_SYNC_URL: str = ""  # psycopg2 URL, used only by Alembic
```

**Contract**:
- Empty string default means local dev without `DATABASE_SYNC_URL` set will not break.
- The field is never read by any async code path.

---

### Component 2: Async Engine (`cybersec/database/session.py`)

**Purpose**: Create the SQLAlchemy async engine that all FastAPI route handlers use via `get_db()`.

**Change**: Add `connect_args={"ssl": "require"}` to `create_async_engine(...)`.

```python
engine = create_async_engine(
    settings.DATABASE_URL,
    connect_args={"ssl": "require"},   # ← new
    pool_size=1,
    max_overflow=2,
    pool_pre_ping=True,
    pool_recycle=300,
)
```

**Contract**:
- All sessions vended by `async_session_maker` and `get_db()` inherit this SSL requirement.
- No changes to callers — 15+ files using `get_db` or `async_session_maker` are unaffected.

---

### Component 3: Alembic Environment (`alembic/env.py`)

**Purpose**: Configure the URL Alembic uses to connect and run schema migrations.

**Change**: Line 16 — use sync URL with fallback to async URL if sync URL is unset:

```python
# Before
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

# After
config.set_main_option(
    "sqlalchemy.url",
    settings.DATABASE_SYNC_URL or settings.DATABASE_URL
)
```

**Rationale**: `asyncpg` is an async-only driver and cannot power Alembic's synchronous migration engine. The `psycopg2`-backed sync URL must be used. The `or` fallback preserves backwards-compatibility for local dev environments where `DATABASE_SYNC_URL` is not set.

**Implication for offline mode**: When `DATABASE_SYNC_URL` is set, `run_migrations_offline()` uses the psycopg2 URL. When only `DATABASE_URL` is set (local), it falls back to the asyncpg URL, which works for offline SQL generation (no actual connection needed).

---

### Component 4: Environment Variables (`.env`)

**Purpose**: Provide the runtime-secret values for both URL fields.

**Change**: Add `DATABASE_SYNC_URL` alongside the existing `DATABASE_URL`:

```
# Async URL — used by FastAPI / asyncpg runtime
DATABASE_URL=postgresql+asyncpg://postgres.[PROJECT-REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:5432/postgres

# Sync URL — used only by Alembic / psycopg2
DATABASE_SYNC_URL=postgresql+psycopg2://postgres.[PROJECT-REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:5432/postgres
```

**Port selection**: Port `5432` is the Supabase **session pooler**. Port `6543` is the transaction pooler. Alembic requires persistent connections across a migration run, so the session pooler (5432) must be used for both URLs.

---

## Data Models

No schema changes. The migration applies the existing 8-table schema to the new Supabase database. Tables created:

| Table | Migration file |
|---|---|
| `users` | `2026_4_2_1858-7e75a30307de_initial.py` |
| `scans` | `2026_4_2_1858-7e75a30307de_initial.py` |
| `scan_results` | `2026_4_2_1858-7e75a30307de_initial.py` |
| `tool_results` | `2026_4_2_1858-7e75a30307de_initial.py` |
| `reports` | `2026_4_2_1858-7e75a30307de_initial.py` |
| `nvd_cve_cache` | `2026_4_24_1645-add_nvd_cve_cache.py` |
| `scan_recovery` | `2026_5_15_1200-add_scan_recovery.py` |
| `nvd_service_lookup_cache` | `2026_6_28_1300-add_nvd_service_lookup_cache.py` |

---

## Key Design Decisions

### Two URL Fields — Never Mixing Drivers

`asyncpg` is async-only. `psycopg2` is sync-only. Alembic's migration runner is fundamentally synchronous. Using `asyncpg` with Alembic requires a complex async bridge (`run_async_migrations`) that is fragile in offline mode. The clean solution is a separate `DATABASE_SYNC_URL` that uses `psycopg2`, keeping drivers strictly in their lanes.

### SSL Required on Runtime Engine Only

Supabase requires SSL on all connections. The `connect_args={"ssl": "require"}` argument is added to the `create_async_engine` call in `session.py`. For Alembic, psycopg2 connects to Supabase via the session pooler URL which already includes SSL negotiation by default — no explicit argument needed in `env.py`.

### Alembic Fallback Preserves Local Dev

The expression `settings.DATABASE_SYNC_URL or settings.DATABASE_URL` means:
- **Production / Supabase**: `DATABASE_SYNC_URL` is set → psycopg2 used → migrations succeed.
- **Local dev**: `DATABASE_SYNC_URL` is empty string → falls back to `DATABASE_URL` (asyncpg) → existing behaviour preserved for `alembic revision --autogenerate` and SQL generation.

### No Application Code Changes

The fix is entirely at the connection layer. All 15+ files that import and use `async_session_maker` or `get_db()` will automatically benefit from the corrected SSL engine — zero changes needed in routes, services, or repositories.

### RLS Disabled

Supabase enables Row-Level Security (RLS) on all tables by default. This app uses its own JWT-based auth and does not use Supabase Auth tokens. RLS policies would block every query. RLS must be disabled for all 8 tables via the Supabase SQL editor after running migrations. This is a one-time manual setup step.

### Session Pooler vs Transaction Pooler

Supabase exposes two poolers:
- **Session pooler** (port 5432): maintains a persistent connection per client session — required by Alembic.
- **Transaction pooler** (port 6543): multiplexes connections per transaction — incompatible with Alembic's migration sessions.

Both `DATABASE_URL` and `DATABASE_SYNC_URL` must target port 5432.

---

## One-Time Setup Steps (Manual)

These are not code changes. They must be executed once after deploying the code changes:

1. **Install sync driver**:
   ```
   pip install psycopg2-binary
   ```

2. **Run migrations against Supabase**:
   ```
   alembic upgrade head
   ```

3. **Disable RLS** — run the following in the Supabase SQL editor for each table:
   ```sql
   ALTER TABLE users DISABLE ROW LEVEL SECURITY;
   ALTER TABLE scans DISABLE ROW LEVEL SECURITY;
   ALTER TABLE scan_results DISABLE ROW LEVEL SECURITY;
   ALTER TABLE tool_results DISABLE ROW LEVEL SECURITY;
   ALTER TABLE reports DISABLE ROW LEVEL SECURITY;
   ALTER TABLE nvd_cve_cache DISABLE ROW LEVEL SECURITY;
   ALTER TABLE scan_recovery DISABLE ROW LEVEL SECURITY;
   ALTER TABLE nvd_service_lookup_cache DISABLE ROW LEVEL SECURITY;
   ```

4. **Verify connection** (manual): Start the FastAPI server and confirm the health endpoint returns 200 with a successful DB query.

---

## Error Handling

### SSL Negotiation Failure
**Condition**: `DATABASE_URL` points at Supabase but `connect_args={"ssl": "require"}` is missing.
**Symptom**: `asyncpg.exceptions.InvalidAuthorizationSpecificationError` or `SSL connection required` error on first DB operation.
**Resolution**: Ensure `connect_args={"ssl": "require"}` is present in `create_async_engine`.

### Alembic asyncpg Driver Error
**Condition**: `DATABASE_SYNC_URL` is unset in production and `DATABASE_URL` uses `asyncpg`.
**Symptom**: `alembic upgrade head` fails with `MissingGreenlet` or async context error.
**Resolution**: Set `DATABASE_SYNC_URL` with the `psycopg2` driver URL in `.env`.

### psycopg2 Not Installed
**Condition**: `pip install psycopg2-binary` was not run before `alembic upgrade head`.
**Symptom**: `ModuleNotFoundError: No module named 'psycopg2'`.
**Resolution**: Run `pip install psycopg2-binary`.

### RLS Blocking Queries
**Condition**: Migrations ran but RLS was not disabled.
**Symptom**: All queries return empty results or `permission denied` errors despite valid auth tokens.
**Resolution**: Run the `ALTER TABLE ... DISABLE ROW LEVEL SECURITY` statements above.

---

## Dependencies

| Dependency | Purpose | Action |
|---|---|---|
| `asyncpg` | Async PostgreSQL driver for FastAPI runtime | Already installed |
| `psycopg2-binary` | Sync PostgreSQL driver for Alembic | **Must be installed** |
| `sqlalchemy[asyncio]` | ORM + async engine | Already installed |
| `alembic` | Schema migration tool | Already installed |
| `pydantic-settings` | Settings model with env file support | Already installed |

---

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Async engine always uses SSL

For any instantiation of `create_async_engine` with `settings.DATABASE_URL`, the resulting engine's `connect_args` must include `{"ssl": "require"}`.

**Validates: Requirements 2.1**

### Property 2: Alembic URL resolves to sync driver when sync URL is set

For any non-empty `DATABASE_SYNC_URL`, the value passed to `config.set_main_option("sqlalchemy.url", ...)` must use the `postgresql+psycopg2://` scheme.

**Validates: Requirements 3.1**

### Property 3: Alembic URL falls back gracefully when sync URL is absent

For any empty `DATABASE_SYNC_URL`, the value passed to `config.set_main_option("sqlalchemy.url", ...)` must equal `settings.DATABASE_URL`.

**Validates: Requirements 3.2**

### Property 4: Settings field isolation

For any `Settings` instance, `DATABASE_SYNC_URL` defaults to an empty string when not provided in the environment, and `DATABASE_URL` retains its asyncpg default — neither field influences the other.

**Validates: Requirements 1.1, 1.2**
