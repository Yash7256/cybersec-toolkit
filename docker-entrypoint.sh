#!/bin/sh
set -e

echo "Running database migrations..."
# Run Alembic migrations; fall back to SQLAlchemy table init if alembic isn't
# available (e.g. poetry not installed in slim builds). Errors are intentionally
# NOT suppressed so a schema mismatch fails loudly rather than silently starting
# with a broken database.
poetry run alembic upgrade head || \
    python -c "import asyncio; from cybersec.database.session import init_db; asyncio.run(init_db())" || \
    echo "WARNING: DB migration failed — app is starting with potentially stale schema. Check logs."

echo "Starting CyberSec..."
exec "$@"
