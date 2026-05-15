#!/bin/sh
set -e

echo "Running database migrations..."
poetry run alembic upgrade head 2>/dev/null || \
    python -c "import asyncio; from cybersec.database.session import init_db; asyncio.run(init_db())" 2>/dev/null || \
    echo "Warning: DB migration skipped (will retry on first request)"

echo "Starting CyberSec..."
exec "$@"
