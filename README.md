# Cybersec

A security analysis and automation tool built with Python, FastAPI, and PostgreSQL.

## Quick Start

```bash
# Install dependencies
poetry install

# Set up environment
cp .env.example .env
# Edit .env with your configuration

# Start services
docker-compose up -d

# Run migrations
poetry run alembic upgrade head

# Start the API
poetry run uvicorn cybersec.api.main:create_app --factory

# Run CLI
poetry run cybersec --help
```

## Development

```bash
# Run tests
poetry run pytest

# Format code
poetry run black cybersec tests
poetry run ruff check cybersec tests
```
# cybersec-new
