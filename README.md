# ⚡ CyberSec — Async Network Security Toolkit

A full-stack async network security toolkit built with FastAPI, React, and Click.  
Port scanning, web app vulnerability detection, OS fingerprinting, AI-powered analysis, and rich reporting — all in one.

---

## Quick Start — Docker (recommended)

```bash
git clone <your-repo-url> cybersec
cd cybersec/cybersec-new

cp .env.example .env
# Edit .env and add your GROQ_API_KEY

docker-compose up --build
```

Open **http://localhost:8000** in your browser.  
API docs: **http://localhost:8000/docs**

---

## Quick Start — Local Development

### Backend

```bash
cd cybersec-new

# Install dependencies
poetry install

# Copy and configure environment
cp .env.example .env

# Start postgres only
docker-compose up -d postgres

# Run database migrations
alembic upgrade head

# Start the API server (hot-reload)
uvicorn cybersec.api.main:app --reload --port 8000
```

### Frontend (separate terminal)

```bash
cd cybersec-frontend
npm install
npm run dev          # → http://localhost:5173 (proxies /api to :8000)
```

To rebuild and serve the frontend from FastAPI:

```bash
cd cybersec-frontend
npm run build
cp -r dist/* ../cybersec-new/cybersec/web/static/
```

---

## CLI Usage

The `cybersec` CLI calls the scanner engine directly — no HTTP server required.

```bash
# Port scanning
cybersec scan run example.com --ports common --output table
cybersec scan run 192.168.1.1 --ports 1-1000 --timeout 2.0 --save
cybersec scan run 10.0.0.1 --ports 80,443,8080 --output json
cybersec scan history --limit 20
cybersec scan show <scan-id>

# Network Tools
cybersec tools dns google.com --type ALL
cybersec tools dns github.com --type MX
cybersec tools whois example.com
cybersec tools ping 8.8.8.8 --count 5
cybersec tools traceroute example.com --max-hops 20
cybersec tools ssl github.com --port 443
cybersec tools headers https://example.com
cybersec tools subdomains example.com --size medium
cybersec tools geo 8.8.8.8

# Help
cybersec --help
cybersec scan --help
cybersec tools --help
cybersec --version
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://postgres:postgres@localhost:5432/cybersec` | Async PostgreSQL connection string |
| `APP_SECRET_KEY` | `change-this-in-production` | JWT signing secret — **change in production** |
| `APP_NAME` | `CyberSec` | Application display name |
| `APP_DEBUG` | `false` | Enable debug mode (`true`/`false`) |
| `APP_VERSION` | `1.0.0` | Application version string |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | JWT token lifetime in minutes |
| `GROQ_API_KEY` | *(empty)* | Groq API key for AI analysis (optional) |
| `GROQ_MODEL` | `llama3-8b-8192` | Groq model identifier |
| `CORS_ORIGINS` | `*` | Comma-separated allowed CORS origins |
| `DATABASE_POOL_SIZE` | `10` | SQLAlchemy connection pool size |
| `DATABASE_MAX_OVERFLOW` | `20` | SQLAlchemy max connection overflow |
| `SCANNER_DEFAULT_CONCURRENCY` | `500` | Default port scan concurrency |
| `SCANNER_DEFAULT_TIMEOUT` | `3.0` | Default port scan timeout (seconds) |
| `SCANNER_COMMON_PORTS` | *(built-in list)* | Override common ports list |
| `MAX_SCAN_RESULTS` | `10000` | Maximum results stored per scan |

---

## API Reference

Interactive API docs available at **http://localhost:8000/docs** (Swagger UI).

| Category | Base Path | Description |
|----------|-----------|-------------|
| Auth | `/api/auth/` | Register, login, JWT endpoints |
| Scans | `/api/scans/` | Create/stream port scans, SSE, OS fingerprint |
| Tools | `/api/tools/` | DNS, WHOIS, Ping, Traceroute, SSL, Headers, Subdomains, GeoIP |
| AI | `/api/ai/` | Chat (SSE streaming), analyze scan results |
| Reports | `/api/reports/` | Export scan reports as JSON, CSV, or PDF |
| Web App | `/api/webapp/` | Web application vulnerability scanner |
| Health | `/api/health` | Server health check |

---

## Architecture Overview

```
cybersec-new/
├── cybersec/
│   ├── api/               # FastAPI routers (auth, scans, tools, ai, reports, webapp)
│   │   ├── routers/
│   │   └── schemas/
│   ├── cli/               # Click CLI (calls core directly)
│   │   └── main.py
│   ├── core/              # Business logic (no FastAPI deps)
│   │   ├── scanner.py     # Async port scanner (asyncio)
│   │   ├── service_detect.py
│   │   ├── cve_lookup.py
│   │   ├── port_analyzer.py
│   │   ├── os_fingerprint.py
│   │   ├── ai/            # Groq client, prompts, context builder
│   │   └── tools/         # dns, whois, ping, traceroute, ssl, http_headers, subdomain, geoip
│   ├── database/          # SQLAlchemy models, session, base
│   └── web/static/        # Built React frontend served by FastAPI
├── cybersec-frontend/     # React + Vite + Tailwind source
├── alembic/               # Database migrations
├── Dockerfile
├── docker-compose.yml
└── pyproject.toml
```

**Stack:**
- **Backend**: FastAPI + SQLAlchemy (async) + PostgreSQL + asyncpg
- **AI**: Groq SDK with SSE streaming
- **Frontend**: React 18 + Vite + Tailwind CSS v4 + FontAwesome
- **CLI**: Click + Rich
- **Scanner**: Pure asyncio TCP scanning with service detection and CVE mapping
- **Auth**: JWT (python-jose) + bcrypt password hashing
- **Reports**: reportlab (PDF), stdlib csv/json

---

## Known Issues Resolved

All 8 issues from the original PRD have been resolved:

| # | Issue | Status |
|---|-------|--------|
| 1 | Scan progress hardcoded at 50% | ✅ Real counter-based progress |
| 2 | SSE streaming endpoint missing | ✅ `/api/scans/{id}/stream` implemented |
| 3 | Frontend navigation conflict (switchTab) | ✅ Eliminated — React state, no global functions |
| 4 | Tool results not saved to DB | ✅ Every tool endpoint creates ToolResult row |
| 5 | Web app scanner endpoint missing | ✅ `POST /api/webapp/scan` implemented |
| 6 | OS fingerprint endpoint missing | ✅ `POST /api/scans/os-fingerprint` implemented |
| 7 | progress_pct derived from real counter | ✅ Calculated from actual scanned/total ratio |
| 8 | Subdomain tool sequential | ✅ Uses `asyncio.gather()` concurrently |

---

## License

MIT
