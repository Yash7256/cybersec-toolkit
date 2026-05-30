<div align="center">

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗█████╗  ██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║███████╗╚██████╗
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝
```

**Async network security toolkit. Port scanning, CVE detection, AI analysis — all in one.**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-2.0-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white)](https://postgresql.org)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D?style=flat-square&logo=redis&logoColor=white)](https://redis.io)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)

</div>

---

## What is this?

CyberSec is a full-stack async network security platform. You point it at a target — it scans ports, fingerprints services, pulls live CVE data, detects technologies, maps MITRE ATT&CK techniques, and runs AI-powered analysis, all streamed live over SSE.

Comes with a REST API, a CLI, a React dashboard, and a Prometheus metrics endpoint. Runs in Docker with one command. Has Alembic migrations, a real test suite, and a worker reaper that recovers stale scans on restart.

Not a wrapper around nmap. Not a tutorial project.

---

## Architecture

<div align="center">

![Architecture](https://raw.githubusercontent.com/Yash7256/cybersec-toolkit/main/data/architecture.svg)

</div>

> Save `data/architecture.svg` from this repo for the diagram to render above.

```
┌────────────────────────────────────────────────────────────────────┐
│  CLIENT LAYER                                                      │
│   React Dashboard (Vite)  │  CLI (Click+Rich)  │  REST / SSE API  │
└───────────────┬────────────┴────────┬───────────┴──────┬───────────┘
                ▼                     ▼                   ▼
┌────────────────────────────────────────────────────────────────────┐
│  FASTAPI v2.0 — /api/auth · /api/scans · /api/tools               │
│                /api/ai · /api/reports · /api/webapp · /api/metrics │
│  SlowAPI 100 req/min · JWT auth · CORS · Prometheus scrape         │
└──────┬─────────────────────────┬───────────────────┬──────────────┘
       ▼                         ▼                   ▼
┌──────────────┐     ┌──────────────────┐   ┌─────────────────────┐
│ SCAN ENGINE  │     │  TOOLS ENGINE    │   │  AI INTEGRATION     │
│              │     │                  │   │                     │
│ 8 scan modes │     │ DNS/WHOIS/Ping   │   │ Groq llama3-8b      │
│ AIMD concurr │     │ Traceroute/GeoIP │   │ Gemini fallback     │
│ TokenBucket  │     │ SSL/TLS audit    │   │ Rule-based fallback │
│ CVE lookup   │     │ HTTP headers     │   │ SSE streaming       │
│ OS fingerpr. │     │ Subdomain enum   │   │ Context builder     │
│ Banner grab  │     │ Tech detection   │   │ Key rotation mgr    │
│ MITRE map    │     │ Webapp scanner   │   │ Auto report gen     │
└──────┬───────┘     └────────┬─────────┘   └──────────┬──────────┘
       └──────────────────────┼────────────────────────┘
                              ▼
        ┌─────────────────────────────────────────┐
        │  DATA LAYER                             │
        │  PostgreSQL 16 (asyncpg + Alembic)      │
        │  Redis 7 (task queues)                  │
        │  SQLAlchemy async sessions              │
        │                                         │
        │  RUNTIME                                │
        │  scan_workers (asyncio task pool)        │
        │  worker heartbeat + stale scan reaper   │
        └─────────────────────────────────────────┘
```

---

## Scan Modes

| Mode | `scan_type` value | Root? | How it works |
|------|:-----------------:|:-----:|--------------|
| TCP Connect | `connect` | No | Full 3-way handshake. Reliable, logged by target. |
| SYN Stealth | `syn` | Yes | Half-open — RST after SYN-ACK. Less likely to appear in logs. |
| UDP | `udp` | Yes | Probes UDP ports. Slower; critical for DNS/SNMP discovery. |
| FIN | `stealth_fin` | Yes | FIN with no prior session. Some firewalls let it through. |
| NULL | `null` | Yes | No TCP flags. Closed ports respond RST per RFC. |
| XMAS | `xmas` | Yes | FIN + PSH + URG set. Evades some stateless packet filters. |
| ACK | `ack` | Yes | Firewall mapping — determines filtered vs. unfiltered ports. |
| Zombie | `zombie` | Yes | Uses a third-party idle host to mask your source IP. |

**Rate presets**

| Preset | Rate | Burst | Use case |
|--------|------|-------|----------|
| `stealth` | 100 pps | 50 | IDS evasion, slow recon |
| `normal` | 1,000 pps | 100 | Default |
| `aggressive` | 5,000 pps | 500 | Fast scans on permissive networks |

---

## Per-Port Output

Every open port comes back with a full threat picture — not just "port 80: open":

```json
{
  "port_number": 443,
  "service": "HTTPS",
  "version": "nginx/1.24.0",
  "raw_banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0...",
  "technologies": ["nginx", "TLS 1.3", "React"],
  "risk_level": "MEDIUM",
  "risk_reason": "HTTP exposed without redirect to HTTPS on port 80",
  "cve_result": {
    "total_count": 3,
    "critical_count": 0,
    "high_count": 1,
    "cves": [
      {
        "cve_id": "CVE-2023-44487",
        "description": "HTTP/2 Rapid Reset Attack",
        "severity": "HIGH",
        "cvss_score": 7.5
      }
    ]
  },
  "mitre_attack": [
    { "technique": "T1190", "name": "Exploit Public-Facing Application" },
    { "technique": "T1595", "name": "Active Scanning" }
  ],
  "misconfigurations": ["Missing HSTS header", "X-Frame-Options not set"],
  "recommendation": "Enable HSTS, set X-Frame-Options, patch nginx to 1.25+",
  "recommendation_priority": "HIGH",
  "exposure_severity": { "internet_facing": true, "severity": "HIGH" },
  "tls": { "cert_expiry": "2025-09-01", "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384" }
}
```

---

## API Reference

| Category | Endpoint | Method | Description |
|----------|----------|:------:|-------------|
| **Auth** | `/api/auth/register` | POST | Register new user |
| | `/api/auth/login` | POST | Get JWT token |
| **Scans** | `/api/scans/` | POST | Start a port scan |
| | `/api/scans/{id}` | GET | Results as JSON / CSV / HTML |
| | `/api/scans/{id}/status` | GET | Poll progress |
| | `/api/scans/{id}/stream` | GET | SSE live results stream |
| | `/api/scans/multi-host` | POST | Scan multiple hosts / CIDR range |
| | `/api/scans/os-fingerprint` | POST | OS fingerprint only |
| **Tools** | `/api/tools/dns` | POST | DNS lookup (A/MX/TXT/ALL) |
| | `/api/tools/whois` | POST | WHOIS record |
| | `/api/tools/ping` | POST | ICMP ping with stats |
| | `/api/tools/traceroute` | POST | Hop-by-hop traceroute |
| | `/api/tools/ssl` | POST | TLS cert + cipher audit |
| | `/api/tools/headers` | POST | HTTP security headers check |
| | `/api/tools/subdomains` | POST | Subdomain enumeration |
| | `/api/tools/geoip` | POST | IP geolocation |
| | `/api/tools/os-fingerprint` | POST | Passive + active OS detection |
| **AI** | `/api/ai/chat` | POST | Chat with scan/tool context |
| | `/api/ai/analyze` | POST | Auto-generate security report |
| **Reports** | `/api/reports/{id}` | GET | Export as JSON / CSV / PDF |
| **WebApp** | `/api/webapp/scan` | POST | Web app vulnerability scan |
| **Ops** | `/api/health` | GET | Health check |
| | `/api/metrics` | GET | Prometheus scrape endpoint |

Interactive Swagger UI at `http://localhost:8000/docs` · ReDoc at `/redoc`

---

## Quick Start

### Docker (recommended)

```bash
git clone https://github.com/Yash7256/cybersec-toolkit
cd cybersec-toolkit
cp .env.example .env        # add GROQ_API_KEY (optional)
docker compose up --build
```

`http://localhost:8000` — API docs at `/docs`

The Docker image sets kernel-level TCP tuning automatically:
```yaml
sysctls:
  - net.ipv4.ip_local_port_range=10000 65535
  - net.ipv4.tcp_fin_timeout=15
  - net.ipv4.tcp_tw_reuse=1
  - net.core.somaxconn=65535
```

### Local dev

```bash
# Backend
poetry install
docker compose up -d postgres redis
alembic upgrade head
uvicorn cybersec.apps.api.main:app --reload --port 8000

# Frontend (separate terminal)
cd cybersec/web/ui
npm install && npm run dev       # → http://localhost:5173, proxies /api to :8000
```

---

## CLI Usage

The CLI calls the scanner core directly — no server required.

```bash
# Scanning
cybersec scan run example.com
cybersec scan run 192.168.1.1 --ports 1-1000 --scan-mode syn --rate aggressive
cybersec scan run 192.168.1.0/24 --ports common --rate stealth
cybersec scan run example.com --ports 80,443,8080 --output json --save-file
cybersec scan history --limit 20
cybersec scan show <scan-id>

# Network tools
cybersec tools dns google.com --type ALL
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
```

---

## Environment Variables

```bash
# Required
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/cybersec
APP_SECRET_KEY=change-this-in-production

# AI (optional — falls back to rule-based analysis without keys)
GROQ_API_KEY=gsk_...
GROQ_MODEL=llama3-8b-8192

# Scanner tuning
SCANNER_DEFAULT_CONCURRENCY=500
SCANNER_DEFAULT_TIMEOUT=3.0
SCAN_TIMEOUT=10.0
OS_FINGERPRINT_TIMEOUT=5.0
SERVICE_DETECTION_TIMEOUT=8.0
MAX_SCAN_RESULTS=10000

# Auth
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60

# Redis
REDIS_URL=redis://localhost:6379/0

# CORS
CORS_ORIGINS=*
```

---

## Testing

```bash
make test-unit          # unit tests only
make test-integration   # integration tests only
make test-all           # full suite, verbose
make coverage           # HTML coverage report → htmlcov/index.html
make test-watch         # re-run on file change
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| API | FastAPI 2.0 + Uvicorn |
| Async DB | SQLAlchemy async + asyncpg + PostgreSQL 16 |
| Migrations | Alembic |
| Scanner | Pure asyncio — zero nmap dependency |
| AI | Groq SDK (llama3-8b) + Gemini + rule-based fallback |
| Auth | JWT via python-jose + bcrypt |
| Rate limiting | SlowAPI (API) + TokenBucket (per-scan) |
| Reports | reportlab (PDF) + stdlib csv/json |
| CLI | Click + Rich |
| Frontend | React 18 + Vite + Tailwind CSS v4 |
| Observability | Prometheus-compatible `/api/metrics` |
| Containers | Docker + docker-compose (postgres:16-alpine, redis:7-alpine) |
| Recovery | PostgreSQL-backed worker heartbeat + stale scan reaper |

---

## Security Notes

- Private IP ranges blocked by default in scanner core
- DNS rebinding protection built in
- All scan endpoints require JWT
- API rate-limited at 100 req/min per IP
- SYN/UDP/stealth modes require `CAP_NET_RAW` (root or Docker `--privileged`)
- Zombie scan requires explicit `--zombie-ip` flag
- GROQ_API_KEY supports multi-key rotation via `GroqKeyManager`

---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">
Built by <a href="https://github.com/Yash7256">Aman Raj</a> &nbsp;·&nbsp; <a href="https://amanraj.codes">amanraj.codes</a> &nbsp;·&nbsp; <a href="https://linkedin.com/in/aman-raj-8571aa291">LinkedIn</a>
</div>
