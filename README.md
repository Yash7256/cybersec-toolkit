# ⚡ CyberSec — Async Network Security Toolkit

A comprehensive async network security toolkit built with FastAPI, React, and Click.  
Advanced port scanning, web vulnerability detection, OS fingerprinting, AI-powered analysis, and rich reporting — all in one.

---

## 🚀 Features

### 🔍 **Port Scanning Engine**
- **Multiple Scan Modes**: TCP connect, SYN, UDP, FIN, NULL, XMAS, ACK, Zombie
- **Rate Limiting**: Configurable packets per second with stealth/normal/aggressive presets
- **Retry Logic**: Exponential backoff with configurable parameters
- **Adaptive Concurrency**: AIMD (Additive Increase/Multiplicative Decrease) controller
- **Connection Pooling**: Optimized for high-performance scanning
- **CIDR Support**: Scan entire networks with automatic target expansion

### 🛡️ **Service & OS Detection**
- **Banner Grabbing**: Automatic service identification for 19+ protocols
- **OS Fingerprinting**: Passive and active OS detection techniques
- **Version Detection**: Extract service versions and CVE information
- **TLS Analysis**: Certificate and TLS configuration analysis

### 📊 **Export & Reporting**
- **Multiple Formats**: JSON, CSV, HTML output options
- **Performance Metrics**: Detailed scan statistics and timing information
- **Real-time Streaming**: Server-sent events for live scan results
- **Auto-generated Filenames**: Timestamp-based file naming

### 🤖 **AI Integration**
- **Groq-powered Analysis**: AI-powered vulnerability assessment
- **Context Builder**: Intelligent context gathering for security analysis
- **Automated Reporting**: AI-generated security reports

---

## 📦 Installation

### Docker (Recommended)

```bash
git clone <your-repo-url> cybersec
cd cybersec

cp .env.example .env
# Edit .env and add your GROQ_API_KEY

docker-compose up --build
```

Open **http://localhost:8000** in your browser.  
API docs: **http://localhost:8000/docs**

### Local Development

#### Backend Installation

```bash
cd cybersec

# Install dependencies
poetry install

# Copy and configure environment
cp .env.example .env

# Start postgres only
docker-compose up -d postgres

# Run database migrations
alembic upgrade head

# Start the API server (hot-reload)
uvicorn cybersec.apps.api.main:app --reload --port 8000
```

#### Frontend Development

```bash
cd cybersec/web/ui
npm install
npm run dev          # → http://localhost:5173 (proxies /api to :8000)
```

To rebuild and serve the frontend from FastAPI:

```bash
cd cybersec/web/ui
npm run build            # builds once into cybersec/web/ui/dist/
cd ../../..
uvicorn cybersec.apps.api.main:app --reload --port 8000
```

---

## 💻 Usage Examples

### Command Line Interface

#### Basic Port Scan
```bash
# Scan common ports on a single target
cybersec scan run 192.168.1.1

# Scan specific port range
cybersec scan run 192.168.1.1 --ports 1-1000

# Scan with custom rate limiting
cybersec scan run 192.168.1.1 --rate stealth --rate-pps 50

# Export results to JSON
cybersec scan run 192.168.1.1 --output json --save-file

# Export results to CSV
cybersec scan run 192.168.1.1 --output csv --save-file
```

#### Advanced Scanning
```bash
# SYN scan (requires root)
cybersec scan run 192.168.1.1 --ports 1-65535 --scan-mode syn --rate aggressive

# UDP scan
cybersec scan run 192.168.1.1 --ports 53,161,123,137 --scan-mode udp

# CIDR range scanning
cybersec scan run 192.168.1.0/24 --ports common --rate normal

# Zombie scan
cybersec scan run 192.168.1.1 --ports 80 --scan-mode zombie --zombie-ip 192.168.1.254
```

### API Usage

#### Start a Scan
```bash
curl -X POST "http://localhost:8000/api/scans/" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.1",
    "port_range": "1-1000",
    "scan_type": "connect",
    "rate_preset": "normal",
    "retry_config": {
      "max_retries": 3,
      "base_delay": 0.5,
      "backoff_multiplier": 2.0,
      "max_delay": 5.0
    }
  }'
```

#### Get Scan Results
```bash
# Get HTML results
curl "http://localhost:8000/api/scans/{scan_id}"

# Get JSON results
curl "http://localhost:8000/api/scans/{scan_id}?format=json"

# Get CSV results
curl "http://localhost:8000/api/scans/{scan_id}?format=csv"
```

#### Real-time Streaming
```bash
# Server-sent events for live results
curl -N "http://localhost:8000/api/scans/{scan_id}/stream"
```

---

## 🔧 API Reference

### Scan Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scans/` | POST | Start a new scan |
| `/api/scans/{id}` | GET | Get scan results |
| `/api/scans/{id}/status` | GET | Get scan status |
| `/api/scans/{id}/stream` | GET | Real-time results stream |
| `/api/scans/multi-host` | POST | Scan multiple hosts |
| `/api/scans/os-fingerprint` | POST | OS fingerprinting |

### Scan Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target` | string | required | IP address, hostname, or domain |
| `port_range` | string | "common" | Port range: "common", "top1000", "all", "1-1000", "80,443" |
| `scan_type` | string | "port" | Scan mode: "connect", "syn", "udp", "stealth_fin", etc. |
| `rate_preset` | string | "normal" | Rate limiting: "stealth" (100 pps), "normal" (1000 pps), "aggressive" (5000 pps) |
| `rate_pps` | float | null | Custom rate in packets per second |
| `timeout` | float | 3.0 | Connection timeout in seconds |
| `concurrency` | int | 500 | Maximum concurrent connections |
| `retry_config` | object | null | Retry configuration with exponential backoff |

### Rate Presets

| Preset | Rate (pps) | Burst | Use Case |
|--------|-----------|-------|----------|
| `stealth` | 100 | 50 | Evasive scanning, IDS evasion |
| `normal` | 1000 | 100 | Regular network scanning |
| `aggressive` | 5000 | 500 | Fast scanning of permissive networks |

---

## 🏗️ Architecture Overview

### Core Components

#### **Scanner Engine** (`cybersec/core/scanner.py`)
- **AsyncPortScanner**: Main scanning orchestrator
- **TokenBucketRateLimiter**: Rate limiting with token bucket algorithm
- **AdaptiveConcurrencyController**: AIMD concurrency management
- **AsyncConnectionPool**: Connection pooling for performance

#### **Scan Modes** (`cybersec/core/`)
- **syn_scan.py**: SYN stealth scanning with Scapy
- **udp_scan.py**: UDP port scanning with retry logic
- **stealth.py**: Various stealth scan techniques (FIN, NULL, XMAS, ACK)
- **zombie_scan.py**: Idle scan using zombie host

#### **Detection Modules** (`cybersec/core/`)
- **service_detect.py**: Banner grabbing and service identification
- **os_fingerprint.py**: OS fingerprinting (passive/active)
- **port_analyzer.py**: Port risk assessment and CVE lookup
- **tls_fingerprint.py**: TLS certificate analysis

#### **Utilities** (`cybersec/core/utils.py`)
- Target resolution and CIDR expansion
- Port range parsing
- Security validation (private IP blocking, DNS rebinding protection)

#### **Performance Metrics** (`cybersec/core/metrics.py`)
- Scan timing and packet statistics
- Retry success rates
- Concurrency and rate limiting metrics
- Resource usage tracking

### API Layer (`cybersec/api/`)
- **FastAPI Application**: RESTful API with OpenAPI documentation
- **Background Tasks**: Async scan execution with progress tracking
- **Server-Sent Events**: Real-time result streaming
- **Database Integration**: PostgreSQL with fallback to in-memory storage

### CLI Interface (`cybersec/cli/`)
- **Click Commands**: Command-line interface for all scan modes
- **Progress Reporting**: Rich console output with progress bars
- **Export Options**: JSON, CSV, HTML output with auto-generated filenames

### Frontend (`cybersec/web/`)
- **React Dashboard**: Web interface for scan management
- **Real-time Updates**: WebSocket integration for live results
- **Visualization**: Interactive charts and network maps

---

## 🧪 Testing

```bash
# Run all tests
make test

# Run unit tests only
make test-unit

# Run integration tests only
make test-integration

# Generate coverage report
make coverage
```

---

## 📊 Performance Metrics

The scanner tracks comprehensive performance metrics for each scan:

### Timing Metrics
- Total scan duration
- Per-port response times (min/max/average)
- Rate limiter wait times

### Packet Statistics
- Packets sent/received
- Success rate percentage
- Filtered vs closed port distinction

### Retry Analysis
- Total retry attempts
- Retry success rate
- Breakdown by failure type (timeout, connection reset, etc.)

### Concurrency Metrics
- Peak concurrency reached
- Average concurrency utilization
- Rate limiter throttle events

### Resource Usage
- Memory consumption
- CPU utilization
- Network I/O

Metrics are included in JSON exports and available via the API.

---

## 🔒 Security Features

### Input Validation
- IP address validation and sanitization
- Private IP range blocking
- DNS rebinding protection
- Port range validation

### Rate Limiting
- API rate limiting (100 requests/minute)
- Scan rate limiting (configurable packets/second)
- Concurrent connection limits

### Access Control
- JWT-based authentication
- User-specific scan quotas
- Audit logging

---

## 🚀 Deployment

### Docker Production

```bash
# Production deployment
docker compose up -d --build

# Rebuild after frontend/backend changes
docker compose up -d --build backend
```

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql://user:pass@localhost/cybersec

# AI Integration
GROQ_API_KEY=your_groq_api_key

# Security
APP_SECRET_KEY=your_secret_key
JWT_ALGORITHM=HS256

# Redis / workers
REDIS_URL=redis://localhost:6379/0

# Scanning
SCAN_TIMEOUT=10.0
OS_FINGERPRINT_TIMEOUT=5.0
SERVICE_DETECTION_TIMEOUT=8.0
```

---

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📞 Support

- **Documentation**: [API Docs](http://localhost:8000/docs)
- **Issues**: [GitHub Issues](https://github.com/your-repo/cybersec/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-repo/cybersec/discussions)

---

**Built with ❤️ by the CyberSec Team**

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
│   └── web/ui/            # React + Vite + Tailwind source and dist build
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
# Port Scanner UI Fix Test - Wednesday 29 April 2026 06:15:28 PM IST
