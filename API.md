# CyberSec API Documentation

## Overview

The CyberSec API provides a comprehensive REST interface for network security scanning and analysis. Built with FastAPI, it offers automatic OpenAPI/Swagger documentation, real-time streaming, and extensive configuration options.

**Base URL**: `http://localhost:8000/api`  
**Documentation**: `http://localhost:8000/docs`  
**OpenAPI Spec**: `http://localhost:8000/openapi.json`

## Authentication

Most endpoints require JWT authentication. Obtain a token via:

```bash
curl -X POST "http://localhost:8000/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "your_username", "password": "your_password"}'
```

Include the token in subsequent requests:
```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  "http://localhost:8000/api/scans/"
```

## Rate Limiting

- **API Rate Limit**: 100 requests per minute per IP address
- **Scan Rate Limiting**: Configurable packets per second per scan
- **Concurrent Scans**: Limited by server configuration

## Scan Endpoints

### Start Single Host Scan

**Endpoint**: `POST /api/scans/`

**Description**: Start a port scan on a single target with comprehensive analysis.

#### Request Body

```json
{
  "target": "192.168.1.1",
  "port_range": "1-1000",
  "scan_type": "connect",
  "timeout": 3.0,
  "concurrency": 500,
  "rate_preset": "normal",
  "rate_pps": null,
  "retry_config": {
    "max_retries": 3,
    "base_delay": 0.5,
    "backoff_multiplier": 2.0,
    "max_delay": 5.0
  },
  "options": {
    "verbose": true,
    "save_to_db": true
  }
}
```

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `target` | string | Yes | - | IP address, hostname, or domain to scan |
| `port_range` | string | No | "common" | Port range specification |
| `scan_type` | string | No | "port" | Scanning technique |
| `timeout` | float | No | 3.0 | Connection timeout in seconds |
| `concurrency` | integer | No | 500 | Maximum concurrent connections |
| `rate_preset` | string | No | "normal" | Rate limiting preset |
| `rate_pps` | float | No | null | Custom rate in packets/second |
| `retry_config` | object | No | null | Retry configuration |
| `options` | object | No | null | Additional options |

#### Port Range Options

- `"common"`: Common ports (21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995)
- `"top1000"`: Top 1000 most common ports
- `"all"`: All 65535 ports
- `"1-1000"`: Custom range
- `"80,443,8080"`: Comma-separated ports

#### Scan Types

- `"connect"`: TCP connect scan (default)
- `"syn"`: SYN stealth scan (requires root)
- `"udp"`: UDP port scan
- `"stealth_fin"`: FIN stealth scan
- `"stealth_null"`: NULL stealth scan
- `"stealth_xmas"`: XMAS stealth scan
- `"stealth_ack"`: ACK stealth scan
- `"zombie"`: Idle scan (requires zombie host)

#### Rate Presets

| Preset | Rate (pps) | Burst | Use Case |
|--------|-----------|-------|----------|
| `"stealth"` | 100 | 50 | Evasive scanning, IDS evasion |
| `"normal"` | 1000 | 100 | Regular network scanning |
| `"aggressive"` | 5000 | 500 | Fast scanning of permissive networks |

#### Response

```json
{
  "id": "scan_1234567890",
  "scan_type": "port",
  "status": "running",
  "target": "192.168.1.1",
  "port_range": "1-1000",
  "scan_mode": "connect",
  "started_at": "2024-01-15T10:30:00Z",
  "stream_url": "/api/scans/scan_1234567890/stream",
  "storage": "database"
}
```

### Start Multi-Host Scan

**Endpoint**: `POST /api/scans/multi-host`

**Description**: Scan multiple targets concurrently.

#### Request Body

```json
{
  "targets": ["192.168.1.1", "192.168.1.2", "example.com"],
  "port_range": "1-1000",
  "scan_type": "connect",
  "timeout": 3.0,
  "concurrency": 500,
  "rate_preset": "normal",
  "host_concurrency_limit": 10,
  "retry_config": {
    "max_retries": 3,
    "base_delay": 0.5,
    "backoff_multiplier": 2.0,
    "max_delay": 5.0
  }
}
```

#### Additional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `targets` | array | required | List of targets to scan |
| `host_concurrency_limit` | integer | 10 | Maximum concurrent hosts |

### Get Scan Status

**Endpoint**: `GET /api/scans/{scan_id}/status`

**Description**: Get current scan status and progress.

#### Response

```json
{
  "id": "scan_1234567890",
  "status": "running",
  "progress": {
    "total_ports": 1000,
    "scanned_ports": 450,
    "open_ports": 12,
    "progress_percent": 45.0
  },
  "started_at": "2024-01-15T10:30:00Z",
  "estimated_completion": "2024-01-15T10:35:00Z"
}
```

### Get Scan Results

**Endpoint**: `GET /api/scans/{scan_id}?format={format}`

**Description**: Retrieve complete scan results in various formats.

#### Format Options

- `html` (default): Interactive HTML report
- `json`: Machine-readable JSON
- `csv`: Comma-separated values

#### JSON Response Example

```json
{
  "id": "scan_1234567890",
  "scan_type": "port",
  "target": "192.168.1.1",
  "ip": "192.168.1.1",
  "scan_time": {
    "started_at": "2024-01-15T10:30:00Z",
    "completed_at": "2024-01-15T10:32:15Z",
    "duration_seconds": 135.2,
    "scan_mode": "connect"
  },
  "scan_stats": {
    "total_ports_scanned": 1000,
    "open_ports_count": 12,
    "avg_latency_ms": 45.3,
    "peak_concurrency": 500
  },
  "performance_metrics": {
    "timing": {
      "total_duration_seconds": 135.2,
      "start_time": "2024-01-15T10:30:00Z",
      "end_time": "2024-01-15T10:32:15Z"
    },
    "packet_statistics": {
      "packets_sent": 1000,
      "packets_received": 988,
      "packet_success_rate": 98.8
    },
    "retry_statistics": {
      "total_retries": 12,
      "retry_success_rate_percent": 91.7
    },
    "concurrency_metrics": {
      "peak_concurrency_reached": 500,
      "avg_concurrency": 342.1
    },
    "rate_limiting_metrics": {
      "throttle_events": 156,
      "total_wait_time_seconds": 2.34
    }
  },
  "ports": [
    {
      "port": 22,
      "protocol": "tcp",
      "state": "open",
      "service": {
        "name": "ssh",
        "version": "OpenSSH_8.2p1",
        "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu2.2",
        "confidence": 95
      },
      "cves": [
        {
          "id": "CVE-2023-1234",
          "severity": "HIGH",
          "cvss_score": 7.5,
          "description": "Remote code execution vulnerability"
        }
      ],
      "risk": {
        "risk_level": "HIGH",
        "risk_score": 7.5
      },
      "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu2.2",
      "latency_ms": 23.4
    }
  ],
  "os_fingerprint": {
    "os_name": "Linux",
    "confidence": 0.85,
    "method": "ttl_analysis"
  }
}
```

### Real-time Scan Streaming

**Endpoint**: `GET /api/scans/{scan_id}/stream`

**Description**: Server-sent events stream for real-time scan results.

#### Usage

```bash
curl -N "http://localhost:8000/api/scans/{scan_id}/stream"
```

#### Event Format

```
data: {"type": "port_result", "port": 22, "state": "open", "service": "ssh"}

data: {"type": "progress", "scanned": 450, "total": 1000, "percent": 45.0}

data: {"type": "complete", "duration": 135.2, "open_ports": 12}
```

### OS Fingerprinting

**Endpoint**: `POST /api/scans/os-fingerprint`

**Description**: Perform OS fingerprinting on a target.

#### Request Body

```json
{
  "target": "192.168.1.1",
  "port_range": "common",
  "scan_type": "connect",
  "options": {
    "aggressive": true,
    "timeout": 5.0
  }
}
```

#### Response

```json
{
  "target": "192.168.1.1",
  "ip": "192.168.1.1",
  "os_fingerprint": {
    "os_name": "Linux",
    "version": "Ubuntu 20.04",
    "confidence": 0.92,
    "method": "passive_ttl",
    "details": {
      "ttl": 64,
      "window_size": 64240,
      "tcp_options": [1460, 1460, 1460, 1460, 1460, 1460]
    }
  },
  "scan_duration": 2.34,
  "started_at": "2024-01-15T10:30:00Z",
  "completed_at": "2024-01-15T10:30:02Z"
}
```

### List Scans

**Endpoint**: `GET /api/scans/`

**Description**: List recent scans with pagination.

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 20 | Maximum number of scans to return |

#### Response

```json
{
  "scans": [
    {
      "id": "scan_1234567890",
      "scan_type": "port",
      "status": "completed",
      "target": "192.168.1.1",
      "started_at": "2024-01-15T10:30:00Z",
      "duration": 135.2,
      "open_ports": 12
    }
  ],
  "total": 1,
  "storage": "database"
}
```

## Error Handling

The API returns standard HTTP status codes with detailed error messages:

### Status Codes

- `200 OK`: Successful request
- `201 Created`: Resource created successfully
- `400 Bad Request`: Invalid parameters
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error
- `503 Service Unavailable`: Database unavailable

### Error Response Format

```json
{
  "error": {
    "code": "INVALID_TARGET",
    "message": "Could not resolve target: invalid.hostname",
    "details": {
      "target": "invalid.hostname",
      "reason": "Name or service not known"
    }
  }
}
```

## Performance Metrics

Every scan includes comprehensive performance metrics:

### Timing Metrics
- Total scan duration
- Start/end timestamps
- Per-port response times

### Packet Statistics
- Packets sent/received
- Success rate percentage
- Filtered vs closed distinction

### Retry Analysis
- Total retry attempts
- Success rate by retry type
- Failure breakdown

### Concurrency Metrics
- Peak concurrency reached
- Average utilization
- Rate limiter events

### Resource Usage
- Memory consumption
- CPU utilization
- Network I/O

## SDK Examples

### Python

```python
import asyncio
import aiohttp

async def scan_target():
    async with aiohttp.ClientSession() as session:
        # Start scan
        async with session.post(
            "http://localhost:8000/api/scans/",
            json={
                "target": "192.168.1.1",
                "port_range": "1-1000",
                "scan_type": "connect"
            }
        ) as response:
            scan_data = await response.json()
            scan_id = scan_data["id"]
        
        # Get results
        async with session.get(
            f"http://localhost:8000/api/scans/{scan_id}?format=json"
        ) as response:
            results = await response.json()
            print(f"Found {len(results['ports'])} open ports")

asyncio.run(scan_target())
```

### JavaScript

```javascript
async function scanTarget() {
  // Start scan
  const response = await fetch('http://localhost:8000/api/scans/', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      target: '192.168.1.1',
      port_range: '1-1000',
      scan_type: 'connect'
    })
  });
  
  const scanData = await response.json();
  const scanId = scanData.id;
  
  // Get results
  const resultsResponse = await fetch(
    `http://localhost:8000/api/scans/${scanId}?format=json`
  );
  const results = await resultsResponse.json();
  
  console.log(`Found ${results.ports.length} open ports`);
}

scanTarget();
```

### curl

```bash
# Start scan
SCAN_ID=$(curl -s -X POST "http://localhost:8000/api/scans/" \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1", "port_range": "1-1000"}' \
  | jq -r '.id')

# Get results
curl "http://localhost:8000/api/scans/$SCAN_ID?format=json" | jq '.ports | length'
```

## WebSocket Support

For real-time updates, use WebSocket connections:

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/scans/scan_id');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Scan update:', data);
};
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | - | PostgreSQL connection string |
| `GROQ_API_KEY` | - | AI analysis API key |
| `RATE_LIMIT_REQUESTS_PER_MINUTE` | 100 | API rate limit |
| `DEFAULT_SCAN_TIMEOUT` | 3.0 | Default scan timeout |
| `MAX_CONCURRENT_SCANS` | 10 | Maximum concurrent scans |
| `SECRET_KEY` | - | JWT secret key |

### Rate Limiting Configuration

Rate limiting can be configured per-scan:

```json
{
  "rate_preset": "custom",
  "rate_pps": 500.0,
  "retry_config": {
    "max_retries": 5,
    "base_delay": 1.0,
    "backoff_multiplier": 1.5,
    "max_delay": 10.0
  }
}
```

## Security Considerations

### Input Validation
- All inputs are validated and sanitized
- Private IP ranges are blocked by default
- DNS rebinding protection is enabled
- Port ranges are strictly validated

### Access Control
- JWT-based authentication
- User-specific scan quotas
- Audit logging for all operations
- Rate limiting prevents abuse

### Network Safety
- Configurable timeouts prevent hanging scans
- Rate limiting avoids network overload
- Connection pooling limits resource usage
- Graceful error handling prevents crashes

## Troubleshooting

### Common Issues

1. **Permission Denied for SYN Scans**
   - SYN scans require root privileges
   - Use `connect` scans instead or run with sudo

2. **Target Resolution Failed**
   - Verify target hostname/IP is correct
   - Check DNS resolution
   - Try using IP address directly

3. **Rate Limiting Errors**
   - Reduce scan rate or use stealth preset
   - Check API rate limits
   - Wait before retrying

4. **Database Unavailable**
   - API falls back to in-memory storage
   - Check PostgreSQL connection
   - Results may be lost on restart

### Debug Mode

Enable debug logging:

```bash
export LOG_LEVEL=DEBUG
uvicorn cybersec.api.main:app --reload
```

### Health Check

Monitor API health:

```bash
curl "http://localhost:8000/api/health"
```

## Support

- **Documentation**: http://localhost:8000/docs
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Email**: support@cybersec.com
