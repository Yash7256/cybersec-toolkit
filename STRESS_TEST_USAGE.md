# CyberSec Stress Test Usage

## Overview

The stress test script (`stress_test.py`) provides comprehensive performance testing for the CyberSec network security scanner. It measures real system performance under various load conditions.

## Prerequisites

1. **CyberSec API Running**: Ensure the CyberSec service is running and accessible
2. **JWT Token**: You need a valid JWT authentication token for the API
3. **Nmap Installed**: Required for baseline comparison in Test Suite 1
4. **Target Host**: An IP address that you can legally scan (localhost for testing)

## Basic Usage

```bash
# Basic stress test with localhost
python stress_test.py --token YOUR_JWT_TOKEN

# Custom target and API URL
python stress_test.py \
  --token YOUR_JWT_TOKEN \
  --target 192.168.1.100 \
  --base-url http://192.168.1.50:8000

# Specify different nmap target (useful for cloud environments)
python stress_test.py \
  --token YOUR_JWT_TOKEN \
  --target 10.0.0.5 \
  --nmap-target 52.12.34.56 \
  --base-url http://cybersec-api.example.com
```

## Test Suites

### Test Suite 1: Full 65,535 Port Range Scan
- **Goal**: Measure time and accuracy scanning all 65535 ports
- **Duration**: ~5-30 minutes depending on target
- **Output**: Speedup ratio compared to Nmap
- **Progress**: Dots printed every 10 seconds

### Test Suite 2: Concurrent API Users
- **Goal**: Measure API throughput under load
- **Concurrency Levels**: 1, 5, 10, 25, 50 simultaneous users
- **Scan Size**: Small (ports 80,443,22,8080) for fast results
- **Metrics**: Requests/sec, mean response time, p95 response time, error rate

### Test Suite 3: Maximum Concurrency (500 Workers)
- **Goal**: Verify AIMD controller reaches 500 workers
- **Scan Size**: 10,000 ports to trigger worker scaling
- **Monitoring**: Worker count tracking (if metrics endpoint available)
- **Duration**: ~5-10 minutes

### Test Suite 4: Sustained Load
- **Goal**: Check for memory leaks and performance degradation
- **Duration**: 5 minutes of continuous scanning
- **Scan Size**: 1,000 ports each, new scan every 10 seconds
- **Analysis**: Performance comparison between first and last 60 seconds

## Output Format

### Real-time Progress
```
🚀 Starting CyberSec Stress Test Suite
📍 Target: 127.0.0.1
🌐 API: http://localhost:8000
✅ API health check passed

🧪 Running Test Suite 1...
🚀 Starting CyberSec full scan (ports 1-65535)...
📝 Scan ID: abc123-def456
⏳ Waiting for completion (progress dots every 10s): . . . . ✅ DONE
📊 CyberSec: 12.34s, 5 open ports

🔍 Running Nmap baseline: nmap -sT -p 1-65535 --min-rate 1000 127.0.0.1
📊 Nmap: 89.12s, 5 open ports
🚀 Speedup ratio: 7.22x
```

### Final Summary Box
```
╔══════════════════════════════════════════════════╗
║           CYBERSEC STRESS TEST RESULTS           ║
╠══════════════════════════════════════════════════╣
║ Full 65k scan:   CyberSec 12.3s vs Nmap 89.1s (7.2x)  ║
║ Max concurrency: 50 users, 12.5 req/s, 1250ms p95       ║
║ Peak workers:    487 / 500                         ║
║ Sustained load:  28 scans/5min, 0.0% error rate  ║
╚══════════════════════════════════════════════════╝
```

## Results File

All test results are automatically saved to `stress_test_results.json`:

```json
{
  "full_scan_results": {
    "success": true,
    "cybersec_duration": 12.34,
    "cybersec_open_ports": 5,
    "nmap_duration": 89.12,
    "nmap_open_ports": 5,
    "speedup_ratio": 7.22
  },
  "concurrent_users_results": [
    {
      "concurrency": 1,
      "req_per_sec": 1.25,
      "mean_rt_ms": 800,
      "p95_rt_ms": 950,
      "errors": 0,
      "total_tests": 1
    }
  ],
  "max_concurrency_results": {
    "success": true,
    "duration": 45.67,
    "open_ports": 3,
    "peak_workers": 487,
    "metrics_available": true,
    "scan_errors": 0
  },
  "sustained_load_results": {
    "success": true,
    "total_scans": 28,
    "first_60s_mean": 8.45,
    "last_60s_mean": 9.12,
    "degradation_detected": false,
    "degradation_ratio": 1.08,
    "total_errors": 0,
    "error_rate": 0.0
  },
  "final_summary": {}
}
```

## Important Notes

### Legal Considerations
- Only scan IPs you own or have explicit permission to scan
- For public cloud instances, use your own instances
- Consider using localhost for initial testing

### Performance Impact
- **Test Suite 1**: High network and CPU usage (65K ports)
- **Test Suite 2**: High API load (up to 50 concurrent requests)
- **Test Suite 3**: Maximum worker utilization
- **Test Suite 4**: Sustained load for 5 minutes

### Error Handling
- All HTTP errors are caught and counted
- Timeouts are handled gracefully
- Failed scans don't stop the test suite
- Network issues are reported but don't crash the script

### Requirements
- Python 3.11+
- `requests` library
- `nmap` command-line tool
- Valid JWT token for CyberSec API

## Troubleshooting

### Common Issues

**ModuleNotFoundError: No module named 'requests'**
```
Traceback (most recent call last):
  File "stress_test.py", line 19, in <module>
    import requests
ModuleNotFoundError: No module named 'requests'
```
- Solution 1: Use the bash wrapper script: `./stress_test.sh --token YOUR_TOKEN`
- Solution 2: Use explicit python3: `python3 stress_test.py --token YOUR_TOKEN`
- Solution 3: Use the Python wrapper: `python run_stress_test.py --token YOUR_TOKEN`
- Solution 4: Reset shell environment: `exec $SHELL` then retry

**API Health Check Failed**
```
❌ API health check failed: Connection refused
```
- Solution: Ensure CyberSec service is running on the specified URL

**Nmap Not Found**
```
nmap: command not found
```
- Solution: Install nmap (`sudo apt-get install nmap` on Ubuntu)

**Permission Denied**
```
❌ Scan submission failed: HTTP 401
```
- Solution: Check JWT token validity and permissions

**Target Unreachable**
```
❌ Scan failed: Host unreachable
```
- Solution: Verify target IP is reachable and not blocking scans

### Debug Mode

For detailed debugging, you can modify the script to enable verbose logging by adding:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Performance Benchmarks

Based on previous tests, expect results similar to:
- **Full Scan**: 7-8x faster than Nmap on common ports
- **Concurrent Users**: 10-50 requests/sec depending on hardware
- **Peak Workers**: Should reach 480-500 workers
- **Sustained Load**: <5% error rate, minimal degradation

## Integration with CI/CD

The script can be integrated into CI/CD pipelines:

```bash
#!/bin/bash
# CI stress test
python stress_test.py \
  --token $CYBERSEC_TOKEN \
  --target $TEST_TARGET \
  --base-url $CYBERSEC_API_URL

# Check exit code for pass/fail
if [ $? -eq 0 ]; then
  echo "Stress tests passed"
else
  echo "Stress tests failed"
  exit 1
fi
```
