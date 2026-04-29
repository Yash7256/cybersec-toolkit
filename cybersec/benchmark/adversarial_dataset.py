"""
Adversarial Service Detection Dataset Generator

Generates 500+ test cases designed to break service detection systems.
Includes protocol confusion, timing attacks, malformed responses, and real-world chaos.
"""
import asyncio
import random
import json
import socket
from typing import Dict, List, Any
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class AdversarialTestCase:
    """Single adversarial test case."""
    host: str
    port: int
    expected_service: str
    scenario_type: str
    description: str
    difficulty: str  # easy/medium/hard/evil
    expected_behavior: str  # correct/ambiguous/unknown/filtered
    probe_data: bytes = b""  # What to send when probed
    delay_ms: int = 0  # Artificial delay
    banner_override: str = ""  # Custom banner response


# Protocol signatures for confusion attacks
PROTOCOL_SIGNATURES = {
    "ssh": [b"SSH-2.0-OpenSSH_8.2p1", b"SSH-2.0-dropbear_2020.81", b"SSH-1.99-OpenSSH_7.4"],
    "http": [b"HTTP/1.1 200 OK", b"HTTP/1.0 404 Not Found", b"HTTP/1.1 301 Moved"],
    "https": [b"HTTP/1.1 200 OK\r\nServer: nginx", b"HTTP/1.1 403 Forbidden"],
    "redis": [b"+PONG", b"+OK\r\n", b"-ERR unknown command"],
    "postgresql": [b"R\x00\x00\x00\x08", b"K\x00\x00\x00\x08", b"E\x00\x00\x00\x05"],
    "ftp": [b"220 Welcome to FTP", b"220 File Transfer Service ready"],
    "smtp": [b"220 mail.example.com ESMTP Postfix", b"220-ESMTP Ready"],
    "telnet": [b"\xff\xfb\x01\xff\xfd\x03", b"login: ", b"Connected to"],
    "mysql": [b"\x0a\x00\x00\x00\x0a5.7.30-log"],
}

# Banner mutations for confusion
BANNER_MUTATIONS = [
    # SSH masquerading as other protocols
    lambda b: b"SSH-2.0-" + b,
    lambda b: b.replace(b"SSH", b"HTTP/1.1 200"),
    lambda b: b + b"\r\nHTTP/1.1\r\n",
    # HTTP masquerading as SSH  
    lambda b: b"HTTP/1.1 200 OK\r\nServer: SSH-2.0-OpenSSH\r\n",
    # Redis with HTTP headers
    lambda b: b"+PONG\r\nServer: Apache\r\n",
    # Partial signatures
    lambda b: b[:5],
    lambda b: b[:10],
    lambda b: b[:3],
    # Garbage injection
    lambda b: b"\x00\xff\xfe\x00" + b + b"\xca\xfe\xba\xbe",
    lambda b: b + b"RANDOM_GARBAGE_DATA",
    # Unicode corruption
    lambda b: b.decode('utf-8', errors='replace').encode('utf-8'),
    # Mixed protocols
    lambda b: b[:len(b)//2] + b"HTTP/1.1\r\n" + b[len(b)//2:],
]


def generate_protocol_confusion_cases() -> List[AdversarialTestCase]:
    """Phase 1: Protocol confusion attacks."""
    cases = []
    hosts = ["127.0.0.1", "localhost"]
    
    # SSH pretending to be other services
    for host in hosts:
        cases.extend([
            AdversarialTestCase(host, 22, "ssh", "protocol_confusion", 
                "SSH sending HTTP-like header", "evil", "ambiguous", 
                probe_data=b"HTTP/1.1 200 OK\r\n"),
            AdversarialTestCase(host, 2222, "telnet", "protocol_confusion",
                "Telnet echoing SSH banner", "hard", "ambiguous",
                probe_data=b"SSH-2.0-Service\r\n"),
            AdversarialTestCase(host, 80, "http", "protocol_confusion",
                "HTTP server returning SSH banner", "evil", "ambiguous",
                probe_data=b"SSH-2.0-Apache\r\n"),
            AdversarialTestCase(host, 8080, "http", "protocol_confusion",
                "HTTP on alt port returning Redis response", "hard", "ambiguous",
                probe_data=b"+PONG\r\n"),
        ])
    
    # Redis masquerading
    for port in [6379, 16379, 26379]:
        cases.append(AdversarialTestCase("127.0.0.1", port, "redis", "protocol_confusion",
            "Redis returning HTTP headers", "hard", "ambiguous",
            probe_data=b"HTTP/1.1 200 OK\r\nServer: Redis\r\nContent-Type: text/html\r\n\r\n"))
    
    # PostgreSQL with TLS-like response
    for port in [5432, 15432]:
        cases.append(AdversarialTestCase("127.0.0.1", port, "postgresql", "protocol_confusion",
            "PostgreSQL with TLS handshake", "hard", "ambiguous",
            probe_data=b"\x16\x03\x01\x00\x01\x01\x00"))
    
    return cases


def generate_partial_response_cases() -> List[AdversarialTestCase]:
    """Phase 2: Partial/truncated responses."""
    cases = []
    
    partial_signatures = [
        (b"SSH-", "ssh"),
        (b"HTT", "http"),
        (b"+P", "redis"),
        (b"R\x00", "postgresql"),
        (b"220", "ftp"),
    ]
    
    for host in ["127.0.0.1", "localhost"]:
        for sig, svc in partial_signatures:
            for port in [22, 80, 6379, 21]:
                cases.append(AdversarialTestCase(
                    host, port, svc, "partial_response",
                    f"Partial signature: {sig.decode()}", "medium", "unknown",
                    probe_data=sig
                ))
        
        # Cut banners mid-packet
        for port in [22, 80, 6379]:
            cases.append(AdversarialTestCase(host, port, "unknown", "partial_response",
                "Truncated banner response", "medium", "unknown",
                probe_data=b"Partial"))
    
    return cases


def generate_garbage_noise_cases() -> List[AdversarialTestCase]:
    """Phase 3: Garbage and noise injection."""
    cases = []
    
    # Valid banner + random junk
    junk_data = [
        b"SSH-2.0-OpenSSH\x00\xff\xfe\xca\xfe",
        b"HTTP/1.1 200 OK\x00\xff\x00\xfe\xba\xbe",
        b"+PONG\xca\xfe\xba\xbe\x00\xff",
    ]
    
    for host in ["127.0.0.1", "localhost"]:
        for junk in junk_data:
            port = random.choice([22, 80, 6379])
            cases.append(AdversarialTestCase(host, port, "unknown", "garbage_noise",
                "Valid signature + garbage suffix", "evil", "unknown",
                probe_data=junk))
        
        # Random bytes before signature
        for port in [22, 80, 6379]:
            cases.append(AdversarialTestCase(host, port, "unknown", "garbage_noise",
                "Random prefix before protocol", "hard", "unknown",
                probe_data=b"\xaa\xbb\xcc\xdd" + PROTOCOL_SIGNATURES["ssh"][0]))
    
    # Interleaved protocols
    for host in ["127.0.0.1"]:
        cases.append(AdversarialTestCase(host, 8080, "http", "garbage_noise",
            "HTTP + Redis interleaved", "evil", "ambiguous",
            probe_data=b"HTTP/1.1 200\r\n+PONG\r\n"))
    
    return cases


def generate_filtered_closed_cases() -> List[AdversarialTestCase]:
    """Phase 4: Filtered vs closed vs silent."""
    cases = []
    
    # Closed ports (immediate RST)
    for port in [1, 9990, 9991, 65535]:
        cases.append(AdversarialTestCase("127.0.0.1", port, "filtered", "filtered",
            "Port closed (RST)", "medium", "filtered"))
    
    # Silent ports (no response)
    for port in range(19990, 19995):
        if port % 2 == 0:
            cases.append(AdversarialTestCase("127.0.0.1", port, "filtered", "filtered",
                "Silent port (timeout)", "hard", "filtered"))
    
    # ICMP unreachable scenarios
    for port in [111, 2049]:
        cases.append(AdversarialTestCase("127.0.0.1", port, "filtered", "filtered",
            "Port likely filtered by firewall", "medium", "filtered"))
    
    return cases


def generate_nonstandard_port_cases() -> List[AdversarialTestCase]:
    """Phase 5: Non-standard port extremes."""
    cases = []
    
    # High ports
    for port in range(49152, 49252, 10):
        cases.append(AdversarialTestCase("127.0.0.1", port, "unknown", "nonstandard",
            f"Service on random high port {port}", "hard", "unknown"))
    
    # Non-standard for common services
    alt_ports = {
        "ssh": [2222, 22222, 22022],
        "http": [3000, 5000, 8888, 9000, 8888, 9999],
        "https": [8443, 9443, 4433],
        "redis": [16379, 26379, 63790],
        "postgresql": [15432, 5433, 5434],
    }
    
    for svc, ports in alt_ports.items():
        for port in ports:
            cases.append(AdversarialTestCase("127.0.0.1", port, svc, "nonstandard",
                f"{svc} on non-standard port {port}", "medium", 
                "correct" if svc else "unknown"))
    
    return cases


def generate_timing_attack_cases() -> List[AdversarialTestCase]:
    """Phase 6: Timing attacks."""
    cases = []
    
    # Various delays
    delays = [100, 500, 1000, 2000, 3500, 4500]
    
    for host in ["127.0.0.1", "localhost"]:
        for delay in delays:
            port = random.choice([22, 80, 6379])
            cases.append(AdversarialTestCase(host, port, "unknown", "timing_attack",
                f"Delayed response {delay}ms", "evil", "unknown",
                delay_ms=delay))
    
    # Jitter injection
    for host in ["127.0.0.1"]:
        for port in [80, 8080]:
            cases.append(AdversarialTestCase(host, port, "http", "timing_attack",
                "Random jitter response", "hard", "ambiguous",
                delay_ms=random.randint(100, 2000)))
    
    return cases


def generate_stateful_protocol_cases() -> List[AdversarialTestCase]:
    """Phase 7: Stateful protocols requiring handshake."""
    cases = []
    
    # PostgreSQL requires startup packet
    for port in [5432, 15432]:
        cases.append(AdversarialTestCase("127.0.0.1", port, "postgresql", "stateful",
            "PostgreSQL requiring startup handshake", "hard", "ambiguous",
            probe_data=b"\x00\x00\x00\x10\x00\x03\x00\x00user\x00\x00"))
    
    # TLS required before HTTP
    for port in [443, 8443]:
        cases.append(AdversarialTestCase("127.0.0.1", port, "https", "stateful",
            "HTTPS requiring TLS handshake", "hard", "ambiguous",
            probe_data=b"\x16\x03\x01"))
    
    # Redis AUTH required
    for port in [6379, 16379]:
        cases.append(AdversarialTestCase("127.0.0.1", port, "redis", "stateful",
            "Redis requiring AUTH before response", "evil", "unknown",
            probe_data=b"AUTH"))
    
    return cases


def generate_honeypot_cases() -> List[AdversarialTestCase]:
    """Phase 8: Honeypot/decoy behavior."""
    cases = []
    
    for host in ["127.0.0.1", "localhost"]:
        # Rotating banners
        for port in [2222, 8080, 9000]:
            cases.append(AdversarialTestCase(host, port, "unknown", "honeypot",
                "Rotating banners per request", "evil", "ambiguous"))
        
        # Multiple protocol signatures
        cases.append(AdversarialTestCase(host, 9999, "unknown", "honeypot",
            "Returning SSH then HTTP", "evil", "ambiguous"))
        
        # Cowrie honeypot emulation
        cases.append(AdversarialTestCase(host, 2222, "ssh", "honeypot",
            "Cowrie SSH honeypot", "hard", "ambiguous",
            probe_data=b"SSH-2.0-8.51\r\n"))
    
    return cases


def generate_edge_port_cases() -> List[AdversarialTestCase]:
    """Phase 9: Edge ports."""
    cases = []
    
    edge_ports = [0, 1, 2, 80, 443, 65535, 65534]
    
    for port in edge_ports:
        expected = {
            0: "unknown", 1: "filtered", 2: "filtered",
            80: "http", 443: "https", 65535: "unknown", 65534: "unknown"
        }.get(port, "unknown")
        
        cases.append(AdversarialTestCase("127.0.0.1", port, expected, "edge_port",
            f"Edge port {port}", "medium", 
            "filtered" if port in [0, 1, 2] else "unknown"))
    
    return cases


def generate_realworld_chaos_cases() -> List[AdversarialTestCase]:
    """Phase 10: Real-world chaos."""
    cases = []
    
    # CDN edge nodes
    for host in ["scanme.nmap.org", "example.com"]:
        cases.append(AdversarialTestCase(host, 443, "https", "realworld",
            "CDN returning inconsistent certificates", "evil", "ambiguous"))
    
    # Behind reverse proxy
    for port in [80, 443]:
        cases.append(AdversarialTestCase("127.0.0.1", port, "http", "realworld",
            "Behind reverse proxy (X-Forwarded-For)", "hard", "ambiguous"))
    
    # WAF altering headers
    for port in [443, 8443]:
        cases.append(AdversarialTestCase("127.0.0.1", port, "https", "realworld",
            "WAF stripping Server headers", "hard", "ambiguous"))
    
    # Load balancer returning 503
    cases.append(AdversarialTestCase("127.0.0.1", 80, "http", "realworld",
        "Load balancer with 503", "medium", "ambiguous",
        probe_data=b"HTTP/1.1 503 Service Unavailable\r\n"))
    
    return cases


def generate_confidence_breaking_cases() -> List[AdversarialTestCase]:
    """Phase 11: Confidence scoring attacks."""
    cases = []
    
    # Low confidence for correct detection
    for port in [3000, 5000, 8888]:
        cases.append(AdversarialTestCase("127.0.0.1", port, "http", "confidence",
            "HTTP on unusual port - correct but low conf", "evil", "correct"))
    
    # High confidence wrong detection
    cases.append(AdversarialTestCase("127.0.0.1", 8080, "telnet", "confidence",
        "Telnet on HTTP port with SSH banner - wrong high conf", "evil", "ambiguous"))
    
    # Ambiguous signatures
    ambiguous = [
        (b"SSH-2.0-", "Could be SSH or honeypot"),
        (b"220 ", "Could be FTP or SMTP"),
        (b"+OK", "Could be POP3 or Redis"),
    ]
    
    for sig, desc in ambiguous:
        port = random.choice([22, 80, 110, 6379])
        cases.append(AdversarialTestCase("127.0.0.1", port, "unknown", "confidence",
            desc, "evil", "ambiguous",
            probe_data=sig))
    
    return cases


def generate_mass_scaling_cases() -> List[AdversarialTestCase]:
    """Phase 12: Mass scaling with random configurations."""
    cases = []
    
    # Random ports per service
    services = {
        "ssh": list(range(20, 25)) + list(range(200, 210)) + list(range(2200, 2210)),
        "http": list(range(80, 90)) + list(range(800, 810)) + list(range(3000, 3050)),
        "https": list(range(443, 453)) + list(range(8443, 8453)),
        "redis": list(range(6370, 6400)) + list(range(16379, 16400)),
        "postgresql": list(range(5430, 5460)) + list(range(15400, 15430)),
    }
    
    for svc, ports in services.items():
        for port in ports:
            expected = "unknown" if port not in [22, 80, 443, 6379, 5432] else svc
            cases.append(AdversarialTestCase("127.0.0.1", port, expected, "mass_scaled",
                f"{svc} on scaled port {port}", "easy", "correct"))
    
    return cases


def generate_dataset(size: int = 500) -> List[Dict[str, Any]]:
    """Generate full adversarial dataset."""
    print("Generating adversarial test dataset...")
    
    all_cases = []
    
    # Generate all phases
    generators = [
        generate_protocol_confusion_cases,
        generate_partial_response_cases,
        generate_garbage_noise_cases,
        generate_filtered_closed_cases,
        generate_nonstandard_port_cases,
        generate_timing_attack_cases,
        generate_stateful_protocol_cases,
        generate_honeypot_cases,
        generate_edge_port_cases,
        generate_realworld_chaos_cases,
        generate_confidence_breaking_cases,
        generate_mass_scaling_cases,
    ]
    
    for gen in generators:
        cases = gen()
        all_cases.extend(cases)
        print(f"  {gen.__name__}: {len(cases)} cases")
    
    # Trim to requested size (if needed, duplicate harder cases)
    while len(all_cases) < size:
        # Duplicate harder cases to reach target
        extra_cases = []
        for tc in all_cases[:min(100, len(all_cases))]:
            # Vary port slightly
            new_port = tc.port + 10000 if tc.port < 50000 else tc.port
            new_case = AdversarialTestCase(
                host=tc.host,
                port=new_port,
                expected_service=tc.expected_service,
                scenario_type=tc.scenario_type,
                description=tc.description + " (variant)",
                difficulty="evil" if tc.difficulty in ["hard", "evil"] else tc.difficulty,
                expected_behavior=tc.expected_behavior,
                probe_data=tc.probe_data,
                delay_ms=tc.delay_ms,
            )
            extra_cases.append(new_case)
        all_cases.extend(extra_cases)
    
    if len(all_cases) > size:
        random.shuffle(all_cases)
        all_cases = all_cases[:size]
    
    # Convert to dict format
    output = []
    for tc in all_cases:
        item = {
            "host": tc.host,
            "port": tc.port,
            "expected_service": tc.expected_service,
            "scenario_type": tc.scenario_type,
            "description": tc.description,
            "difficulty": tc.difficulty,
            "expected_behavior": tc.expected_behavior,
        }
        if tc.probe_data:
            item["probe_data"] = tc.probe_data.hex()
        if tc.delay_ms:
            item["delay_ms"] = tc.delay_ms
        output.append(item)
    
    # Add difficulty breakdown
    difficulty_counts = {"easy": 0, "medium": 0, "hard": 0, "evil": 0}
    for item in output:
        difficulty_counts[item["difficulty"]] += 1
    
    print(f"\nTotal: {len(output)} test cases")
    print(f"Difficulty: {difficulty_counts}")
    
    return output


async def run_evaluation(dataset: List[Dict], detector_cls) -> Dict[str, Any]:
    """Run evaluation against dataset."""
    from cybersec.core.scanner.analysis.service_detect import ServiceDetector
    
    detector = ServiceDetector()
    results = []
    
    for item in dataset:
        try:
            result = await detector.detect(
                item["host"],
                item["port"],
                timeout=2.0
            )
            match = result.name.lower() == item["expected_service"].lower()
            results.append({
                "port": item["port"],
                "expected": item["expected_service"],
                "detected": result.name,
                "confidence": result.confidence,
                "match": match,
                "scenario": item["scenario_type"],
                "difficulty": item["difficulty"],
            })
        except Exception as e:
            results.append({
                "port": item["port"],
                "expected": item["expected_service"],
                "detected": "error",
                "confidence": 0,
                "match": False,
                "error": str(e),
            })
    
    return results


def main():
    """Generate and optionally run dataset."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Adversarial dataset generator")
    parser.add_argument("--size", type=int, default=500, help="Dataset size")
    parser.add_argument("--output", type=str, default="adversarial_dataset.json", help="Output file")
    parser.add_argument("--run", action="store_true", help="Run evaluation")
    args = parser.parse_args()
    
    # Generate dataset
    dataset = generate_dataset(args.size)
    
    # Save
    with open(args.output, "w") as f:
        json.dump(dataset, f, indent=2)
    
    print(f"\nDataset saved to: {args.output}")
    
    # Run if requested
    if args.run:
        import asyncio
        print("\nRunning evaluation...")
        results = asyncio.run(run_evaluation(dataset, None))
        
        # Compute metrics
        correct = sum(1 for r in results if r["match"])
        total = len(results)
        accuracy = correct / total * 100
        
        by_scenario = {}
        for r in results:
            sc = r["scenario"]
            if sc not in by_scenario:
                by_scenario[sc] = {"correct": 0, "total": 0}
            by_scenario[sc]["total"] += 1
            if r["match"]:
                by_scenario[sc]["correct"] += 1
        
        print(f"\n=== ADVERSARIAL EVALUATION ===")
        print(f"Overall: {accuracy:.1f}% ({correct}/{total})")
        print("\nBy Scenario:")
        for sc, stats in by_scenario.items():
            acc = stats["correct"] / stats["total"] * 100
            print(f"  {sc}: {acc:.1f}%")


if __name__ == "__main__":
    main()