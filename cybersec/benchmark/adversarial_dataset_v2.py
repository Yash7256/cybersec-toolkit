"""
Adversarial Service Detection Dataset Generator V2

Generates 10,000+ test cases designed to break service detection systems.
Includes protocol confusion, timing attacks, malformed responses, mutation engines,
and real-world chaos.

DESIGN PHILOSOPHY: FAILURE DISCOVERY, not validation.
"""
import asyncio
import random
import json
import hashlib
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass, asdict, field
from datetime import datetime
from collections import defaultdict
import math


# Seeded randomness for reproducibility
RANDOM_SEED = 42
random.seed(RANDOM_SEED)


@dataclass
class AdversarialTestCase:
    """Single adversarial test case."""
    id: str
    host: str
    port: int
    expected_service: str
    scenario_type: str
    scenario_subtype: str
    description: str
    difficulty: str  # easy/medium/hard/evil
    expected_behavior: str  # correct/ambiguous/unknown/filtered
    probe_data: str = ""  # Hex-encoded probe data
    banner_override: str = ""  # Hex-encoded expected banner
    delay_ms: int = 0
    mutation_tags: List[str] = field(default_factory=list)
    base_case_id: str = ""  # For mutated cases
    
    def to_dict(self) -> Dict[str, Any]:
        d = {
            "id": self.id,
            "host": self.host,
            "port": self.port,
            "expected_service": self.expected_service,
            "scenario_type": self.scenario_type,
            "scenario_subtype": self.scenario_subtype,
            "description": self.description,
            "difficulty": self.difficulty,
            "expected_behavior": self.expected_behavior,
        }
        if self.probe_data:
            d["probe_data"] = self.probe_data
        if self.banner_override:
            d["banner_override"] = self.banner_override
        if self.delay_ms:
            d["delay_ms"] = self.delay_ms
        if self.mutation_tags:
            d["mutation_tags"] = self.mutation_tags
        if self.base_case_id:
            d["base_case_id"] = self.base_case_id
        return d


# =============================================================================
# MUTATION ENGINE
# =============================================================================

class MutationEngine:
    """Generates mutated variants from base test cases."""
    
    def __init__(self, seed: int = RANDOM_SEED):
        self.rng = random.Random(seed)
    
    def byte_flip(self, data: bytes, num_bits: int = 1) -> bytes:
        """Flip random bits in byte data."""
        result = bytearray(data)
        for _ in range(num_bits):
            if len(result) == 0:
                break
            idx = self.rng.randint(0, len(result) - 1)
            bit = self.rng.randint(0, 7)
            result[idx] ^= (1 << bit)
        return bytes(result)
    
    def byte_insertion(self, data: bytes, num_bytes: int = 5) -> bytes:
        """Insert random bytes at random position."""
        if len(data) == 0:
            return self.rng.randbytes(num_bytes)
        idx = self.rng.randint(0, len(data))
        random_bytes = bytes([self.rng.randint(0, 255) for _ in range(num_bytes)])
        return data[:idx] + random_bytes + data[idx:]
    
    def byte_deletion(self, data: bytes, num_bytes: int = 1) -> bytes:
        """Delete random bytes from data."""
        if len(data) <= num_bytes:
            return b""
        idx = self.rng.randint(0, len(data) - num_bytes)
        return data[:idx] + data[idx + num_bytes:]
    
    def truncation(self, data: bytes, ratio: float = 0.5) -> bytes:
        """Truncate data at random offset."""
        if len(data) == 0:
            return b""
        cutoff = max(1, int(len(data) * ratio))
        return data[:cutoff]
    
    def case_mutation(self, text: str) -> str:
        """Random case changes in string."""
        result = []
        for ch in text:
            if ch.isalpha():
                if self.rng.random() < 0.3:
                    result.append(ch.swapcase())
                else:
                    result.append(ch)
            else:
                result.append(ch)
        return "".join(result)
    
    def header_reorder(self, headers: List[str]) -> List[str]:
        """Reorder headers in HTTP-like response."""
        if len(headers) <= 1:
            return headers
        shuffled = headers.copy()
        self.rng.shuffle(shuffled)
        return shuffled
    
    def timing_jitter(self, base_delay: int, max_jitter: int = 500) -> int:
        """Add timing jitter to delay."""
        jitter = self.rng.randint(-max_jitter, max_jitter)
        return max(0, base_delay + jitter)
    
    def inject_binary_noise(self, data: bytes, noise_ratio: float = 0.2) -> bytes:
        """Mix binary noise with data."""
        if len(data) == 0:
            return bytes([self.rng.randint(0, 255) for _ in range(50)])
        noise_len = max(1, int(len(data) * noise_ratio))
        noise = bytes([self.rng.randint(0, 255) for _ in range(noise_len)])
        pos = self.rng.randint(0, len(data))
        return data[:pos] + noise + data[pos:]
    
    def generate_mutations(self, base_case: AdversarialTestCase, num_variants: int = 20) -> List[AdversarialTestCase]:
        """Generate multiple mutated variants from a base case."""
        variants = []
        
        probe_data = bytes.fromhex(base_case.probe_data) if base_case.probe_data else b""
        
        for i in range(num_variants):
            mutation_type = self.rng.choice([
                "byte_flip", "byte_insertion", "byte_deletion", "truncation",
                "case_mutation", "header_reorder", "timing_jitter", "binary_noise",
                "truncation_extreme", "double_mutation"
            ])
            
            mutated_probe = probe_data
            mutation_tags = [mutation_type]
            
            if mutation_type == "byte_flip":
                mutated_probe = self.byte_flip(probe_data, self.rng.randint(1, 10))
            elif mutation_type == "byte_insertion":
                mutated_probe = self.byte_insertion(probe_data, self.rng.randint(1, 20))
            elif mutation_type == "byte_deletion":
                mutated_probe = self.byte_deletion(probe_data, self.rng.randint(1, 5))
            elif mutation_type == "truncation":
                mutated_probe = self.truncation(probe_data, self.rng.uniform(0.1, 0.8))
            elif mutation_type == "case_mutation":
                text = probe_data.decode('utf-8', errors='ignore')
                mutated_probe = self.case_mutation(text).encode('utf-8')
            elif mutation_type == "timing_jitter":
                base_delay = base_case.delay_ms if base_case.delay_ms > 0 else 1000
                new_delay = self.timing_jitter(base_delay, 2000)
                mutated_case = AdversarialTestCase(
                    id=f"{base_case.id}_mut_{i:03d}",
                    host=base_case.host,
                    port=base_case.port + self.rng.randint(-100, 100),
                    expected_service=base_case.expected_service,
                    scenario_type=base_case.scenario_type,
                    scenario_subtype=f"{base_case.scenario_subtype}_timing",
                    description=f"{base_case.description} + timing jitter ({new_delay}ms)",
                    difficulty="evil",
                    expected_behavior="ambiguous",
                    delay_ms=new_delay,
                    probe_data=probe_data.hex() if probe_data else "",
                    mutation_tags=["timing_jitter"],
                    base_case_id=base_case.id,
                )
                variants.append(mutated_case)
                continue
            elif mutation_type == "binary_noise":
                mutated_probe = self.inject_binary_noise(probe_data, self.rng.uniform(0.1, 0.5))
            elif mutation_type == "truncation_extreme":
                mutated_probe = self.truncation(probe_data, self.rng.uniform(0.01, 0.3))
            elif mutation_type == "double_mutation":
                mutated_probe = self.byte_flip(probe_data, 5)
                mutated_probe = self.byte_insertion(mutated_probe, 3)
                mutation_tags = ["byte_flip", "byte_insertion"]
            
            # Generate mutated case
            mutated_port = base_case.port + self.rng.randint(-50, 50)
            mutated_port = max(1, min(65535, mutated_port))
            
            mutated_case = AdversarialTestCase(
                id=f"{base_case.id}_mut_{i:03d}",
                host=base_case.host,
                port=mutated_port,
                expected_service=base_case.expected_service,
                scenario_type=base_case.scenario_type,
                scenario_subtype=f"{base_case.scenario_subtype}_{mutation_type}",
                description=f"{base_case.description} + {mutation_type} mutation",
                difficulty="evil" if base_case.difficulty in ["hard", "evil"] else "hard",
                expected_behavior="ambiguous",
                probe_data=mutated_probe.hex() if mutated_probe else "",
                mutation_tags=mutation_tags,
                base_case_id=base_case.id,
            )
            variants.append(mutated_case)
        
        return variants


# =============================================================================
# SCENARIO GENERATORS (12 CATEGORIES)
# =============================================================================

class ScenarioGenerators:
    """Generate test cases for each adversarial scenario category."""
    
    def __init__(self):
        self.case_counter = 0
        self.rng = random.Random(RANDOM_SEED)
    
    def _next_id(self, prefix: str) -> str:
        self.case_counter += 1
        return f"{prefix}_{self.case_counter:05d}"
    
    # 1. PARTIAL / TRUNCATED BANNERS
    def generate_partial_banners(self, target: int = 500) -> List[AdversarialTestCase]:
        """Generate truncated/partial banner cases."""
        cases = []
        
        banners = {
            "ssh": [b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu2.2", b"SSH-2.0-dropbear_2020.81", b"SSH-1.99-OpenSSH_7.4"],
            "http": [b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Type: text/html\r\n\r\n", b"HTTP/1.0 404 Not Found\r\nServer: nginx"],
            "redis": [b"+PONG\r\n", b"+OK\r\n", b"-ERR unknown command 'INVALID'\r\n"],
            "postgresql": [b"R\x00\x00\x00\x08\x00\x00\x00\x00", b"E\x00\x00\x00\x05F"],
            "ftp": [b"220 (vsFTPd 3.0.3)\r\n", b"220 Welcome to FTP Service\r\n"],
            "smtp": [b"220 mail.example.com ESMTP Postfix\r\n", b"220-smtp.example.com\r\n"],
        }
        
        truncation_points = [1, 2, 3, 5, 8, 10, 15, 20, 25, 30, 40, 50]
        
        for service, banner_list in banners.items():
            for banner in banner_list:
                for trunc_pt in truncation_points:
                    if len(banner) > trunc_pt:
                        truncated = banner[:trunc_pt]
                        port = self.rng.choice([22, 80, 6379, 5432, 21, 25, 8080, 3000, 5000, 8888])
                        
                        cases.append(AdversarialTestCase(
                            id=self._next_id("PARTIAL"),
                            host="127.0.0.1",
                            port=port,
                            expected_service=service,
                            scenario_type="partial_banner",
                            scenario_subtype="truncation",
                            description=f"Truncated {service} banner at byte {trunc_pt}: {truncated[:20]}",
                            difficulty="hard" if trunc_pt < 10 else "medium",
                            expected_behavior="ambiguous" if trunc_pt < 15 else "unknown",
                            probe_data=truncated.hex(),
                        ))
        
        # Mid-header EOF cases
        headers = [
            b"HTTP/1.1 200 OK\r\nServer: Apache\r\nContent-Type: text/html\r\nContent-Length: 1234\r\n",
            b"SSH-2.0-OpenSSH_8.2p1\r\n",
            b"220 mail.example.com ESMTP Postfix (Ubuntu)\r\n",
        ]
        
        for header in headers:
            for _ in range(30):
                cutoff = self.rng.randint(1, len(header) - 1)
                partial = header[:cutoff]
                service = "http" if b"HTTP" in partial else ("ssh" if b"SSH" in partial else "smtp")
                
                cases.append(AdversarialTestCase(
                    id=self._next_id("PARTIAL"),
                    host="127.0.0.1",
                    port=self.rng.choice([80, 22, 25, 8080, 443]),
                    expected_service=service,
                    scenario_type="partial_banner",
                    scenario_subtype="mid_header_eof",
                    description=f"Mid-header EOF in {service} at byte {cutoff}",
                    difficulty="evil",
                    expected_behavior="ambiguous",
                    probe_data=partial.hex(),
                ))
        
        while len(cases) < target:
            # Generate additional variants
            base_banner = self.rng.choice([b"SSH-2.0-", b"HTTP/1.1 ", b"+P", b"220 ", b"R\x00"])
            extra_bytes = self.rng.randint(1, 5)
            truncated = base_banner[:self.rng.randint(1, min(len(base_banner), 8))]
            
            cases.append(AdversarialTestCase(
                id=self._next_id("PARTIAL"),
                host="127.0.0.1",
                port=self.rng.randint(1, 65535),
                expected_service="unknown",
                scenario_type="partial_banner",
                scenario_subtype="extreme_truncation",
                description=f"Extreme truncation: {truncated}",
                difficulty="evil",
                expected_behavior="unknown",
                probe_data=truncated.hex(),
            ))
        
        return cases[:target]
    
    # 2. PROTOCOL CONFUSION
    def generate_protocol_confusion(self, target: int = 600) -> List[AdversarialTestCase]:
        """Generate protocol confusion cases."""
        cases = []
        
        confusion_matrix = [
            # (actual_service, fake_banner, ports)
            ("ssh", b"HTTP/1.1 200 OK\r\nServer: OpenSSH\r\n\r\n", [22, 2222, 22222]),
            ("ssh", b"+PONG\r\n", [22, 2222]),
            ("http", b"SSH-2.0-Apache_Httpd\r\n", [80, 8080, 3000, 5000]),
            ("http", b"R\x00\x00\x00\x08", [80, 8080]),
            ("redis", b"HTTP/1.1 200 OK\r\nServer: Redis\r\n\r\n", [6379, 16379, 26379]),
            ("redis", b"SSH-2.0-Redis\r\n", [6379]),
            ("postgresql", b"+PONG\r\n", [5432, 15432]),
            ("postgresql", b"HTTP/1.1 200 OK\r\n", [5432]),
            ("ftp", b"SSH-2.0-FTP\r\n", [21]),
            ("smtp", b"+PONG\r\n", [25]),
            ("telnet", b"HTTP/1.1 200 OK\r\n", [23]),
            ("https", b"SSH-2.0-SecureServer\r\n", [443, 8443]),
        ]
        
        for actual_svc, fake_banner, ports in confusion_matrix:
            for port in ports:
                for _ in range(10):
                    mutated_banner = fake_banner
                    # Add variations
                    if self.rng.random() < 0.5:
                        mutated_banner = fake_banner + bytes([self.rng.randint(0, 255) for _ in range(self.rng.randint(1, 10))])
                    
                    cases.append(AdversarialTestCase(
                        id=self._next_id("CONFUSE"),
                        host="127.0.0.1",
                        port=port,
                        expected_service=actual_svc,
                        scenario_type="protocol_confusion",
                        scenario_subtype=f"{actual_svc}_pretending",
                        description=f"{actual_svc} sending {fake_banner[:30]} on port {port}",
                        difficulty="evil",
                        expected_behavior="ambiguous",
                        probe_data=mutated_banner.hex(),
                    ))
        
        # Cross-protocol hybrid banners
        hybrid_banners = [
            b"SSH-2.0-OpenSSH\r\nHTTP/1.1 200 OK\r\n",
            b"HTTP/1.1 200 OK\r\n+PONG\r\n",
            b"220 FTP ready\r\nSSH-2.0-FTP\r\n",
            b"+PONG\r\nR\x00\x00\x00\x08",
            b"SSH-2.0-OpenSSH\r\n220 SMTP ready\r\n",
        ]
        
        for hybrid in hybrid_banners:
            for _ in range(50):
                port = self.rng.randint(1, 65535)
                cases.append(AdversarialTestCase(
                    id=self._next_id("CONFUSE"),
                    host="127.0.0.1",
                    port=port,
                    expected_service="unknown",
                    scenario_type="protocol_confusion",
                    scenario_subtype="hybrid_banner",
                    description=f"Hybrid multi-protocol banner on port {port}",
                    difficulty="evil",
                    expected_behavior="ambiguous",
                    probe_data=hybrid.hex(),
                ))
        
        return cases[:target]
    
    # 3. TIMING ATTACKS
    def generate_timing_attacks(self, target: int = 500) -> List[AdversarialTestCase]:
        """Generate timing-based attack cases."""
        cases = []
        
        delays = [
            (50, "near_timeout"),
            (100, "near_timeout"),
            (500, "delayed_response"),
            (1000, "delayed_response"),
            (2000, "slow_response"),
            (3000, "slow_response"),
            (4500, "near_timeout"),
            (5000, "at_timeout_boundary"),
            (7000, "beyond_timeout"),
            (10000, "far_beyond_timeout"),
        ]
        
        services = ["ssh", "http", "redis", "postgresql", "ftp", "unknown"]
        
        for delay_ms, delay_type in delays:
            for service in services:
                for _ in range(15):
                    port = self.rng.choice([22, 80, 6379, 5432, 21, 8080, 3000, 443])
                    
                    cases.append(AdversarialTestCase(
                        id=self._next_id("TIMING"),
                        host="127.0.0.1",
                        port=port,
                        expected_service=service,
                        scenario_type="timing_attack",
                        scenario_subtype=delay_type,
                        description=f"{service} with {delay_ms}ms delay ({delay_type})",
                        difficulty="evil" if delay_ms >= 3000 else "hard",
                        expected_behavior="unknown" if delay_ms >= 5000 else "ambiguous",
                        delay_ms=delay_ms,
                    ))
        
        # Split packet timing
        for _ in range(100):
            delay = self.rng.randint(100, 5000)
            cases.append(AdversarialTestCase(
                id=self._next_id("TIMING"),
                host="127.0.0.1",
                port=self.rng.randint(1, 65535),
                expected_service=self.rng.choice(["http", "ssh", "unknown"]),
                scenario_type="timing_attack",
                scenario_subtype="split_packet",
                description=f"Split packet with {delay}ms inter-packet delay",
                difficulty="evil",
                expected_behavior="ambiguous",
                delay_ms=delay,
            ))
        
        # First byte delay vs full payload
        for delay in [100, 500, 1000, 2000, 3000]:
            for _ in range(20):
                cases.append(AdversarialTestCase(
                    id=self._next_id("TIMING"),
                    host="127.0.0.1",
                    port=self.rng.choice([80, 22, 443]),
                    expected_service="http",
                    scenario_type="timing_attack",
                    scenario_subtype="first_byte_delay",
                    description=f"First byte delayed by {delay}ms, then full payload",
                    difficulty="hard",
                    expected_behavior="ambiguous",
                    delay_ms=delay,
                ))
        
        return cases[:target]
    
    # 4. GARBAGE / NOISE INJECTION
    def generate_garbage_noise(self, target: int = 700) -> List[AdversarialTestCase]:
        """Generate garbage and noise injection cases."""
        cases = []
        
        valid_banners = [
            (b"SSH-2.0-OpenSSH_8.2p1", "ssh"),
            (b"HTTP/1.1 200 OK\r\n", "http"),
            (b"+PONG\r\n", "redis"),
            (b"220 FTP ready\r\n", "ftp"),
        ]
        
        # Random binary noise
        for _ in range(200):
            noise_len = self.rng.randint(10, 500)
            noise = bytes([self.rng.randint(0, 255) for _ in range(noise_len)])
            
            cases.append(AdversarialTestCase(
                id=self._next_id("NOISE"),
                host="127.0.0.1",
                port=self.rng.randint(1, 65535),
                expected_service="unknown",
                scenario_type="garbage_noise",
                scenario_subtype="random_binary",
                description=f"Random binary noise ({noise_len} bytes, entropy: high)",
                difficulty="evil",
                expected_behavior="unknown",
                probe_data=noise.hex(),
            ))
        
        # Valid banner + noise prefix/suffix
        for banner, service in valid_banners:
            for _ in range(50):
                noise_prefix = bytes([self.rng.randint(0, 255) for _ in range(self.rng.randint(5, 50))])
                noise_suffix = bytes([self.rng.randint(0, 255) for _ in range(self.rng.randint(5, 50))])
                
                corrupted = noise_prefix + banner + noise_suffix
                
                cases.append(AdversarialTestCase(
                    id=self._next_id("NOISE"),
                    host="127.0.0.1",
                    port=self.rng.choice([22, 80, 6379, 21, 8080]),
                    expected_service=service,
                    scenario_type="garbage_noise",
                    scenario_subtype="noise_around_valid",
                    description=f"{service} banner with random prefix/suffix noise",
                    difficulty="evil",
                    expected_behavior="ambiguous",
                    probe_data=corrupted.hex(),
                ))
        
        # Corrupted encodings
        for _ in range(100):
            text = f"HTTP/1.1 200 OK\r\nServer: Test\r\n\r\n"
            corrupted = text.encode('utf-8')
            # Inject invalid UTF-8 sequences
            pos = self.rng.randint(0, len(corrupted))
            corrupted = corrupted[:pos] + b"\xff\xfe\x00\x80" + corrupted[pos:]
            
            cases.append(AdversarialTestCase(
                id=self._next_id("NOISE"),
                host="127.0.0.1",
                port=self.rng.choice([80, 8080, 3000]),
                expected_service="http",
                scenario_type="garbage_noise",
                scenario_subtype="corrupted_encoding",
                description="HTTP banner with corrupted UTF-8 encoding",
                difficulty="hard",
                expected_behavior="ambiguous",
                probe_data=corrupted.hex(),
            ))
        
        # High entropy payloads
        for _ in range(150):
            payload = bytes([self.rng.randint(0, 255) for _ in range(self.rng.randint(50, 200))])
            # Mix in some ASCII
            ascii_part = b"VALID_BANNER_MIXED"
            pos = self.rng.randint(0, len(payload))
            payload = payload[:pos] + ascii_part + payload[pos:]
            
            cases.append(AdversarialTestCase(
                id=self._next_id("NOISE"),
                host="127.0.0.1",
                port=self.rng.randint(1, 65535),
                expected_service="unknown",
                scenario_type="garbage_noise",
                scenario_subtype="high_entropy_mixed",
                description=f"High entropy payload with ASCII fragment",
                difficulty="evil",
                expected_behavior="unknown",
                probe_data=payload.hex(),
            ))
        
        return cases[:target]
    
    # 5. FILTERED vs CLOSED vs SILENT
    def generate_filtered_closed(self, target: int = 400) -> List[AdversarialTestCase]:
        """Generate filtered/closed/silent port cases."""
        cases = []
        
        # No response (silent)
        for _ in range(150):
            port = self.rng.randint(1, 65535)
            cases.append(AdversarialTestCase(
                id=self._next_id("FILTER"),
                host="127.0.0.1",
                port=port,
                expected_service="filtered",
                scenario_type="filtered_closed",
                scenario_subtype="no_response",
                description=f"Silent port {port} (no response, timeout)",
                difficulty="hard",
                expected_behavior="filtered",
            ))
        
        # Immediate RST (closed)
        for _ in range(100):
            port = self.rng.choice([1, 9990, 9991, 9992, 65535, 65534, 12345, 54321])
            cases.append(AdversarialTestCase(
                id=self._next_id("FILTER"),
                host="127.0.0.1",
                port=port,
                expected_service="filtered",
                scenario_type="filtered_closed",
                scenario_subtype="immediate_rst",
                description=f"Port {port} closed (immediate RST)",
                difficulty="medium",
                expected_behavior="filtered",
            ))
        
        # Delayed close
        for delay in [100, 500, 1000, 2000]:
            for _ in range(30):
                port = self.rng.randint(10000, 60000)
                cases.append(AdversarialTestCase(
                    id=self._next_id("FILTER"),
                    host="127.0.0.1",
                    port=port,
                    expected_service="filtered",
                    scenario_type="filtered_closed",
                    scenario_subtype="delayed_close",
                    description=f"Port {port} with delayed close ({delay}ms)",
                    difficulty="hard",
                    expected_behavior="filtered",
                    delay_ms=delay,
                ))
        
        return cases[:target]
    
    # 6. HONEYPOT / DECEPTION
    def generate_honeypot(self, target: int = 400) -> List[AdversarialTestCase]:
        """Generate honeypot/deception cases."""
        cases = []
        
        # Fake SSH banners
        fake_ssh = [
            b"SSH-2.0-OpenSSH_9.0",
            b"SSH-2.0-OpenSSH_8.9",
            b"SSH-2.0-dropbear_2022.83",
            b"SSH-1.99-OpenSSH_7.4",
        ]
        
        for banner in fake_ssh:
            for _ in range(40):
                port = self.rng.choice([22, 2222, 22222, 8022, 2200])
                cases.append(AdversarialTestCase(
                    id=self._next_id("HONEY"),
                    host="127.0.0.1",
                    port=port,
                    expected_service="unknown",
                    scenario_type="honeypot",
                    scenario_subtype="fake_ssh",
                    description=f"Fake SSH banner '{banner.decode()}' but actually HTTP follows",
                    difficulty="evil",
                    expected_behavior="ambiguous",
                    probe_data=banner.hex(),
                ))
        
        # Multi-service hybrid (rotating)
        rotating_sequences = [
            [b"SSH-2.0-OpenSSH\r\n", b"HTTP/1.1 200 OK\r\n"],
            [b"+PONG\r\n", b"SSH-2.0-Redis\r\n"],
            [b"220 FTP\r\n", b"HTTP/1.1 404\r\n"],
        ]
        
        for seq in rotating_sequences:
            for _ in range(50):
                port = self.rng.randint(1000, 60000)
                cases.append(AdversarialTestCase(
                    id=self._next_id("HONEY"),
                    host="127.0.0.1",
                    port=port,
                    expected_service="unknown",
                    scenario_type="honeypot",
                    scenario_subtype="rotating_banner",
                    description=f"Rotating banner sequence on port {port}",
                    difficulty="evil",
                    expected_behavior="ambiguous",
                    probe_data=seq[0].hex(),
                ))
        
        # Cowrie honeypot emulation
        cowrie_banners = [
            b"SSH-2.0-OpenSSH_8.51",
            b"SSH-2.0-OpenSSH_7.4p1",
            b"SSH-2.0-dropbear_2019.78",
        ]
        
        for banner in cowrie_banners:
            for _ in range(30):
                cases.append(AdversarialTestCase(
                    id=self._next_id("HONEY"),
                    host="127.0.0.1",
                    port=self.rng.choice([22, 2222, 22222]),
                    expected_service="honeypot",
                    scenario_type="honeypot",
                    scenario_subtype="cowrie",
                    description=f"Cowrie honeypot: {banner.decode()}",
                    difficulty="evil",
                    expected_behavior="ambiguous",
                    probe_data=banner.hex(),
                ))
        
        return cases[:target]
    
    # 7. NON-STANDARD PORTS (EXTREME)
    def generate_nonstandard_ports(self, target: int = 800) -> List[AdversarialTestCase]:
        """Generate extreme non-standard port cases."""
        cases = []
        
        services = {
            "ssh": [b"SSH-2.0-OpenSSH_8.2p1"],
            "http": [b"HTTP/1.1 200 OK\r\nServer: Test\r\n\r\n"],
            "https": [b"HTTP/1.1 200 OK\r\nServer: Secure\r\n\r\n"],
            "redis": [b"+PONG\r\n"],
            "postgresql": [b"R\x00\x00\x00\x08"],
            "ftp": [b"220 FTP ready\r\n"],
        }
        
        # Each service on 50+ different random ports
        for service, banners in services.items():
            ports_used = set()
            for _ in range(80):
                port = self.rng.randint(1, 65535)
                while port in ports_used:
                    port = self.rng.randint(1, 65535)
                ports_used.add(port)
                
                banner = self.rng.choice(banners)
                
                cases.append(AdversarialTestCase(
                    id=self._next_id("NONSTD"),
                    host="127.0.0.1",
                    port=port,
                    expected_service=service,
                    scenario_type="nonstandard_port",
                    scenario_subtype=f"{service}_on_random",
                    description=f"{service} on non-standard port {port}",
                    difficulty="hard",
                    expected_behavior="correct",
                    probe_data=banner.hex(),
                ))
        
        # Conflicting signals (port says HTTP, banner says SSH)
        for _ in range(200):
            port = self.rng.choice([80, 8080, 3000, 5000, 9000])
            cases.append(AdversarialTestCase(
                id=self._next_id("NONSTD"),
                host="127.0.0.1",
                port=port,
                expected_service="http",
                scenario_type="nonstandard_port",
                scenario_subtype="conflicting_signals",
                description=f"Port {port} suggests HTTP but banner is SSH",
                difficulty="evil",
                expected_behavior="ambiguous",
                probe_data=b"SSH-2.0-OpenSSH_8.2p1".hex(),
            ))
        
        return cases[:target]
    
    # 8. STATEFUL PROTOCOL EDGE CASES
    def generate_stateful_protocols(self, target: int = 300) -> List[AdversarialTestCase]:
        """Generate stateful protocol edge cases."""
        cases = []
        
        # PostgreSQL partial handshake
        pg_handshakes = [
            b"\x00\x00\x00\x10\x00\x03\x00\x00user\x00\x00",
            b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
            b"\x00\x00\x00\x10\x00\x03\x00\x00",
        ]
        
        for handshake in pg_handshakes:
            for _ in range(40):
                port = self.rng.choice([5432, 15432, 5433, 5434, 6432])
                cases.append(AdversarialTestCase(
                    id=self._next_id("STATE"),
                    host="127.0.0.1",
                    port=port,
                    expected_service="postgresql",
                    scenario_type="stateful_protocol",
                    scenario_subtype="pg_partial_handshake",
                    description=f"PostgreSQL partial handshake on port {port}",
                    difficulty="hard",
                    expected_behavior="ambiguous",
                    probe_data=handshake.hex(),
                ))
        
        # Redis requiring AUTH
        redis_auth_seqs = [
            b"AUTH password\r\n",
            b"PING\r\n",
            b"SELECT 0\r\n",
        ]
        
        for seq in redis_auth_seqs:
            for _ in range(30):
                port = self.rng.choice([6379, 16379, 26379])
                cases.append(AdversarialTestCase(
                    id=self._next_id("STATE"),
                    host="127.0.0.1",
                    port=port,
                    expected_service="redis",
                    scenario_type="stateful_protocol",
                    scenario_subtype="redis_auth_required",
                    description=f"Redis requiring AUTH on port {port}",
                    difficulty="evil",
                    expected_behavior="unknown",
                    probe_data=seq.hex(),
                ))
        
        # Multi-step responses truncated
        for _ in range(80):
            port = self.rng.choice([5432, 6379, 80])
            cases.append(AdversarialTestCase(
                id=self._next_id("STATE"),
                host="127.0.0.1",
                port=port,
                expected_service="unknown",
                scenario_type="stateful_protocol",
                scenario_subtype="multistep_truncated",
                description=f"Multi-step protocol response truncated on port {port}",
                difficulty="evil",
                expected_behavior="ambiguous",
            ))
        
        return cases[:target]
    
    # 9. EDGE PORT CONDITIONS
    def generate_edge_ports(self, target: int = 300) -> List[AdversarialTestCase]:
        """Generate edge port condition cases."""
        cases = []
        
        edge_ports = [0, 1, 2, 7, 9, 19, 79, 111, 135, 139, 445, 65534, 65535]
        
        for port in edge_ports:
            for _ in range(20):
                expected = "filtered" if port < 10 else "unknown"
                cases.append(AdversarialTestCase(
                    id=self._next_id("EDGE"),
                    host="127.0.0.1",
                    port=port,
                    expected_service=expected,
                    scenario_type="edge_port",
                    scenario_subtype=f"port_{port}",
                    description=f"Edge port {port} (reserved/system)",
                    difficulty="medium",
                    expected_behavior="filtered" if port < 10 else "unknown",
                ))
        
        # Rapid open/close race conditions
        for _ in range(100):
            port = self.rng.randint(10000, 60000)
            cases.append(AdversarialTestCase(
                id=self._next_id("EDGE"),
                host="127.0.0.1",
                port=port,
                expected_service="unknown",
                scenario_type="edge_port",
                scenario_subtype="race_condition",
                description=f"Rapid open/close race on port {port}",
                difficulty="evil",
                expected_behavior="ambiguous",
            ))
        
        return cases[:target]
    
    # 10. REAL-WORLD CHAOS
    def generate_realworld_chaos(self, target: int = 500) -> List[AdversarialTestCase]:
        """Generate real-world chaos cases."""
        cases = []
        
        # Mixed valid + invalid packets
        for _ in range(150):
            valid = self.rng.choice([b"HTTP/1.1 200 OK\r\n", b"SSH-2.0-OpenSSH\r\n", b"+PONG\r\n"])
            invalid = bytes([self.rng.randint(0, 255) for _ in range(self.rng.randint(10, 100))])
            
            # Interleave
            mixed = b""
            v_idx, i_idx = 0, 0
            while v_idx < len(valid) or i_idx < len(invalid):
                if v_idx < len(valid) and self.rng.random() < 0.7:
                    mixed += valid[v_idx:v_idx+1]
                    v_idx += 1
                elif i_idx < len(invalid):
                    mixed += invalid[i_idx:i_idx+1]
                    i_idx += 1
                else:
                    break
            
            cases.append(AdversarialTestCase(
                id=self._next_id("CHAOS"),
                host="127.0.0.1",
                port=self.rng.randint(1, 65535),
                expected_service="unknown",
                scenario_type="realworld_chaos",
                scenario_subtype="mixed_packets",
                description=f"Mixed valid/invalid packets ({len(mixed)} bytes)",
                difficulty="evil",
                expected_behavior="unknown",
                probe_data=mixed.hex(),
            ))
        
        # Load-induced corruption
        for _ in range(100):
            banner = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n"
            # Corrupt random bytes
            corrupted = bytearray(banner)
            num_corrupt = self.rng.randint(1, 10)
            for _ in range(num_corrupt):
                pos = self.rng.randint(0, len(corrupted) - 1)
                corrupted[pos] = self.rng.randint(0, 255)
            
            cases.append(AdversarialTestCase(
                id=self._next_id("CHAOS"),
                host="127.0.0.1",
                port=self.rng.choice([80, 8080, 443]),
                expected_service="http",
                scenario_type="realworld_chaos",
                scenario_subtype="load_corruption",
                description=f"Load-induced corruption ({num_corrupt} bytes corrupted)",
                difficulty="hard",
                expected_behavior="ambiguous",
                probe_data=bytes(corrupted).hex(),
            ))
        
        # Intermittent responses
        for _ in range(150):
            port = self.rng.randint(1000, 60000)
            cases.append(AdversarialTestCase(
                id=self._next_id("CHAOS"),
                host="127.0.0.1",
                port=port,
                expected_service=self.rng.choice(["http", "ssh", "unknown"]),
                scenario_type="realworld_chaos",
                scenario_subtype="intermittent",
                description=f"Intermittent response on port {port} (works every 2nd run)",
                difficulty="evil",
                expected_behavior="ambiguous",
            ))
        
        return cases[:target]
    
    # 11. CONFIDENCE BREAKING CASES
    def generate_confidence_breaking(self, target: int = 500) -> List[AdversarialTestCase]:
        """Generate confidence scoring attack cases."""
        cases = []
        
        # Weak signals that should be low confidence
        weak_signals = [
            (b"SSH-", "ssh", "ssh_partial_signature"),
            (b"HTT", "http", "http_truncated"),
            (b"+P", "redis", "redis_partial"),
            (b"220", "ftp", "ftp_code_only"),
            (b"R\x00", "postgresql", "pg_binary_fragment"),
        ]
        
        for signal, service, subtype in weak_signals:
            for _ in range(60):
                port = self.rng.choice([22, 80, 6379, 21, 5432, 8080, 3000])
                cases.append(AdversarialTestCase(
                    id=self._next_id("CONFID"),
                    host="127.0.0.1",
                    port=port,
                    expected_service=service,
                    scenario_type="confidence_breaking",
                    scenario_subtype=subtype,
                    description=f"Weak signal '{signal}' for {service} - should be low confidence",
                    difficulty="evil",
                    expected_behavior="ambiguous",
                    probe_data=signal.hex(),
                ))
        
        # Conflicting heuristics
        for _ in range(150):
            # Banner matches multiple services
            conflicting = self.rng.choice([
                b"220-ESMTP SSH-2.0-OpenSSH",
                b"+OK POP3 server HTTP/1.1",
                b"SSH-2.0-HTTP/1.1 200 OK",
            ])
            
            cases.append(AdversarialTestCase(
                id=self._next_id("CONFID"),
                host="127.0.0.1",
                port=self.rng.randint(1, 65535),
                expected_service="unknown",
                scenario_type="confidence_breaking",
                scenario_subtype="conflicting_heuristics",
                description=f"Conflicting heuristics: {conflicting.decode(errors='ignore')}",
                difficulty="evil",
                expected_behavior="ambiguous",
                probe_data=conflicting.hex(),
            ))
        
        # Force overconfidence failures
        for _ in range(140):
            # Strong-looking but wrong banner
            strong_wrong = self.rng.choice([
                b"HTTP/1.1 200 OK\r\nServer: SSH-2.0-OpenSSH_8.2p1\r\n\r\n",
                b"SSH-2.0-OpenSSH\r\n+PONG\r\n",
                b"HTTP/1.1 200 OK\r\nServer: Redis/6.2.6\r\n\r\n",
            ])
            
            cases.append(AdversarialTestCase(
                id=self._next_id("CONFID"),
                host="127.0.0.1",
                port=self.rng.choice([80, 22, 6379]),
                expected_service="unknown",
                scenario_type="confidence_breaking",
                scenario_subtype="overconfidence_trap",
                description=f"Strong-looking but misleading banner",
                difficulty="evil",
                expected_behavior="ambiguous",
                probe_data=strong_wrong.hex(),
            ))
        
        return cases[:target]
    
    # 12. MASS SCALING
    def generate_mass_scaling(self, target: int = 5000) -> List[AdversarialTestCase]:
        """Generate mass scaling cases with near-duplicates."""
        cases = []
        
        base_templates = [
            {"service": "ssh", "banner": b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu2.2"},
            {"service": "http", "banner": b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n"},
            {"service": "redis", "banner": b"+PONG\r\n"},
            {"service": "postgresql", "banner": b"R\x00\x00\x00\x08"},
            {"service": "ftp", "banner": b"220 (vsFTPd 3.0.3)\r\n"},
            {"service": "unknown", "banner": b"RandomService v1.0"},
        ]
        
        mutation_types = [
            "1_byte_diff",
            "timing_jitter",
            "case_change",
            "whitespace_change",
            "header_order",
        ]
        
        cases_per_template = target // len(base_templates)
        
        for template in base_templates:
            for i in range(cases_per_template):
                port = self.rng.randint(1, 65535)
                mutation = self.rng.choice(mutation_types)
                
                # Apply mutation
                banner = template["banner"]
                if mutation == "1_byte_diff":
                    pos = self.rng.randint(0, len(banner) - 1)
                    banner = banner[:pos] + bytes([(banner[pos] + 1) % 256]) + banner[pos+1:]
                elif mutation == "timing_jitter":
                    pass  # Will add delay_ms
                elif mutation == "case_change":
                    text = banner.decode('utf-8', errors='ignore')
                    banner = text.swapcase().encode('utf-8')
                elif mutation == "whitespace_change":
                    text = banner.decode('utf-8', errors='ignore')
                    text = text.replace(" ", "\t") if " " in text else text + " "
                    banner = text.encode('utf-8')
                
                delay = self.rng.randint(0, 2000) if mutation == "timing_jitter" else 0
                
                cases.append(AdversarialTestCase(
                    id=self._next_id("SCALE"),
                    host="127.0.0.1",
                    port=port,
                    expected_service=template["service"],
                    scenario_type="mass_scaling",
                    scenario_subtype=mutation,
                    description=f"Mass scaled {template['service']} case #{i} (mutation: {mutation})",
                    difficulty=self.rng.choice(["easy", "medium", "hard", "evil"]),
                    expected_behavior="correct" if template["service"] != "unknown" else "unknown",
                    probe_data=banner.hex(),
                    delay_ms=delay,
                ))
        
        return cases[:target]
    
    def generate_all(self) -> List[AdversarialTestCase]:
        """Generate all scenario categories."""
        print("=" * 70)
        print("GENERATING ADVERSARIAL DATASET V2")
        print("=" * 70)
        
        all_cases = []
        
        generators = [
            ("Partial/Truncated Banners", self.generate_partial_banners, 500),
            ("Protocol Confusion", self.generate_protocol_confusion, 600),
            ("Timing Attacks", self.generate_timing_attacks, 500),
            ("Garbage/Noise Injection", self.generate_garbage_noise, 700),
            ("Filtered/Closed/Silent", self.generate_filtered_closed, 400),
            ("Honeypot/Deception", self.generate_honeypot, 400),
            ("Non-Standard Ports", self.generate_nonstandard_ports, 800),
            ("Stateful Protocols", self.generate_stateful_protocols, 300),
            ("Edge Port Conditions", self.generate_edge_ports, 300),
            ("Real-World Chaos", self.generate_realworld_chaos, 500),
            ("Confidence Breaking", self.generate_confidence_breaking, 500),
            ("Mass Scaling", self.generate_mass_scaling, 5000),
        ]
        
        for name, gen_func, target in generators:
            print(f"\nGenerating: {name} (target: {target})...")
            cases = gen_func(target)
            all_cases.extend(cases)
            print(f"  ✓ Generated {len(cases)} cases")
        
        print(f"\n{'=' * 70}")
        print(f"TOTAL: {len(all_cases)} test cases")
        print(f"{'=' * 70}")
        
        # Difficulty distribution
        diff_counts = defaultdict(int)
        for case in all_cases:
            diff_counts[case.difficulty] += 1
        
        print(f"\nDifficulty Distribution:")
        for diff in ["easy", "medium", "hard", "evil"]:
            count = diff_counts.get(diff, 0)
            pct = count / len(all_cases) * 100
            print(f"  {diff}: {count} ({pct:.1f}%)")
        
        hard_evil_pct = (diff_counts.get("hard", 0) + diff_counts.get("evil", 0)) / len(all_cases) * 100
        print(f"\nHard+Evil: {hard_evil_pct:.1f}%")
        
        return all_cases


# =============================================================================
# EVALUATION ENGINE
# =============================================================================

class AdversarialEvaluationEngine:
    """Run adversarial tests against service detector and compute metrics."""
    
    def __init__(self, detector):
        self.detector = detector
        self.results = []
        self.rng = random.Random(RANDOM_SEED)
    
    async def run_single_test(self, test_case: AdversarialTestCase) -> Dict[str, Any]:
        """Run a single adversarial test case (mocked for dataset generation)."""
        # This would normally connect to the service detector
        # For dataset generation, we simulate expected outcomes
        return {
            "test_id": test_case.id,
            "port": test_case.port,
            "expected_service": test_case.expected_service,
            "scenario_type": test_case.scenario_type,
            "difficulty": test_case.difficulty,
        }
    
    def compute_metrics(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compute comprehensive metrics from results."""
        if not results:
            return {}
        
        # Overall accuracy
        correct = sum(1 for r in results if r.get("match", False))
        total = len(results)
        overall_accuracy = (correct / total * 100) if total > 0 else 0
        
        # Safe confidence extraction
        def safe_float(val):
            return (float(val) if isinstance(val, (int, float)) else
                    float(val) if isinstance(val, str) and val.replace('.', '', 1).isdigit() else 0.0)
        
        # Per-scenario metrics
        by_scenario = defaultdict(lambda: {
            "correct": 0, "total": 0, "confidences": [],
            "false_positives": 0, "false_negatives": 0, "unknown_rate": 0
        })
        
        for r in results:
            scenario = r.get("scenario_type", "unknown")
            by_scenario[scenario]["total"] += 1
            
            if r.get("match", False):
                by_scenario[scenario]["correct"] += 1
            
            if "confidence" in r:
                conf_val = safe_float(r["confidence"])
                by_scenario[scenario]["confidences"].append(conf_val)
                if not isinstance(conf_val, (int, float)):
                    raise ValueError(f"Invalid confidence type detected: {type(conf_val)} -> {conf_val}")
            
            if r.get("detected") not in ["unknown", "filtered"] and r.get("expected") in ["unknown", "filtered"]:
                by_scenario[scenario]["false_positives"] += 1
            
            if r.get("detected") in ["unknown", "filtered"] and r.get("expected") not in ["unknown", "filtered"]:
                by_scenario[scenario]["false_negatives"] += 1
            
            if r.get("detected") == "unknown":
                by_scenario[scenario]["unknown_rate"] += 1
        
        scenario_metrics = {}
        for scenario, stats in by_scenario.items():
            acc = (stats["correct"] / stats["total"] * 100) if stats["total"] > 0 else 0
            confidences = stats["confidences"]
            avg_conf = sum(confidences) / len(confidences) if confidences else 0
            std_conf = (
                math.sqrt(sum((c - avg_conf) ** 2 for c in confidences) / len(confidences))
                if confidences else 0
            )
            low_conf_count = sum(1 for c in confidences if c < 30)
            
            scenario_metrics[scenario] = {
                "accuracy": round(acc, 2),
                "total": stats["total"],
                "correct": stats["correct"],
                "false_positives": stats["false_positives"],
                "false_negatives": stats["false_negatives"],
                "unknown_classification_rate": round(stats["unknown_rate"] / stats["total"] * 100, 2) if stats["total"] > 0 else 0,
                "confidence": {
                    "mean": round(avg_conf, 2),
                    "std": round(std_conf, 2),
                    "low_confidence_rate": round(low_conf_count / len(confidences) * 100, 2) if confidences else 0,
                }
            }
        
        # Misclassification matrix
        confusion = defaultdict(lambda: defaultdict(int))
        for r in results:
            expected = r.get("expected", "unknown")
            detected = r.get("detected", "unknown")
            confusion[expected][detected] += 1
        
        # High confidence failures (CRITICAL BUGS)
        high_conf_failures = [
            r for r in results
            if r.get("confidence", 0) > 50 and not r.get("match", False)
        ]
        
        # Stability analysis
        by_test_case = defaultdict(list)
        for r in results:
            key = r.get("test_id", "")
            by_test_case[key].append(r.get("detected"))
        
        unstable_cases = sum(1 for detections in by_test_case.values() if len(set(detections)) > 1)
        
        metrics = {
            "summary": {
                "total_cases": total,
                "overall_accuracy": round(overall_accuracy, 2),
                "correct": correct,
                "incorrect": total - correct,
            },
            "per_scenario": scenario_metrics,
            "confusion_matrix": {k: dict(v) for k, v in confusion.items()},
            "high_confidence_failures": {
                "count": len(high_conf_failures),
                "rate": round(len(high_conf_failures) / total * 100, 2) if total > 0 else 0,
            },
            "stability": {
                "unstable_cases": unstable_cases,
                "instability_rate": round(unstable_cases / len(by_test_case) * 100, 2) if by_test_case else 0,
            },
            "timestamp": datetime.now().isoformat(),
        }
        
        return metrics
    
    def identify_failure_cases(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify and prioritize failure cases."""
        failures = []
        
        for r in results:
            failure_reasons = []
            
            # Critical: High confidence but wrong
            if r.get("confidence", 0) > 50 and not r.get("match", False):
                failure_reasons.append("CRITICAL: High confidence wrong classification")
            
            # Consistent misclassification
            if not r.get("match", False) and r.get("detected") != "unknown":
                failure_reasons.append("Consistent misclassification")
            
            # Low accuracy scenario
            scenario = r.get("scenario_type", "")
            
            failures.append({
                "test_id": r.get("test_id"),
                "port": r.get("port"),
                "expected": r.get("expected"),
                "detected": r.get("detected"),
                "confidence": r.get("confidence", 0),
                "scenario": scenario,
                "difficulty": r.get("difficulty"),
                "failure_reasons": failure_reasons,
                "severity": "CRITICAL" if "CRITICAL" in str(failure_reasons) else "HIGH" if failure_reasons else "MEDIUM",
            })
        
        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
        failures.sort(key=lambda x: severity_order.get(x["severity"], 3))
        
        return failures


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def generate_and_save_dataset(output_file: str = "adversarial_dataset_v2.json") -> List[Dict[str, Any]]:
    """Generate full dataset and save to JSON."""
    generators = ScenarioGenerators()
    all_cases = generators.generate_all()
    
    # Apply mutation engine to subset of cases
    mutation_engine = MutationEngine(seed=RANDOM_SEED)
    mutated_cases = []
    
    # Select 500 base cases for mutation
    base_cases = [c for c in all_cases if c.scenario_type != "mass_scaling"][:500]
    
    print(f"\nApplying mutations to {len(base_cases)} base cases...")
    for i, base_case in enumerate(base_cases):
        if (i + 1) % 100 == 0:
            print(f"  Mutated {i + 1}/{len(base_cases)} base cases...")
        
        # Generate 10-20 variants per base case
        num_variants = random.randint(10, 20)
        variants = mutation_engine.generate_mutations(base_case, num_variants)
        mutated_cases.extend(variants)
    
    all_cases.extend(mutated_cases)
    print(f"  ✓ Added {len(mutated_cases)} mutated variants")
    print(f"\nFinal dataset size: {len(all_cases)} test cases")
    
    # Convert to dict format
    output = [case.to_dict() for case in all_cases]
    
    # Save dataset
    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"\nDataset saved to: {output_file}")
    
    return output


def generate_summary_table(metrics: Dict[str, Any]) -> str:
    """Generate summary table."""
    table = "\n" + "=" * 80 + "\n"
    table += "SCENARIO SUMMARY TABLE\n"
    table += "=" * 80 + "\n"
    table += f"{'Scenario':<30} | {'Accuracy':>10} | {'Avg Confidence':>15} | {'Failure Mode':<20}\n"
    table += "-" * 80 + "\n"
    
    for scenario, stats in metrics.get("per_scenario", {}).items():
        accuracy = stats["accuracy"]
        avg_conf = stats["confidence"]["mean"]
        
        if accuracy < 50:
            failure_mode = "Low accuracy"
        elif stats["false_positives"] > stats["false_negatives"]:
            failure_mode = "High FP rate"
        elif stats["false_negatives"] > 0:
            failure_mode = "High FN rate"
        else:
            failure_mode = "Stable"
        
        table += f"{scenario:<30} | {accuracy:>9.1f}% | {avg_conf:>14.1f} | {failure_mode:<20}\n"
    
    table += "=" * 80 + "\n"
    return table


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Adversarial dataset generator V2")
    parser.add_argument("--output", type=str, default="adversarial_dataset_v2.json", help="Output file")
    parser.add_argument("--no-mutations", action="store_true", help="Skip mutation engine")
    args = parser.parse_args()
    
    # Generate dataset
    dataset = generate_and_save_dataset(args.output)
    
    print("\n" + "=" * 70)
    print("DATASET GENERATION COMPLETE")
    print("=" * 70)
    print(f"Total test cases: {len(dataset)}")
    print(f"Output file: {args.output}")
    
    # Generate placeholder metrics (actual evaluation requires running against scanner)
    print("\nNote: To run actual evaluation against the scanner, use:")
    print("  python -m cybersec.benchmark.adversarial_dataset_v2 --evaluate")


if __name__ == "__main__":
    main()
