"""
Adversarial-Resilient Service Detection Engine V2

Implements:
- Port state detection (OPEN/CLOSED/FILTERED)
- Dual timeout system (connect + read)
- Signal-based detection with confidence calibration
- Partial data handling
- Retry strategy for uncertain cases
"""
import asyncio
import re
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Tuple
from enum import Enum


class PortState(Enum):
    """Explicit port states."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


@dataclass
class SignalEvidence:
    """Individual signal from detection."""
    signal_type: str  # banner, handshake, structure, byte_signature
    matched_service: str
    confidence: int  # 0-100
    strength: str  # strong, moderate, weak, conflicting
    details: str = ""


@dataclass
class ServiceInfo:
    """Enhanced service detection result."""
    name: str
    confidence: int
    state: PortState
    signals: List[SignalEvidence] = field(default_factory=list)
    reasoning: str = ""
    version: Optional[str] = None
    banner: Optional[str] = None
    retries: int = 0
    unstable: bool = False


class ServiceDetector:
    """Adversarial-resilient service detector with signal-based classification."""
    
    PORT_SERVICE_MAP = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
        110: "pop3", 143: "imap", 443: "https", 445: "smb", 3306: "mysql",
        3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
        8080: "http", 8443: "https", 27017: "mongodb", 9200: "elasticsearch",
        11211: "memcached",
        1194: "openvpn", 1723: "pptp", 2049: "nfs", 3128: "squid",
        5060: "sip", 5061: "sips", 5901: "vnc", 5902: "vnc", 5903: "vnc",
        6667: "irc", 8000: "http", 8008: "http", 8888: "http", 9000: "http",
        9090: "http", 9091: "http", 2052: "cpanel", 2053: "cpanel",
        2082: "cpanel", 2083: "cpanel", 2086: "cpanel", 2087: "cpanel",
        2095: "cpanel", 2096: "cpanel", 465: "smtps", 587: "smtp",
        993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
        5000: "http", 8009: "ajp", 10000: "webmin", 32768: "rpc",
        49152: "upnp", 49153: "upnp",
        16379: "redis", 26379: "redis",
        15432: "postgresql", 5433: "postgresql", 5434: "postgresql",
        3000: "http", 5000: "http", 2222: "ssh", 22222: "ssh",
    }

    # Strong patterns (high confidence, complete signatures)
    STRONG_PATTERNS = [
        (re.compile(r"SSH-(\d+\.\d+)-([\w.\-]+)", re.IGNORECASE), "ssh", 95),
        (re.compile(r"^HTTP/1\.[01]\s+\d+", re.IGNORECASE), "http", 90),
        (re.compile(r"\+PONG\r?\n", re.IGNORECASE), "redis", 95),
        (re.compile(r"220.*vsftpd", re.IGNORECASE), "ftp", 95),
        (re.compile(r"220.*ESMTP", re.IGNORECASE), "smtp", 90),
        (re.compile(r"\* OK.*IMAP4", re.IGNORECASE), "imap", 90),
        (re.compile(r"RFB \d{3}\.\d{3}", re.IGNORECASE), "vnc", 95),
        (re.compile(r"PostgreSQL", re.IGNORECASE), "postgresql", 95),
        (re.compile(r"MongoDB", re.IGNORECASE), "mongodb", 95),
        (re.compile(r"elasticsearch", re.IGNORECASE), "elasticsearch", 95),
        (re.compile(r"memcached", re.IGNORECASE), "memcached", 95),
    ]
    
    # Moderate patterns (medium confidence)
    MODERATE_PATTERNS = [
        (re.compile(r"SSH-(\d+\.\d+)", re.IGNORECASE), "ssh", 70),
        (re.compile(r"HTTP/1\.\d", re.IGNORECASE), "http", 65),
        (re.compile(r"Server:.*Apache", re.IGNORECASE), "http", 75),
        (re.compile(r"Server:.*nginx", re.IGNORECASE), "http", 75),
        (re.compile(r"220.*FTP.*ready", re.IGNORECASE), "ftp", 75),
        (re.compile(r"\+OK.*Dovecot", re.IGNORECASE), "pop3", 80),
        (re.compile(r"-ERR.*REDIS", re.IGNORECASE), "redis", 75),
    ]
    
    # Weak patterns (low confidence - partial/truncated)
    WEAK_PATTERNS = [
        (re.compile(r"^SSH", re.IGNORECASE), "ssh", 40),
        (re.compile(r"^HTTP", re.IGNORECASE), "http", 35),
        (re.compile(r"^220", re.IGNORECASE), "ftp", 35),
        (re.compile(r"^\+OK", re.IGNORECASE), "pop3", 30),
        (re.compile(r"^\+P", re.IGNORECASE), "redis", 30),
        (re.compile(r"^R\x00", re.IGNORECASE), "postgresql", 35),
        (re.compile(r"login:", re.IGNORECASE), "telnet", 50),
        (re.compile(r"Server:", re.IGNORECASE), "http", 40),
    ]

    # Dual timeout system
    CONNECT_TIMEOUT = 2.0  # Max time to establish connection
    READ_TIMEOUT_INITIAL = 1.5  # Initial read timeout
    READ_TIMEOUT_EXTENDED = 4.0  # Extended read for delayed banners
    MAX_RETRIES = 2  # Retry uncertain cases

    # Service probes for active detection
    SERVICE_PROBES = {
        22: ("ssh", b"SSH-2.0-OpenSSH_Probe\r\n"),
        21: ("ftp", b""),
        25: ("smtp", b"EHLO probe.local\r\n"),
        587: ("smtp", b"EHLO probe.local\r\n"),
        110: ("pop3", b""),
        995: ("pop3", b""),
        143: ("imap", b""),
        993: ("imap", b""),
        3306: ("mysql", b"\x00\x00\x00\x00"),
        5432: ("postgresql", b"\x00\x00\x00\x08\x04\xd2\x16\x2f"),
        6379: ("redis", b"PING\r\n"),
        27017: ("mongodb", b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00\x1f\x00\x00\x00\x01ismaster\x00\x01\x00\x00\x00\x00"),
        9200: ("elasticsearch", b"GET / HTTP/1.0\r\n\r\n"),
        11211: ("memcached", b"version\r\n"),
        23: ("telnet", b"\xff\xfd\x01"),
        3389: ("rdp", b""),
        5900: ("vnc", b""),
    }

    async def _determine_port_state(self, host: str, port: int) -> Tuple[PortState, Optional[Any], Optional[Any]]:
        """
        Determine port state with dual timeout system.
        Returns (state, reader, writer) tuple.
        """
        try:
            # Phase 1: Connect timeout
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.CONNECT_TIMEOUT
            )
            
            # Connection succeeded - port is OPEN
            return PortState.OPEN, reader, writer
            
        except asyncio.TimeoutError:
            # Connection timeout - likely FILTERED
            return PortState.FILTERED, None, None
            
        except ConnectionRefusedError:
            # Immediate rejection - CLOSED
            return PortState.CLOSED, None, None
            
        except OSError as e:
            # Network error - treat as FILTERED
            if "No route to host" in str(e) or "Network is unreachable" in str(e):
                return PortState.FILTERED, None, None
            return PortState.CLOSED, None, None

    async def _read_banner(self, reader, timeout: float = None) -> bytes:
        """Read banner with configurable timeout."""
        if timeout is None:
            timeout = self.READ_TIMEOUT_INITIAL
        
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            return data
        except asyncio.TimeoutError:
            return b""

    def _analyze_signals(self, banner: bytes, port: int) -> List[SignalEvidence]:
        """
        Signal-based detection with strength classification.
        Returns list of signals with confidence scores.
        """
        signals = []
        banner_text = banner.decode('utf-8', errors='ignore').replace('\x00', '').strip()
        
        if not banner or len(banner) == 0:
            return signals
        
        # Check partial data - short banners get penalized
        is_partial = len(banner) < 10
        
        # Strong pattern matching
        for pattern, service, base_conf in self.STRONG_PATTERNS:
            match = pattern.search(banner_text)
            if match:
                conf = base_conf
                if is_partial:
                    conf = max(30, conf - 40)  # Penalize partial matches
                
                strength = "strong" if conf >= 80 else "moderate"
                signals.append(SignalEvidence(
                    signal_type="banner",
                    matched_service=service,
                    confidence=conf,
                    strength=strength,
                    details=f"Strong pattern match: {banner_text[:50]}"
                ))
        
        # Moderate patterns
        for pattern, service, base_conf in self.MODERATE_PATTERNS:
            match = pattern.search(banner_text)
            if match:
                conf = base_conf
                if is_partial:
                    conf = max(25, conf - 30)
                
                strength = "moderate" if conf >= 60 else "weak"
                signals.append(SignalEvidence(
                    signal_type="banner",
                    matched_service=service,
                    confidence=conf,
                    strength=strength,
                    details=f"Moderate pattern: {banner_text[:50]}"
                ))
        
        # Weak patterns (only if no strong signals found)
        if not any(s.confidence >= 70 for s in signals):
            for pattern, service, base_conf in self.WEAK_PATTERNS:
                match = pattern.search(banner_text)
                if match:
                    conf = base_conf
                    if is_partial:
                        conf = max(15, conf - 15)
                    
                    signals.append(SignalEvidence(
                        signal_type="banner_partial",
                        matched_service=service,
                        confidence=conf,
                        strength="weak",
                        details=f"Partial signature: {banner_text[:30]}"
                    ))
        
        return signals

    def _calibrate_confidence(self, signals: List[SignalEvidence]) -> Tuple[str, int, str]:
        """
        Calibrate confidence from multiple signals.
        Returns (service, confidence, reasoning).
        """
        if not signals:
            return "unknown", 10, "No signals detected"
        
        # Check for conflicting signals
        services = set(s.matched_service for s in signals if s.confidence > 30)
        
        if len(services) > 1:
            # Conflicting signals - reduce confidence
            top_signal = max(signals, key=lambda s: s.confidence)
            calibrated_conf = max(15, top_signal.confidence - 30)
            return (
                top_signal.matched_service,
                calibrated_conf,
                f"Conflicting signals detected: {', '.join(services)}"
            )
        
        # Single service - use highest confidence signal
        strongest = max(signals, key=lambda s: s.confidence)
        
        # If all signals are weak, return unknown
        if strongest.confidence < 30:
            return "unknown", strongest.confidence, "Weak signals only, insufficient evidence"
        
        # Calculate average confidence for same-service signals
        same_service_signals = [s for s in signals if s.matched_service == strongest.matched_service]
        avg_conf = sum(s.confidence for s in same_service_signals) / len(same_service_signals)
        
        # Cap confidence based on signal strength
        if strongest.strength == "weak":
            final_conf = min(int(avg_conf), 45)  # Never overconfident with weak signals
            reasoning = f"Weak signal for {strongest.matched_service}"
        elif strongest.strength == "moderate":
            final_conf = min(int(avg_conf), 70)
            reasoning = f"Moderate confidence in {strongest.matched_service}"
        else:  # strong
            final_conf = min(int(avg_conf), 95)
            reasoning = f"Strong signal for {strongest.matched_service}"
        
        return strongest.matched_service, final_conf, reasoning

    async def _attempt_detection(self, host: str, port: int) -> ServiceInfo:
        """Single detection attempt with dual timeouts."""
        # Step 1: Determine port state
        state, reader, writer = await self._determine_port_state(host, port)
        
        if state == PortState.CLOSED:
            return ServiceInfo(
                name="unknown",
                confidence=0,
                state=PortState.CLOSED,
                reasoning="Port closed (connection refused)"
            )
        
        if state == PortState.FILTERED:
            return ServiceInfo(
                name="unknown",
                confidence=0,
                state=PortState.FILTERED,
                reasoning="Port filtered (connection timeout)"
            )
        
        # Port is OPEN - try to read banner
        try:
            # Send appropriate probe
            if port in [80, 8080, 8443, 443, 3000, 5000, 9000]:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port in self.SERVICE_PROBES:
                _, probe = self.SERVICE_PROBES[port]
                if probe:
                    writer.write(probe)
            else:
                writer.write(b"\r\n")
            
            await asyncio.wait_for(writer.drain(), timeout=1.0)
            
            # Step 2: Read with extended timeout for delayed banners
            banner = await self._read_banner(reader, timeout=self.READ_TIMEOUT_EXTENDED)
            
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            
            # Step 3: Analyze signals
            if not banner or len(banner) == 0:
                return ServiceInfo(
                    name="unknown",
                    confidence=10,
                    state=PortState.OPEN,
                    reasoning="Port open but no banner received"
                )
            
            signals = self._analyze_signals(banner, port)
            
            # Step 4: Calibrate confidence
            service, confidence, reasoning = self._calibrate_confidence(signals)
            
            banner_text = banner.decode('utf-8', errors='ignore')[:200]
            
            return ServiceInfo(
                name=service,
                confidence=confidence,
                state=PortState.OPEN,
                signals=signals,
                reasoning=reasoning,
                banner=banner_text
            )
            
        except Exception as e:
            return ServiceInfo(
                name="unknown",
                confidence=0,
                state=PortState.OPEN,
                reasoning=f"Error during banner grab: {str(e)}"
            )

    async def detect(self, host: str, port: int, timeout: float = 5.0) -> ServiceInfo:
        """
        Main detection method with retry strategy.
        Retries uncertain cases to detect instability.
        """
        # First attempt
        result = await self._attempt_detection(host, port)
        
        # Check if we should retry (low confidence or conflicting signals)
        if result.confidence < 50 and result.confidence > 10 and result.state == PortState.OPEN:
            retries = 0
            results = [result]
            
            for _ in range(self.MAX_RETRIES):
                retry_result = await self._attempt_detection(host, port)
                results.append(retry_result)
                retries += 1
                
                # If we got a confident result, stop retrying
                if retry_result.confidence >= 70:
                    result = retry_result
                    result.retries = retries
                    break
            
            # Check for instability
            detected_services = [r.name for r in results]
            if len(set(detected_services)) > 1:
                result.unstable = True
                result.reasoning += f" [UNSTABLE: Detected {', '.join(set(detected_services))}]"
                result.confidence = max(10, result.confidence - 20)  # Penalize instability
        
        return result
    
    # Legacy compatibility methods
    async def probe_protocol(self, host: str, port: int) -> Optional[ServiceInfo]:
        """Legacy method - redirects to detect."""
        return await self.detect(host, port)
