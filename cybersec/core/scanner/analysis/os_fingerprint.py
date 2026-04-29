import re
from dataclasses import dataclass, field
from typing import List, Optional, Any, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from cybersec.core.scanner.analysis.service_detect import ServiceInfo

# OS Signatures for packet-level fingerprinting
OS_SIGNATURES = {
    "linux": {
        "ttl_hop_decay": (1, 5),  # Expected hop count range
        "window_sizes": [5840, 5792, 65535, 14600, 29200],
        "tcp_options_order": ["mss", "sack", "timestamp", "nop", "wscale"],
        "ip_id_behavior": "random",  # or "sequential", "zero"
        "icmp_ttl": 64,
        "tcp_timestamp_hz": 1000
    },
    "windows": {
        "ttl_hop_decay": (1, 3),
        "window_sizes": [8192, 65535, 16384, 32768, 64240],
        "tcp_options_order": ["mss", "nop", "wscale", "nop", "nop", "sack"],
        "ip_id_behavior": "sequential",
        "icmp_ttl": 128,
        "tcp_timestamp_hz": 1000
    },
    "macos": {
        "ttl_hop_decay": (1, 5),
        "window_sizes": [65535, 131072, 262144],
        "tcp_options_order": ["mss", "nop", "wscale", "nop", "nop", "timestamp", "sack"],
        "ip_id_behavior": "random",
        "icmp_ttl": 64,
        "tcp_timestamp_hz": 1000
    },
    "cisco": {
        "ttl_hop_decay": (1, 10),
        "window_sizes": [4128, 8192, 16384],
        "tcp_options_order": ["mss", "nop", "wscale", "nop", "nop", "timestamp"],
        "ip_id_behavior": "sequential",
        "icmp_ttl": 255,
        "tcp_timestamp_hz": 1000
    }
}

SIGNAL_WEIGHTS = {
    "ttl": 0.20,
    "window_size": 0.25,
    "tcp_options": 0.30,
    "ip_id": 0.10,
    "icmp": 0.15
}

@dataclass
class TechnicalStackInfo:
    ttl: Optional[int] = None
    window_size: Optional[int] = None
    df_flag: bool = False
    tcp_options: List[str] = field(default_factory=list)

@dataclass
class OSFingerprint:
    os_name: str
    confidence: float
    method: str
    vendor: str = "Unknown"
    os_family: str = "Unknown"
    version: Optional[str] = None
    tech_details: TechnicalStackInfo = field(default_factory=TechnicalStackInfo)
    ambiguous: bool = False
    signals_used: List[str] = field(default_factory=list)
    hop_count: Optional[int] = None

class OSFingerprinter:
    # Service to OS mapping (High confidence signals)
    SERVICE_OS_MAP: Dict[str, tuple] = {
        "iis": ("Windows", "Microsoft", "Windows Server"),
        "msrpc": ("Windows", "Microsoft", "Windows"),
        "netbios-ssn": ("Windows", "Microsoft", "Windows"),
        "microsoft-ds": ("Windows", "Microsoft", "Windows"),
        "rdp": ("Windows", "Microsoft", "Windows"),
        "afp": ("macOS", "Apple", "macOS"),
        "apple-afp": ("macOS", "Apple", "macOS"),
        "cisco-ios": ("Cisco IOS", "Cisco", "Cisco IOS"),
    }

    BANNER_OS_PATTERNS = [
        (re.compile(r"Ubuntu/(\S+)", re.IGNORECASE), "Linux", "Ubuntu", "Linux"),
        (re.compile(r"Debian", re.IGNORECASE), "Linux", "Debian", "Linux"),
        (re.compile(r"CentOS|RedHat|RHEL", re.IGNORECASE), "Linux", "RHEL/CentOS", "Linux"),
        (re.compile(r"Windows", re.IGNORECASE), "Windows", "Microsoft", "Windows"),
        (re.compile(r"FreeBSD", re.IGNORECASE), "FreeBSD", "FreeBSD", "FreeBSD"),
        (re.compile(r"OpenBSD", re.IGNORECASE), "OpenBSD", "OpenBSD", "OpenBSD"),
        (re.compile(r"Darwin|macOS", re.IGNORECASE), "macOS", "Apple", "macOS"),
        (re.compile(r"Cisco", re.IGNORECASE), "Cisco IOS", "Cisco", "Cisco IOS"),
    ]

    def analyze_ttl(self, ttl_observed: int) -> tuple[str, float]:
        """Analyze TTL to determine OS and confidence contribution."""
        # Round up to nearest initial TTL bucket
        initial_ttl = min([64, 128, 255], key=lambda x: x - ttl_observed if x >= ttl_observed else float('inf'))
        hop_count = initial_ttl - ttl_observed
        
        best_match = None
        best_conf = 0.0
        
        for os_name, sig in OS_SIGNATURES.items():
            hop_range = sig["ttl_hop_decay"]
            if hop_range[0] <= hop_count <= hop_range[1]:
                conf = 1.0 - (abs(hop_count - sum(hop_range)/2) / (hop_range[1] - hop_range[0] + 1))
                if conf > best_conf:
                    best_conf = conf
                    best_match = os_name
        
        return (best_match or "unknown", best_conf * SIGNAL_WEIGHTS["ttl"])

    def analyze_window_size(self, window: int) -> tuple[str, float]:
        """Analyze TCP window size to determine OS and confidence contribution."""
        best_match = None
        best_conf = 0.0
        
        for os_name, sig in OS_SIGNATURES.items():
            for win_size in sig["window_sizes"]:
                if window == win_size:
                    return (os_name, SIGNAL_WEIGHTS["window_size"])
                elif abs(window - win_size) <= 500:
                    conf = 1.0 - (abs(window - win_size) / 500)
                    if conf > best_conf:
                        best_conf = conf
                        best_match = os_name
        
        return (best_match or "unknown", best_conf * SIGNAL_WEIGHTS["window_size"])

    def parse_tcp_options(self, options: list) -> list[str]:
        """Parse Scapy TCP options into normalized string list."""
        normalized = []
        for opt in options:
            if isinstance(opt, tuple):
                opt_name = str(opt[0]).lower()
            else:
                opt_name = str(opt).lower()
            # Normalize common option names
            if "mss" in opt_name:
                normalized.append("mss")
            elif "sack" in opt_name:
                normalized.append("sack")
            elif "timestamp" in opt_name:
                normalized.append("timestamp")
            elif "wscale" in opt_name:
                normalized.append("wscale")
            elif "nop" in opt_name:
                normalized.append("nop")
        return normalized

    def analyze_tcp_options(self, options: list) -> tuple[str, float]:
        """Analyze TCP options order to determine OS and confidence contribution."""
        normalized = self.parse_tcp_options(options)
        best_match = None
        best_conf = 0.0
        
        for os_name, sig in OS_SIGNATURES.items():
            expected_order = sig["tcp_options_order"]
            # Calculate how many options match in correct order
            matches = 0
            for i, opt in enumerate(normalized):
                if i < len(expected_order) and opt == expected_order[i]:
                    matches += 1
            
            conf = matches / max(len(expected_order), len(normalized)) if expected_order else 0.0
            if conf > best_conf:
                best_conf = conf
                best_match = os_name
        
        return (best_match or "unknown", best_conf * SIGNAL_WEIGHTS["tcp_options"])

    def analyze_ip_id(self, id_list: list[int]) -> tuple[str, float]:
        """Analyze IP ID sequence behavior to determine OS and confidence contribution."""
        if not id_list or len(id_list) < 2:
            return ("unknown", 0.0)
        
        # Check for sequential (Windows)
        diffs = [id_list[i+1] - id_list[i] for i in range(len(id_list)-1)]
        if all(1 <= diff <= 10 for diff in diffs):
            return ("windows", SIGNAL_WEIGHTS["ip_id"])
        
        # Check for all zeros (some Linux)
        if all(id == 0 for id in id_list):
            return ("linux", SIGNAL_WEIGHTS["ip_id"])
        
        # Check for random/high variance (macOS, modern Linux)
        variance = sum((x - sum(id_list)/len(id_list))**2 for x in id_list) / len(id_list)
        if variance > 10000:  # High variance indicates randomness
            return ("macos", SIGNAL_WEIGHTS["ip_id"] * 0.8)  # Slightly lower confidence
        
        return ("unknown", 0.0)

    def probe_active(self, target_ip: str, port: int = 80) -> dict:
        """Send active probes to extract packet-level OS fingerprints."""
        try:
            from scapy.all import IP, TCP, ICMP, sr1, send
            import time
            
            results = {"ttl": None, "window": None, "options": [], "ip_id_list": [], "icmp_ttl": None}
            
            # Send SYN packet
            syn = IP(dst=target_ip)/TCP(dport=port, flags="S")
            syn_ack = sr1(syn, timeout=2, verbose=0)
            
            if syn_ack:
                results["ttl"] = syn_ack[IP].ttl
                results["window"] = syn_ack[TCP].window
                results["options"] = syn_ack[TCP].options
                results["ip_id_list"].append(syn_ack[IP].id)
                
                # Send RST to close connection
                rst = IP(dst=target_ip)/TCP(dport=port, flags="R", seq=syn_ack[TCP].ack)
                send(rst, verbose=0)
            
            # Send ICMP echo for TTL
            icmp_req = IP(dst=target_ip)/ICMP()
            icmp_reply = sr1(icmp_req, timeout=2, verbose=0)
            if icmp_reply:
                results["icmp_ttl"] = icmp_reply[IP].ttl
            
            # Collect more IP IDs
            for _ in range(3):
                time.sleep(0.1)
                probe = IP(dst=target_ip)/TCP(dport=port, flags="S")
                resp = sr1(probe, timeout=1, verbose=0)
                if resp:
                    results["ip_id_list"].append(resp[IP].id)
                    # Send RST
                    rst = IP(dst=target_ip)/TCP(dport=port, flags="R", seq=resp[TCP].ack)
                    send(rst, verbose=0)
            
            return results
            
        except Exception as e:
            print(f"[OS Fingerprint] Active probe failed: {e}")
            return {}

    def fingerprint_active(self, target_ip: str, ports: list = [80, 443, 22]) -> OSFingerprint:
        """Perform active OS fingerprinting using packet analysis."""
        # Try each port until we get a response
        probe_data = {}
        for port in ports:
            probe_data = self.probe_active(target_ip, port)
            if probe_data.get("ttl"):
                break
        
        if not probe_data.get("ttl"):
            # Fall back to existing heuristic method
            return self.fingerprint([], [], [])
        
        # Analyze each signal
        signals = {}
        
        # TTL analysis with edge case handling
        if probe_data.get("ttl"):
            observed_ttl = probe_data["ttl"]
            initial_ttl = min([64, 128, 255], key=lambda x: x - observed_ttl if x >= observed_ttl else float('inf'))
            if observed_ttl > initial_ttl:
                # TTL was rewritten by firewall/NAT
                signals["ttl"] = {"os": "unknown", "confidence": 0.0, "ttl_rewritten": True}
            else:
                os_ttl, conf_ttl = self.analyze_ttl(observed_ttl)
                signals["ttl"] = {"os": os_ttl, "confidence": conf_ttl}
        
        # Window size analysis
        if probe_data.get("window"):
            os_win, conf_win = self.analyze_window_size(probe_data["window"])
            signals["window"] = {"os": os_win, "confidence": conf_win}
        
        # TCP options analysis
        if probe_data.get("options"):
            os_opts, conf_opts = self.analyze_tcp_options(probe_data["options"])
            signals["tcp_options"] = {"os": os_opts, "confidence": conf_opts}
        
        # IP ID analysis
        if probe_data.get("ip_id_list"):
            os_ipid, conf_ipid = self.analyze_ip_id(probe_data["ip_id_list"])
            signals["ip_id"] = {"os": os_ipid, "confidence": conf_ipid}
        
        # ICMP TTL analysis
        if probe_data.get("icmp_ttl"):
            os_icmp, conf_icmp = self.analyze_ttl(probe_data["icmp_ttl"])
            signals["icmp"] = {"os": os_icmp, "confidence": conf_icmp}
        
        # Score each OS
        os_scores = {}
        for os_name in OS_SIGNATURES.keys():
            score = 0.0
            for signal_name, signal_data in signals.items():
                if signal_data["os"] == os_name:
                    score += signal_data["confidence"]
            os_scores[os_name] = score
        
        # Find best match
        best_os = max(os_scores.items(), key=lambda x: x[1])
        total_score = sum(os_scores.values())
        confidence = (best_os[1] / total_score * 100) if total_score > 0 else 0.0
        
        # Check for ambiguity (top two within 10%)
        sorted_scores = sorted(os_scores.values(), reverse=True)
        ambiguous = len(sorted_scores) > 1 and sorted_scores[1] / sorted_scores[0] > 0.9
        
        # Check for conflicting signals (possible NAT)
        possible_nat = False
        os_votes = {}
        for signal_data in signals.values():
            os_name = signal_data["os"]
            if os_name != "unknown":
                os_votes[os_name] = os_votes.get(os_name, 0) + 1
        
        if len(os_votes) > 1 and max(os_votes.values()) == 1:
            possible_nat = True
        
        # Check for VM indicators
        possible_vm = False
        if probe_data.get("window") == 65535 and probe_data.get("options"):
            # VMware often uses window=65535 with specific option patterns
            options_str = str(probe_data["options"]).lower()
            if "vmware" in options_str or len(probe_data["options"]) > 6:
                possible_vm = True
        
        # Calculate hop count
        hop_count = None
        if probe_data.get("ttl") and not signals.get("ttl", {}).get("ttl_rewritten"):
            initial_ttl = min([64, 128, 255], key=lambda x: x - probe_data["ttl"] if x >= probe_data["ttl"] else float('inf'))
            hop_count = initial_ttl - probe_data["ttl"]
        
        return OSFingerprint(
            os_name=best_os[0],
            os_family=best_os[0],
            confidence=round(confidence, 1),
            method="active_packet_analysis",
            signals_used=list(signals.keys()),
            ambiguous=ambiguous,
            hop_count=hop_count,
            tech_details=TechnicalStackInfo(
                ttl=probe_data.get("ttl"),
                window_size=probe_data.get("window"),
                tcp_options=self.parse_tcp_options(probe_data.get("options", []))
            )
        )

    def fingerprint_passive(self, iface: str = "eth0", count: int = 50) -> list[OSFingerprint]:
        """Perform passive OS fingerprinting by sniffing network traffic."""
        try:
            from scapy.all import sniff, IP, TCP
            
            fingerprints = []
            host_data = {}
            
            def packet_handler(pkt):
                if IP in pkt and TCP in pkt:
                    src_ip = pkt[IP].src
                    if src_ip not in host_data:
                        host_data[src_ip] = {
                            "ttl": pkt[IP].ttl,
                            "window": pkt[TCP].window,
                            "options": pkt[TCP].options,
                            "ip_ids": [pkt[IP].id]
                        }
                    else:
                        # Collect more IP IDs for sequence analysis
                        if pkt[IP].id not in host_data[src_ip]["ip_ids"]:
                            host_data[src_ip]["ip_ids"].append(pkt[IP].id)
            
            # Sniff packets
            sniff(iface=iface, prn=packet_handler, count=count, timeout=10, store=0)
            
            # Generate fingerprints for each host
            for ip, data in host_data.items():
                if len(data["ip_ids"]) >= 2:
                    # Analyze signals
                    signals = {}
                    
                    os_ttl, conf_ttl = self.analyze_ttl(data["ttl"])
                    signals["ttl"] = {"os": os_ttl, "confidence": conf_ttl}
                    
                    os_win, conf_win = self.analyze_window_size(data["window"])
                    signals["window"] = {"os": os_win, "confidence": conf_win}
                    
                    os_opts, conf_opts = self.analyze_tcp_options(data["options"])
                    signals["tcp_options"] = {"os": os_opts, "confidence": conf_opts}
                    
                    os_ipid, conf_ipid = self.analyze_ip_id(data["ip_ids"])
                    signals["ip_id"] = {"os": os_ipid, "confidence": conf_ipid}
                    
                    # Score OS
                    os_scores = {}
                    for os_name in OS_SIGNATURES.keys():
                        score = 0.0
                        for signal_data in signals.values():
                            if signal_data["os"] == os_name:
                                score += signal_data["confidence"]
                        os_scores[os_name] = score
                    
                    best_os = max(os_scores.items(), key=lambda x: x[1])
                    total_score = sum(os_scores.values())
                    confidence = (best_os[1] / total_score * 100) if total_score > 0 else 0.0
                    
                    fingerprints.append(OSFingerprint(
                        os_name=best_os[0],
                        os_family=best_os[0],
                        confidence=round(confidence, 1),
                        method="passive_packet_analysis",
                        signals_used=list(signals.keys()),
                        tech_details=TechnicalStackInfo(
                            ttl=data["ttl"],
                            window_size=data["window"],
                            tcp_options=self.parse_tcp_options(data["options"])
                        )
                    ))
            
            return fingerprints
            
        except Exception as e:
            print(f"[OS Fingerprint] Passive fingerprinting failed: {e}")
            return []

    def fingerprint(self, banners: List[str], open_ports: List[int], services: List[Any] = None) -> OSFingerprint:
        evidence: List[Dict[str, Any]] = []
        
        # 1. Check Banners
        for banner in banners:
            if not banner: continue
            for pattern, os_family, vendor, name in self.BANNER_OS_PATTERNS:
                match = pattern.search(banner)
                if match:
                    version = match.group(1) if match.groups() else None
                    evidence.append({
                        "name": str(name), "family": str(os_family), "vendor": str(vendor), 
                        "version": version, "conf": 0.9, "method": "banner"
                    })

        # 2. Check Services
        if services:
            for svc in services:
                if not svc or not hasattr(svc, 'service_name') or not svc.service_name: continue
                svc_name = str(svc.service_name).lower()
                if svc_name in self.SERVICE_OS_MAP:
                    family, vendor, name = self.SERVICE_OS_MAP[svc_name]
                    evidence.append({
                        "name": str(name), "family": str(family), "vendor": str(vendor),
                        "version": getattr(svc, 'service_version', None), "conf": 0.85, "method": "service_match"
                    })

        # 3. Check Port Patterns
        ports_set = set(open_ports)
        if {135, 139, 445, 3389}.intersection(ports_set):
            evidence.append({
                "name": "Windows", "family": "Windows", "vendor": "Microsoft",
                "version": None, "conf": 0.7, "method": "port_pattern"
            })
        
        if 22 in ports_set and not ports_set.intersection({135, 445}):
            evidence.append({
                "name": "Linux/Unix", "family": "Linux", "vendor": "Unknown",
                "version": None, "conf": 0.4, "method": "port_pattern"
            })
            
        if 548 in ports_set:
            evidence.append({
                "name": "macOS", "family": "macOS", "vendor": "Apple",
                "version": None, "conf": 0.75, "method": "port_pattern"
            })

        # Heuristic Scoring
        if not evidence:
            return OSFingerprint(os_name="Unknown", confidence=0.0, method="unknown")

        # Sort by confidence and take the best
        evidence.sort(key=lambda x: x["conf"], reverse=True)
        best = evidence[0]
        
        # Boost confidence if multiple vectors agree
        final_conf = float(best.get("conf", 0.0))
        best_family = str(best.get("family", "Unknown"))
        
        other_matches = [e for e in evidence[1:] if str(e.get("family")) == best_family]
        if other_matches:
            final_conf = min(0.99, final_conf + (0.05 * len(other_matches)))

        # Simulate Stack Fingerprinting (Advanced technical details)
        tech = TechnicalStackInfo()
        if best_family == "Linux":
            tech.ttl = 64
            tech.window_size = 5840
            tech.df_flag = True
        elif best_family == "Windows":
            tech.ttl = 128
            tech.window_size = 8192
            tech.df_flag = True
        elif best_family == "macOS":
            tech.ttl = 64
            tech.window_size = 65535

        return OSFingerprint(
            os_name=str(best.get("name", "Unknown")),
            os_family=best_family,
            vendor=str(best.get("vendor", "Unknown")),
            version=str(best.get("version")) if best.get("version") else None,
            confidence=float("{:.1f}".format(final_conf * 100)),
            method=str(best.get("method", "unknown")),
            tech_details=tech
        )
