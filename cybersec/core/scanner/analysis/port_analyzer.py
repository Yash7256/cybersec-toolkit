"""
Port analyzer.
"""
from dataclasses import dataclass
from typing import List
from cybersec.core.security.cve_lookup import CVEEntry
from cybersec.core.security.attack_mapping import ATTACK_TECHNIQUE_DB
from cybersec.core.security.enhanced_attack import EnhancedATTACKMapping

@dataclass
class PortRisk:
    port: int
    risk_score: float
    risk_level: str
    mitre_techniques: List[str]
    notes: str

class PortAnalyzer:
    CRITICAL_SERVICES = {22, 3389}  # SSH, RDP
    HIGH_SERVICES = {21, 23, 25, 53, 110, 143, 993, 995}  # FTP, Telnet, SMTP, DNS, POP3, IMAP, POP3S, IMAPS
    MEDIUM_SERVICES = {80, 25, 53, 8080, 443, 587}
    LOW_SERVICES = {123}

    def __init__(self):
        self.enhanced_attack = EnhancedATTACKMapping('attack.db')

    @staticmethod
    def get_port_mitre_techniques(port: int) -> List[str]:
        """Get MITRE ATT&CK techniques for a port from the database."""
        port_techniques = ATTACK_TECHNIQUE_DB.get("port_techniques", {}).get(str(port), [])
        return [tech["id"] for tech in port_techniques]

    def analyze(self, port: int, cves: List[CVEEntry]) -> PortRisk:
        try:
            score = 0.0
            if port in self.CRITICAL_SERVICES:
                score = 0.8
            elif port in self.HIGH_SERVICES:
                score = 0.6
            elif port in self.MEDIUM_SERVICES:
                score = 0.4
            elif port in self.LOW_SERVICES:
                score = 0.2

            if cves:
                max_cvss = max((cve.cvss_score for cve in cves), default=0.0)
                score += (max_cvss / 10.0) * 0.5
                
            score = min(score, 1.0)
            
            if score >= 0.8:
                risk_level = "CRITICAL"
            elif score >= 0.6:
                risk_level = "HIGH"
            elif score >= 0.4:
                risk_level = "MEDIUM"
            elif score >= 0.2:
                risk_level = "LOW"
            else:
                risk_level = "INFO"
                
            # Get enhanced MITRE techniques
            try:
                enhanced_techniques = self.enhanced_attack.get_port_techniques(port)
                mitre_techniques = [tech["id"] for tech in enhanced_techniques]
            except Exception:
                # Fallback to basic mapping
                mitre_techniques = self.get_port_mitre_techniques(port)
            
            cve_str = f" with {len(cves)} CVEs" if cves else ""
            notes = f"Service on port {port} has {risk_level} risk{cve_str}."
            
            return PortRisk(
                port=port,
                risk_score=score,
                risk_level=risk_level,
                mitre_techniques=mitre_techniques,
                notes=notes
            )
        except Exception:
            return PortRisk(port=port, risk_score=0.0, risk_level="INFO", mitre_techniques=[], notes="Error analyzing risk")
