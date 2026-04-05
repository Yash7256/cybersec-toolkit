"""
Port analyzer.
"""
from dataclasses import dataclass
from typing import List
from cybersec.core.cve_lookup import CVEEntry

@dataclass
class PortRisk:
    port: int
    risk_score: float
    risk_level: str
    mitre_techniques: List[str]
    notes: str

class PortAnalyzer:
    CRITICAL_SERVICES = {23, 21, 111, 445}
    HIGH_SERVICES = {22, 3389, 3306, 1433, 5432, 5900, 6379, 27017}
    MEDIUM_SERVICES = {80, 25, 53, 8080, 443, 587}
    LOW_SERVICES = {123}

    MITRE_MAP = {
        22: ["T1021.004"],
        23: ["T1021.004", "T1040"],
        21: ["T1071.002"],
        445: ["T1021.002"],
        3389: ["T1021.001"],
        3306: ["T1190"],
        5432: ["T1190"],
        6379: ["T1190"],
        27017: ["T1190"],
        80: ["T1190", "T1071.001"],
        443: ["T1071.001"]
    }

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
                
            mitre_techniques = self.MITRE_MAP.get(port, [])
            
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
