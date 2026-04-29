"""
MITRE ATT&CK Framework Mapping for CyberSec Scanner.

This module provides real MITRE ATT&CK technique mappings without external API calls.
All technique data is stored locally for speed and reliability.
"""
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from cybersec.core.security.nvd_client import CVEResult
from cybersec.core.scanner.analysis.service_detect import ServiceDetectionResult


@dataclass
class ATTACKTechnique:
    """MITRE ATT&CK Technique representation."""
    id: str
    name: str
    tactic: str
    url: str


# Local MITRE ATT&CK Knowledge Base - All techniques are real from Enterprise matrix
ATTACK_TECHNIQUE_DB = {
    "service_techniques": {
        "ssh": [
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "url": "https://attack.mitre.org/techniques/T1110/"
            },
            {
                "id": "T1021.004",
                "name": "Remote Services: SSH",
                "tactic": "Lateral Movement",
                "url": "https://attack.mitre.org/techniques/T1021/004/"
            },
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "url": "https://attack.mitre.org/techniques/T1190/"
            },
            {
                "id": "T1078",
                "name": "Valid Accounts",
                "tactic": "Initial Access",
                "url": "https://attack.mitre.org/techniques/T1078/"
            }
        ],
        "http": [
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "url": "https://attack.mitre.org/techniques/T1190/"
            },
            {
                "id": "T1071.001",
                "name": "Application Layer Protocol: Web Protocols",
                "tactic": "Command and Control",
                "url": "https://attack.mitre.org/techniques/T1071/001/"
            },
            {
                "id": "T1059.007",
                "name": "Command and Scripting Interpreter: JavaScript",
                "tactic": "Execution",
                "url": "https://attack.mitre.org/techniques/T1059/007/"
            },
            {
                "id": "T1595.002",
                "name": "Vulnerability Scanning: Web Scanning",
                "tactic": "Reconnaissance",
                "url": "https://attack.mitre.org/techniques/T1595/002/"
            }
        ],
        "https": [
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "url": "https://attack.mitre.org/techniques/T1190/"
            },
            {
                "id": "T1071.001",
                "name": "Application Layer Protocol: Web Protocols",
                "tactic": "Command and Control",
                "url": "https://attack.mitre.org/techniques/T1071/001/"
            },
            {
                "id": "T1571",
                "name": "Non-Standard Port",
                "tactic": "Defense Evasion",
                "url": "https://attack.mitre.org/techniques/T1571/"
            },
            {
                "id": "T1048.003",
                "name": "Exfiltration Over Unencrypted/Obfuscated Channel: Exfiltration Over Unencrypted Protocol",
                "tactic": "Exfiltration",
                "url": "https://attack.mitre.org/techniques/T1048/003/"
            }
        ],
        "ftp": [
            {
                "id": "T1071.002",
                "name": "Application Layer Protocol: File Transfer Protocols",
                "tactic": "Command and Control",
                "url": "https://attack.mitre.org/techniques/T1071/002/"
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "url": "https://attack.mitre.org/techniques/T1110/"
            },
            {
                "id": "T1048.002",
                "name": "Exfiltration Over Unencrypted/Obfuscated Channel: Exfiltration Over C2 Channel",
                "tactic": "Exfiltration",
                "url": "https://attack.mitre.org/techniques/T1048/002/"
            },
            {
                "id": "T1083",
                "name": "File and Directory Discovery",
                "tactic": "Discovery",
                "url": "https://attack.mitre.org/techniques/T1083/"
            }
        ],
        "smtp": [
            {
                "id": "T1071.003",
                "name": "Application Layer Protocol: Mail Protocols",
                "tactic": "Command and Control",
                "url": "https://attack.mitre.org/techniques/T1071/003/"
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "url": "https://attack.mitre.org/techniques/T1110/"
            },
            {
                "id": "T1566.001",
                "name": "Phishing: Spearphishing Attachment",
                "tactic": "Initial Access",
                "url": "https://attack.mitre.org/techniques/T1566/001/"
            },
            {
                "id": "T1592",
                "name": "Gather Victim Host Information",
                "tactic": "Reconnaissance",
                "url": "https://attack.mitre.org/techniques/T1592/"
            }
        ],
        "redis": [
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "url": "https://attack.mitre.org/techniques/T1190/"
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "url": "https://attack.mitre.org/techniques/T1110/"
            },
            {
                "id": "T1210",
                "name": "Exploitation of Remote Services",
                "tactic": "Lateral Movement",
                "url": "https://attack.mitre.org/techniques/T1210/"
            },
            {
                "id": "T1078",
                "name": "Valid Accounts",
                "tactic": "Initial Access",
                "url": "https://attack.mitre.org/techniques/T1078/"
            },
            {
                "id": "T1059",
                "name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "url": "https://attack.mitre.org/techniques/T1059/"
            }
        ],
        "postgresql": [
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "url": "https://attack.mitre.org/techniques/T1190/"
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "url": "https://attack.mitre.org/techniques/T1110/"
            },
            {
                "id": "T1210",
                "name": "Exploitation of Remote Services",
                "tactic": "Lateral Movement",
                "url": "https://attack.mitre.org/techniques/T1210/"
            },
            {
                "id": "T1021.002",
                "name": "Remote Services: SMB/Windows Admin Shares",
                "tactic": "Lateral Movement",
                "url": "https://attack.mitre.org/techniques/T1021/002/"
            }
        ],
        "mysql": [
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "url": "https://attack.mitre.org/techniques/T1190/"
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "url": "https://attack.mitre.org/techniques/T1110/"
            },
            {
                "id": "T1210",
                "name": "Exploitation of Remote Services",
                "tactic": "Lateral Movement",
                "url": "https://attack.mitre.org/techniques/T1210/"
            },
            {
                "id": "T1078",
                "name": "Valid Accounts",
                "tactic": "Initial Access",
                "url": "https://attack.mitre.org/techniques/T1078/"
            }
        ],
        "mongodb": [
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "url": "https://attack.mitre.org/techniques/T1190/"
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "url": "https://attack.mitre.org/techniques/T1110/"
            },
            {
                "id": "T1210",
                "name": "Exploitation of Remote Services",
                "tactic": "Lateral Movement",
                "url": "https://attack.mitre.org/techniques/T1210/"
            },
            {
                "id": "T1027",
                "name": "Obfuscated Files or Information",
                "tactic": "Defense Evasion",
                "url": "https://attack.mitre.org/techniques/T1027/"
            }
        ],
        "telnet": [
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "url": "https://attack.mitre.org/techniques/T1110/"
            },
            {
                "id": "T1021.004",
                "name": "Remote Services: SSH",
                "tactic": "Lateral Movement",
                "url": "https://attack.mitre.org/techniques/T1021/004/"
            },
            {
                "id": "T1048.003",
                "name": "Exfiltration Over Unencrypted/Obfuscated Channel: Exfiltration Over Unencrypted Protocol",
                "tactic": "Exfiltration",
                "url": "https://attack.mitre.org/techniques/T1048/003/"
            },
            {
                "id": "T1078",
                "name": "Valid Accounts",
                "tactic": "Initial Access",
                "url": "https://attack.mitre.org/techniques/T1078/"
            }
        ],
        "rdp": [
            {
                "id": "T1021.001",
                "name": "Remote Services: Remote Desktop Protocol",
                "tactic": "Lateral Movement",
                "url": "https://attack.mitre.org/techniques/T1021/001/"
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "url": "https://attack.mitre.org/techniques/T1110/"
            },
            {
                "id": "T1078",
                "name": "Valid Accounts",
                "tactic": "Initial Access",
                "url": "https://attack.mitre.org/techniques/T1078/"
            },
            {
                "id": "T1566.002",
                "name": "Phishing: Spearphishing Link",
                "tactic": "Initial Access",
                "url": "https://attack.mitre.org/techniques/T1566/002/"
            }
        ],
        "smb": [
            {
                "id": "T1021.002",
                "name": "Remote Services: SMB/Windows Admin Shares",
                "tactic": "Lateral Movement",
                "url": "https://attack.mitre.org/techniques/T1021/002/"
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "url": "https://attack.mitre.org/techniques/T1110/"
            },
            {
                "id": "T1135",
                "name": "Network Share Discovery",
                "tactic": "Discovery",
                "url": "https://attack.mitre.org/techniques/T1135/"
            },
            {
                "id": "T1040",
                "name": "Network Sniffing",
                "tactic": "Credential Access",
                "url": "https://attack.mitre.org/techniques/T1040/"
            }
        ],
        "dns": [
            {
                "id": "T1071.004",
                "name": "Application Layer Protocol: DNS",
                "tactic": "Command and Control",
                "url": "https://attack.mitre.org/techniques/T1071/004/"
            },
            {
                "id": "T1595.001",
                "name": "Vulnerability Scanning: DNS Zone Transfers",
                "tactic": "Reconnaissance",
                "url": "https://attack.mitre.org/techniques/T1595/001/"
            },
            {
                "id": "T1048.004",
                "name": "Exfiltration Over Unencrypted/Obfuscated Channel: Exfiltration Over DNS",
                "tactic": "Exfiltration",
                "url": "https://attack.mitre.org/techniques/T1048/004/"
            },
            {
                "id": "T1070.001",
                "name": "Indicator Removal: Clear Windows Event Logs",
                "tactic": "Defense Evasion",
                "url": "https://attack.mitre.org/techniques/T1070/001/"
            }
        ]
    },
    "cvss_severity_techniques": {
        "CRITICAL": [
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "url": "https://attack.mitre.org/techniques/T1190/"
            },
            {
                "id": "T1210",
                "name": "Exploitation of Remote Services",
                "tactic": "Lateral Movement",
                "url": "https://attack.mitre.org/techniques/T1210/"
            },
            {
                "id": "T1068",
                "name": "Exploitation for Privilege Escalation",
                "tactic": "Privilege Escalation",
                "url": "https://attack.mitre.org/techniques/T1068/"
            }
        ],
        "HIGH": [
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "url": "https://attack.mitre.org/techniques/T1190/"
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "url": "https://attack.mitre.org/techniques/T1110/"
            },
            {
                "id": "T1210",
                "name": "Exploitation of Remote Services",
                "tactic": "Lateral Movement",
                "url": "https://attack.mitre.org/techniques/T1210/"
            }
        ],
        "MEDIUM": [
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "url": "https://attack.mitre.org/techniques/T1110/"
            },
            {
                "id": "T1083",
                "name": "File and Directory Discovery",
                "tactic": "Discovery",
                "url": "https://attack.mitre.org/techniques/T1083/"
            },
            {
                "id": "T1595.002",
                "name": "Vulnerability Scanning: Web Scanning",
                "tactic": "Reconnaissance",
                "url": "https://attack.mitre.org/techniques/T1595/002/"
            }
        ],
        "LOW": [
            {
                "id": "T1083",
                "name": "File and Directory Discovery",
                "tactic": "Discovery",
                "url": "https://attack.mitre.org/techniques/T1083/"
            },
            {
                "id": "T1592",
                "name": "Gather Victim Host Information",
                "tactic": "Reconnaissance",
                "url": "https://attack.mitre.org/techniques/T1592/"
            }
        ]
    },
    "port_techniques": {
        "21": [
            {
                "id": "T1071.002",
                "name": "Application Layer Protocol: File Transfer Protocols",
                "tactic": "Command and Control",
                "url": "https://attack.mitre.org/techniques/T1071/002/"
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "url": "https://attack.mitre.org/techniques/T1110/"
            }
        ],
        "22": [
            {
                "id": "T1021.004",
                "name": "Remote Services: SSH",
                "tactic": "Lateral Movement",
                "url": "https://attack.mitre.org/techniques/T1021/004/"
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "url": "https://attack.mitre.org/techniques/T1110/"
            }
        ],
        "23": [
            {
                "id": "T1021.004",
                "name": "Remote Services: SSH",
                "tactic": "Lateral Movement",
                "url": "https://attack.mitre.org/techniques/T1021/004/"
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "url": "https://attack.mitre.org/techniques/T1110/"
            },
            {
                "id": "T1048.003",
                "name": "Exfiltration Over Unencrypted/Obfuscated Channel: Exfiltration Over Unencrypted Protocol",
                "tactic": "Exfiltration",
                "url": "https://attack.mitre.org/techniques/T1048/003/"
            }
        ],
        "25": [
            {
                "id": "T1071.003",
                "name": "Application Layer Protocol: Mail Protocols",
                "tactic": "Command and Control",
                "url": "https://attack.mitre.org/techniques/T1071/003/"
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "url": "https://attack.mitre.org/techniques/T1110/"
            }
        ],
        "53": [
            {
                "id": "T1071.004",
                "name": "Application Layer Protocol: DNS",
                "tactic": "Command and Control",
                "url": "https://attack.mitre.org/techniques/T1071/004/"
            },
            {
                "id": "T1595.001",
                "name": "Vulnerability Scanning: DNS Zone Transfers",
                "tactic": "Reconnaissance",
                "url": "https://attack.mitre.org/techniques/T1595/001/"
            }
        ],
        "80": [
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "url": "https://attack.mitre.org/techniques/T1190/"
            },
            {
                "id": "T1071.001",
                "name": "Application Layer Protocol: Web Protocols",
                "tactic": "Command and Control",
                "url": "https://attack.mitre.org/techniques/T1071/001/"
            },
            {
                "id": "T1059.007",
                "name": "Command and Scripting Interpreter: JavaScript",
                "tactic": "Execution",
                "url": "https://attack.mitre.org/techniques/T1059/007/"
            }
        ],
        "443": [
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "url": "https://attack.mitre.org/techniques/T1190/"
            },
            {
                "id": "T1071.001",
                "name": "Application Layer Protocol: Web Protocols",
                "tactic": "Command and Control",
                "url": "https://attack.mitre.org/techniques/T1071/001/"
            },
            {
                "id": "T1571",
                "name": "Non-Standard Port",
                "tactic": "Defense Evasion",
                "url": "https://attack.mitre.org/techniques/T1571/"
            }
        ],
        "445": [
            {
                "id": "T1021.002",
                "name": "Remote Services: SMB/Windows Admin Shares",
                "tactic": "Lateral Movement",
                "url": "https://attack.mitre.org/techniques/T1021/002/"
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "url": "https://attack.mitre.org/techniques/T1110/"
            },
            {
                "id": "T1135",
                "name": "Network Share Discovery",
                "tactic": "Discovery",
                "url": "https://attack.mitre.org/techniques/T1135/"
            }
        ],
        "3389": [
            {
                "id": "T1021.001",
                "name": "Remote Services: Remote Desktop Protocol",
                "tactic": "Lateral Movement",
                "url": "https://attack.mitre.org/techniques/T1021/001/"
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "url": "https://attack.mitre.org/techniques/T1110/"
            },
            {
                "id": "T1078",
                "name": "Valid Accounts",
                "tactic": "Initial Access",
                "url": "https://attack.mitre.org/techniques/T1078/"
            }
        ],
        "6379": [
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "url": "https://attack.mitre.org/techniques/T1190/"
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "url": "https://attack.mitre.org/techniques/T1110/"
            },
            {
                "id": "T1210",
                "name": "Exploitation of Remote Services",
                "tactic": "Lateral Movement",
                "url": "https://attack.mitre.org/techniques/T1210/"
            }
        ],
        "5432": [
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "url": "https://attack.mitre.org/techniques/T1190/"
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "url": "https://attack.mitre.org/techniques/T1110/"
            },
            {
                "id": "T1210",
                "name": "Exploitation of Remote Services",
                "tactic": "Lateral Movement",
                "url": "https://attack.mitre.org/techniques/T1210/"
            }
        ],
        "3306": [
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "url": "https://attack.mitre.org/techniques/T1190/"
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "url": "https://attack.mitre.org/techniques/T1110/"
            },
            {
                "id": "T1210",
                "name": "Exploitation of Remote Services",
                "tactic": "Lateral Movement",
                "url": "https://attack.mitre.org/techniques/T1210/"
            }
        ],
        "27017": [
            {
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
                "url": "https://attack.mitre.org/techniques/T1190/"
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access",
                "url": "https://attack.mitre.org/techniques/T1110/"
            },
            {
                "id": "T1210",
                "name": "Exploitation of Remote Services",
                "tactic": "Lateral Movement",
                "url": "https://attack.mitre.org/techniques/T1210/"
            }
        ]
    }
}


def map_cve_to_attack(cve_result: CVEResult) -> List[ATTACKTechnique]:
    """
    Map CVE results to ATT&CK techniques based on description and CVSS severity.
    
    Args:
        cve_result: CVE result from NVD API
        
    Returns:
        List of deduplicated ATT&CK techniques sorted by technique ID
    """
    techniques = []
    description = cve_result.description.lower()
    
    # Keyword-based mapping from CVE description
    keyword_mappings = {
        "remote code execution": ["T1190", "T1059"],  # Exploit Public-Facing Application, Command and Scripting
        "buffer overflow": ["T1203"],  # Exploitation for Client Execution
        "sql injection": ["T1190"],  # Exploit Public-Facing Application
        "authentication bypass": ["T1078"],  # Valid Accounts
        "denial of service": ["T1499"],  # Endpoint Denial of Service
        "privilege escalation": ["T1068"],  # Exploitation for Privilege Escalation
        "information disclosure": ["T1552", "T1083"],  # Unsecured Credentials, File and Directory Discovery
        "cross-site scripting": ["T1059.007"],  # Command and Scripting: JavaScript
        "path traversal": ["T1083"],  # File and Directory Discovery
        "command injection": ["T1059"],  # Command and Scripting Interpreter
        "arbitrary code": ["T1190"],  # Exploit Public-Facing Application
        "jndi": ["T1190", "T1059"],  # Exploit Public-Facing Application, Command and Scripting (Log4j)
        "ldap": ["T1078"],  # Valid Accounts
        "execute arbitrary code": ["T1190", "T1059"],  # Exploit Public-Facing Application, Command and Scripting
        "bypasses the authentication": ["T1078"],  # Valid Accounts
    }
    
    # Check for keyword matches
    for keyword, technique_ids in keyword_mappings.items():
        if keyword in description:
            for technique_id in technique_ids:
                # Find technique in our database
                for category in ATTACK_TECHNIQUE_DB.values():
                    for items in category.values():
                        for item in items:
                            if item["id"] == technique_id:
                                techniques.append(ATTACKTechnique(
                                    id=item["id"],
                                    name=item["name"],
                                    tactic=item["tactic"],
                                    url=item["url"]
                                ))
                                break
    
    # Map based on CVSS severity
    cvss_score = cve_result.cvss_v3_score or cve_result.cvss_v2_score or 0.0
    if cvss_score >= 9.0:
        severity = "CRITICAL"
    elif cvss_score >= 7.0:
        severity = "HIGH"
    elif cvss_score >= 4.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    
    # Add severity-based techniques
    severity_techniques = ATTACK_TECHNIQUE_DB.get("cvss_severity_techniques", {}).get(severity, [])
    for item in severity_techniques:
        techniques.append(ATTACKTechnique(
            id=item["id"],
            name=item["name"],
            tactic=item["tactic"],
            url=item["url"]
        ))
    
    # Deduplicate by technique ID
    seen_ids = set()
    unique_techniques = []
    for technique in techniques:
        if technique.id not in seen_ids:
            seen_ids.add(technique.id)
            unique_techniques.append(technique)
    
    # Sort by technique ID
    unique_techniques.sort(key=lambda x: x.id)
    
    return unique_techniques


def enrich_scan_with_attack(
    scan_results: dict,
    cve_results: List[CVEResult],
    detected_services: List[ServiceDetectionResult]
) -> dict:
    """
    Enrich scan results with ATT&CK technique mappings.
    
    Args:
        scan_results: Original scan results dictionary
        cve_results: List of CVE results found
        detected_services: List of detected services
        
    Returns:
        Enhanced scan results with ATT&CK mappings
    """
    attack_techniques = []
    tactic_set = set()
    
    # Process each detected service
    for service_result in detected_services:
        service_name = service_result.service_name.lower()
        port = str(service_result.port)
        
        # Add service-based techniques
        service_techniques = ATTACK_TECHNIQUE_DB.get("service_techniques", {}).get(service_name, [])
        for item in service_techniques:
            technique_info = {
                "technique_id": item["id"],
                "technique_name": item["name"],
                "tactic": item["tactic"],
                "url": item["url"],
                "source": f"service:{service_name}",
                "cvss_context": None
            }
            attack_techniques.append(technique_info)
            tactic_set.add(item["tactic"])
        
        # Add port-based techniques
        port_techniques = ATTACK_TECHNIQUE_DB.get("port_techniques", {}).get(port, [])
        for item in port_techniques:
            technique_info = {
                "technique_id": item["id"],
                "technique_name": item["name"],
                "tactic": item["tactic"],
                "url": item["url"],
                "source": f"port:{port}",
                "cvss_context": None
            }
            attack_techniques.append(technique_info)
            tactic_set.add(item["tactic"])
    
    # Process CVE results
    for cve in cve_results:
        cve_techniques = map_cve_to_attack(cve)
        for technique in cve_techniques:
            cvss_score = cve.cvss_v3_score or cve.cvss_v2_score or 0.0
            technique_info = {
                "technique_id": technique.id,
                "technique_name": technique.name,
                "tactic": technique.tactic,
                "url": technique.url,
                "source": f"cve:{cve.cve_id}",
                "cvss_context": cvss_score
            }
            attack_techniques.append(technique_info)
            tactic_set.add(technique.tactic)
    
    # Deduplicate techniques by ID
    seen_ids = set()
    unique_techniques = []
    for technique in attack_techniques:
        if technique["technique_id"] not in seen_ids:
            seen_ids.add(technique["technique_id"])
            unique_techniques.append(technique)
    
    # Sort by technique ID
    unique_techniques.sort(key=lambda x: x["technique_id"])
    
    # Add ATT&CK data to scan results
    scan_results["attack_techniques"] = unique_techniques
    scan_results["tactics_summary"] = sorted(list(tactic_set))
    scan_results["attack_technique_count"] = len(unique_techniques)
    
    return scan_results
