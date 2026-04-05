"""
CVE lookup functionality.
"""
from dataclasses import dataclass
from typing import Optional

@dataclass
class CVEEntry:
    id: str
    cvss_score: float
    severity: str
    description: str

CVE_DATABASE: dict[str, list[CVEEntry]] = {
    "ssh": [
        CVEEntry("CVE-2023-38408", 9.8, "CRITICAL", "Remote Code Execution in OpenSSH forwarded ssh-agent"),
        CVEEntry("CVE-2021-28041", 7.1, "HIGH", "OpenSSH ssh-agent memory exhaustion")
    ],
    "ftp": [
        CVEEntry("CVE-2020-0001", 5.0, "MEDIUM", "FTP bounce attack"),
        CVEEntry("CVE-2015-3306", 10.0, "CRITICAL", "ProFTPd 1.3.5 mod_copy Remote Command Execution")
    ],
    "smtp": [
        CVEEntry("CVE-2020-28017", 8.1, "HIGH", "Exim buffer overflow"),
        CVEEntry("CVE-2019-10149", 9.8, "CRITICAL", "Exim Return-path Remote Command Execution")
    ],
    "http": [
        CVEEntry("CVE-2021-41773", 7.5, "HIGH", "Apache HTTP Server path traversal")
    ],
    "https": [
        CVEEntry("CVE-2014-0160", 7.5, "HIGH", "Heartbleed in OpenSSL")
    ],
    "mysql": [
        CVEEntry("CVE-2022-21278", 5.5, "MEDIUM", "MySQL Server vulnerability")
    ],
    "postgresql": [
        CVEEntry("CVE-2022-1552", 8.8, "HIGH", "PostgreSQL privilege escalation")
    ],
    "redis": [
        CVEEntry("CVE-2022-0543", 10.0, "CRITICAL", "Redis Lua escape vulnerability")
    ],
    "mongodb": [
        CVEEntry("CVE-2019-2386", 7.5, "HIGH", "MongoDB improper authorization")
    ],
    "smb": [
        CVEEntry("CVE-2017-0144", 8.1, "HIGH", "EternalBlue SMBv1 vulnerability")
    ],
    "rdp": [
        CVEEntry("CVE-2019-0708", 9.8, "CRITICAL", "BlueKeep RDP vulnerability")
    ],
    "telnet": [
        CVEEntry("CVE-2020-10188", 9.8, "CRITICAL", "telnetd buffer overflow")
    ],
    "vnc": [
        CVEEntry("CVE-2019-15690", 9.8, "CRITICAL", "VNC heap buffer overflow")
    ],
    "elasticsearch": [
        CVEEntry("CVE-2021-44228", 10.0, "CRITICAL", "Log4j Remote Code Execution (Log4Shell)")
    ],
    "memcached": [
        CVEEntry("CVE-2018-1000115", 9.8, "CRITICAL", "Memcached UDP amplification")
    ]
}

class CVELookup:
    def lookup(self, service: str, version: Optional[str] = None) -> list[CVEEntry]:
        try:
            service_lower = service.lower()
            if version:
                search_key = f"{service_lower}-{version.lower()}"
                if search_key in CVE_DATABASE:
                    return CVE_DATABASE[search_key]
            if service_lower in CVE_DATABASE:
                return CVE_DATABASE[service_lower]
            return []
        except Exception:
            return []
