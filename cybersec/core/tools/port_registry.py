"""
Unified port metadata registry.

Single source of truth merging the six previously separate dictionaries:
  COMMON_PORTS (port_scanner.py)
  PORT_DESCRIPTIONS (port_descriptions.py)
  HIGH/MEDIUM/LOW_RISK_PORTS (port_risk.py)
  EXPOSED_SERVICE_PORTS (port_scanner.py)
  MITRE_PORT_MAPPINGS (port_scanner.py)
  POTENTIAL_THREATS (port_scanner.py)

Backward-compatible derived views (COMMON_PORTS, HIGH_RISK_PORTS, etc.) are
generated at the bottom of this module so all existing import sites continue to
work without modification.

Risk-level conflict notes are marked with # CONFLICT where the old sources
disagreed; in every case the higher risk level is kept.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PortInfo:
    port: int
    service: str
    risk_level: str               # "low" | "medium" | "high"
    risk_reason: str
    purpose: str
    security_concern: str
    exposed_service_warning: str | None = None
    # Each tuple: (technique_id, technique_name, tactic)
    mitre_mappings: list[tuple[str, str, str]] = field(default_factory=list)
    potential_threat: str | None = None


# ---------------------------------------------------------------------------
# Master registry — union of all 48 ports across all 6 original sources.
# ---------------------------------------------------------------------------

PORT_REGISTRY: dict[int, PortInfo] = {
    # --- FTP ---
    21: PortInfo(
        port=21,
        service="FTP",
        risk_level="medium",
        risk_reason="FTP — cleartext credentials and file transfer",
        purpose="File Transfer Protocol for uploading and downloading files.",
        security_concern="Credentials and data travel in cleartext; anonymous uploads may be enabled.",
        exposed_service_warning="FTP exposes credentials and file access if not tightly controlled.",
        mitre_mappings=[
            ("T1071.002", "Application Layer Protocol: File Transfer Protocols", "Command and Control"),
            ("T1110", "Brute Force", "Credential Access"),
        ],
        potential_threat="Credential attacks and unauthorized file transfer are possible on FTP service.",
    ),
    # --- SSH ---
    22: PortInfo(
        port=22,
        service="SSH",
        risk_level="medium",
        risk_reason="SSH — remote administration surface",
        purpose="Secure remote login protocol for shell access and tunneling.",
        security_concern="Can be brute-forced if exposed publicly or weak keys/passwords are used.",
        exposed_service_warning=None,
        mitre_mappings=[
            ("T1110", "Brute Force", "Credential Access"),
            ("T1021.004", "Remote Services: SSH", "Lateral Movement"),
            ("T1078", "Valid Accounts", "Initial Access"),
        ],
        potential_threat="Brute force attempts possible on SSH service.",
    ),
    # --- Telnet ---
    23: PortInfo(
        port=23,
        service="Telnet",
        risk_level="high",
        risk_reason="Telnet transmits credentials in cleartext",
        purpose="Legacy remote terminal access to network devices and servers.",
        security_concern="All traffic including passwords is sent unencrypted — high interception risk.",
        exposed_service_warning=None,
        mitre_mappings=[
            ("T1110", "Brute Force", "Credential Access"),
            ("T1021", "Remote Services", "Lateral Movement"),
            ("T1048.003", "Exfiltration Over Unencrypted Protocol", "Exfiltration"),
        ],
        potential_threat="Cleartext credential theft and brute force attempts are possible on Telnet service.",
    ),
    # --- SMTP ---
    25: PortInfo(
        port=25,
        service="SMTP",
        risk_level="medium",
        risk_reason="SMTP — mail relay and user enumeration risk",
        purpose="Simple Mail Transfer Protocol for sending email between servers.",
        security_concern="Open relays and user enumeration can enable spam or phishing abuse.",
        exposed_service_warning=None,
        mitre_mappings=[
            ("T1071.003", "Application Layer Protocol: Mail Protocols", "Command and Control"),
            ("T1110", "Brute Force", "Credential Access"),
            ("T1566.001", "Phishing: Spearphishing Attachment", "Initial Access"),
        ],
        potential_threat="Mail relay abuse, account brute force, or phishing infrastructure abuse may be possible.",
    ),
    # --- DNS ---
    53: PortInfo(
        port=53,
        service="DNS",
        risk_level="medium",
        risk_reason="DNS — zone transfer and recursion misconfigurations",
        purpose="Domain Name System for resolving hostnames to IP addresses.",
        security_concern="Zone transfers and recursion misconfigurations may leak internal network data.",
        exposed_service_warning=None,
        mitre_mappings=[
            ("T1071.004", "Application Layer Protocol: DNS", "Command and Control"),
            ("T1595.001", "Active Scanning: Scanning IP Blocks", "Reconnaissance"),
        ],
        potential_threat="DNS tunneling, reconnaissance, or zone-transfer probing may be possible.",
    ),
    # --- TFTP ---
    69: PortInfo(
        port=69,
        service="TFTP",
        risk_level="high",
        risk_reason="TFTP has no authentication",
        purpose="Trivial File Transfer Protocol for diskless boot and firmware delivery.",
        security_concern="No authentication mechanism; any host can read or write files.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- HTTP ---
    80: PortInfo(
        port=80,
        service="HTTP",
        risk_level="low",
        risk_reason="HTTP — standard web service",
        purpose="Unencrypted web traffic for websites and APIs.",
        security_concern="Traffic can be intercepted or modified; outdated web apps increase exploit risk.",
        exposed_service_warning=None,
        mitre_mappings=[
            ("T1190", "Exploit Public-Facing Application", "Initial Access"),
            ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
        ],
        potential_threat="Public web exploitation and web reconnaissance are possible on HTTP service.",
    ),
    # --- POP3 ---
    110: PortInfo(
        port=110,
        service="POP3",
        risk_level="medium",
        risk_reason="POP3 — cleartext mail retrieval",
        purpose="Post Office Protocol for downloading email from a mail server.",
        security_concern="Usernames and passwords are often transmitted without encryption.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- RPC portmapper ---
    111: PortInfo(
        port=111,
        service="RPCBind",
        risk_level="high",
        risk_reason="RPC portmapper can expose internal services",
        purpose="RPC portmapper / sunrpc for registering and locating RPC services.",
        security_concern="Exposes a map of all RPC services; can reveal internal service topology.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- Microsoft RPC ---
    135: PortInfo(
        port=135,
        service="MS-RPC",
        risk_level="high",
        risk_reason="Microsoft RPC endpoint mapper",
        purpose="Microsoft RPC Endpoint Mapper used by Windows DCOM/WMI.",
        security_concern="Exposed DCOM/WMI services are frequent lateral movement vectors.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- NetBIOS ---
    139: PortInfo(
        port=139,
        service="NetBIOS",
        risk_level="high",
        risk_reason="NetBIOS session service",
        purpose="NetBIOS session service for legacy Windows file and printer sharing.",
        security_concern="Exposes machine names and may allow unauthenticated null sessions.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- IMAP ---
    143: PortInfo(
        port=143,
        service="IMAP",
        risk_level="medium",
        risk_reason="IMAP — mail access and credential exposure",
        purpose="Internet Message Access Protocol for remote mailbox management.",
        security_concern="Cleartext login exposes mail credentials on untrusted networks.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- SNMP ---
    161: PortInfo(
        port=161,
        service="SNMP",
        risk_level="medium",
        risk_reason="SNMP — community strings may leak device info",
        purpose="Simple Network Management Protocol for monitoring and managing network devices.",
        security_concern="Default community strings (public/private) can expose device configuration.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- LDAP ---
    389: PortInfo(
        port=389,
        service="LDAP",
        risk_level="medium",
        risk_reason="LDAP — directory authentication target",
        purpose="Lightweight Directory Access Protocol for directory services and authentication.",
        security_concern="Cleartext LDAP binds expose credentials; anonymous binds may leak user data.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- HTTPS ---
    443: PortInfo(
        port=443,
        service="HTTPS",
        risk_level="low",
        risk_reason="HTTPS — encrypted web service",
        purpose="Encrypted web traffic using TLS for websites and APIs.",
        security_concern="Certificate or TLS misconfiguration can still weaken confidentiality.",
        exposed_service_warning=None,
        mitre_mappings=[
            ("T1190", "Exploit Public-Facing Application", "Initial Access"),
            ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
        ],
        potential_threat="Public web exploitation and encrypted command-and-control traffic may blend into HTTPS service.",
    ),
    # --- SMB ---
    445: PortInfo(
        port=445,
        service="SMB",
        risk_level="high",
        risk_reason="SMB file sharing — frequent ransomware/lateral movement target",
        purpose="Server Message Block for Windows file and printer sharing.",
        security_concern="Frequent target for ransomware and lateral movement (e.g. EternalBlue).",
        exposed_service_warning="SMB is sensitive when exposed beyond trusted networks.",
        mitre_mappings=[
            ("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
            ("T1135", "Network Share Discovery", "Discovery"),
            ("T1110", "Brute Force", "Credential Access"),
        ],
        potential_threat="SMB exposure can enable lateral movement, share discovery, and credential attacks.",
    ),
    # --- rexec ---
    512: PortInfo(
        port=512,
        service="rexec",
        risk_level="high",
        risk_reason="rexec — legacy remote execution",
        purpose="Legacy BSD remote execution daemon.",
        security_concern="Transmits credentials in cleartext; no modern use case.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- rlogin ---
    513: PortInfo(
        port=513,
        service="rlogin",
        risk_level="high",
        risk_reason="rlogin — legacy remote login",
        purpose="Legacy BSD remote login daemon.",
        security_concern="Trust-based authentication easily spoofed; cleartext protocol.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- rsh ---
    514: PortInfo(
        port=514,
        service="rsh",
        risk_level="high",
        risk_reason="rsh — legacy remote shell",
        purpose="Legacy BSD remote shell daemon.",
        security_concern="No authentication in many implementations; trust relationships exploitable.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- LDAPS ---
    636: PortInfo(
        port=636,
        service="LDAPS",
        risk_level="medium",
        risk_reason="LDAPS — directory authentication target",
        purpose="LDAP over TLS for encrypted directory services.",
        security_concern="Weak TLS configuration or certificate issues can compromise directory auth.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- IMAPS ---
    993: PortInfo(
        port=993,
        service="IMAPS",
        risk_level="low",
        risk_reason="IMAPS — encrypted mail",
        purpose="IMAP over TLS for encrypted remote mailbox access.",
        security_concern="Weak TLS settings or expired certificates reduce protection.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- POP3S ---
    995: PortInfo(
        port=995,
        service="POP3S",
        risk_level="low",
        risk_reason="POP3S — encrypted mail",
        purpose="POP3 over TLS for encrypted mail download.",
        security_concern="Misconfigured TLS or credential stuffing still pose login risk.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- MSSQL --- CONFLICT: medium in MEDIUM_RISK_PORTS (admin port note) AND high in HIGH_RISK_PORTS;
    # keeping high as it is a high-value database target.
    1433: PortInfo(
        port=1433,
        service="MSSQL",
        risk_level="high",
        risk_reason="Microsoft SQL Server — high-value database target",
        purpose="Microsoft SQL Server database engine listener.",
        security_concern="Frequently targeted for credential attacks and SQL injection pivots.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- Oracle DB ---
    1521: PortInfo(
        port=1521,
        service="Oracle",
        risk_level="medium",
        risk_reason="Oracle database listener",
        purpose="Oracle Database TNS listener for client connections.",
        security_concern="Listener poison attacks and credential brute-force are common.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- Backdoor/bind port ---
    1524: PortInfo(
        port=1524,
        service="Ingreslock",
        risk_level="high",
        risk_reason="Often abused bind/backdoor port",
        purpose="Historically Ingres database; now commonly associated with backdoor shells.",
        security_concern="Any service on this port warrants immediate investigation.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- AWS EFS/NFS ---
    2048: PortInfo(
        port=2048,
        service="NFS-Alt",
        risk_level="medium",
        risk_reason="AWS EFS/NFS-related exposure",
        purpose="Alternate NFS or custom service port.",
        security_concern="NFS exports may grant unauthorized file-system access.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- NFS ---
    2049: PortInfo(
        port=2049,
        service="NFS",
        risk_level="high",
        risk_reason="NFS exports may leak sensitive files",
        purpose="Network File System daemon for shared filesystem access.",
        security_concern="Misconfigured NFS exports can allow unauthenticated access to filesystem data.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- Docker API ---
    2375: PortInfo(
        port=2375,
        service="Docker",
        risk_level="high",
        risk_reason="Docker API — unauthenticated remote control risk",
        purpose="Docker Engine REST API for container management.",
        security_concern="Unauthenticated Docker API grants full host control and container escape.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- Node.js dev ---
    3000: PortInfo(
        port=3000,
        service="Node-Dev",
        risk_level="medium",
        risk_reason="Node.js dev server — often unhardened",
        purpose="Common Node.js/Express development server or admin UI port.",
        security_concern="Dev servers often lack authentication, rate-limiting, and TLS.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- MySQL ---
    3306: PortInfo(
        port=3306,
        service="MySQL",
        risk_level="medium",
        risk_reason="MySQL — database administration port",
        purpose="Popular relational database server for application data storage.",
        security_concern="Exposed databases are scanned for weak credentials and SQL injection chains.",
        exposed_service_warning="MySQL should not be internet-exposed unless strongly restricted.",
        mitre_mappings=[
            ("T1110", "Brute Force", "Credential Access"),
            ("T1210", "Exploitation of Remote Services", "Lateral Movement"),
            ("T1190", "Exploit Public-Facing Application", "Initial Access"),
        ],
        potential_threat="Database brute force and remote service exploitation may be possible on MySQL.",
    ),
    # --- RDP alternate ---
    3388: PortInfo(
        port=3388,
        service="RDP-Alt",
        risk_level="medium",
        risk_reason="RDP alternate / clustered remote desktop",
        purpose="Alternate RDP port used in clustered or non-standard deployments.",
        security_concern="Carries the same brute-force and exploit risk as standard RDP (3389).",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- RDP ---
    3389: PortInfo(
        port=3389,
        service="RDP",
        risk_level="high",
        risk_reason="RDP — common brute-force and exploit target",
        purpose="Remote Desktop Protocol for graphical Windows administration.",
        security_concern="Common brute-force and exploit target when reachable from the internet.",
        exposed_service_warning="RDP is a common brute-force and ransomware target.",
        mitre_mappings=[
            ("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement"),
            ("T1110", "Brute Force", "Credential Access"),
            ("T1078", "Valid Accounts", "Initial Access"),
        ],
        potential_threat="Brute force attempts and remote desktop lateral movement are possible on RDP.",
    ),
    # --- Metasploit listener ---
    4444: PortInfo(
        port=4444,
        service="Metasploit",
        risk_level="high",
        risk_reason="Metasploit default listener port",
        purpose="Default Metasploit Framework reverse-shell listener port.",
        security_concern="Any service on this port is highly suspicious and warrants immediate investigation.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- Flask/Docker registry ---
    5000: PortInfo(
        port=5000,
        service="Flask-Dev",
        risk_level="medium",
        risk_reason="Flask/dev or Docker registry UI",
        purpose="Flask development server or Docker registry web UI.",
        security_concern="Development servers are rarely hardened; registries may expose private images.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- PostgreSQL ---
    5432: PortInfo(
        port=5432,
        service="PostgreSQL",
        risk_level="medium",
        risk_reason="PostgreSQL — database administration port",
        purpose="Advanced open-source relational database server.",
        security_concern="Public exposure invites credential attacks and privilege escalation attempts.",
        exposed_service_warning="PostgreSQL should not be internet-exposed unless strongly restricted.",
        mitre_mappings=[
            ("T1110", "Brute Force", "Credential Access"),
            ("T1210", "Exploitation of Remote Services", "Lateral Movement"),
            ("T1190", "Exploit Public-Facing Application", "Initial Access"),
        ],
        potential_threat="Database brute force and remote service exploitation may be possible on PostgreSQL.",
    ),
    # --- VNC ---
    5900: PortInfo(
        port=5900,
        service="VNC",
        risk_level="high",
        risk_reason="VNC — often weak or missing authentication",
        purpose="Virtual Network Computing for remote desktop viewing and control.",
        security_concern="Often protected only by a password; many instances lack encryption.",
        exposed_service_warning="VNC often exposes remote desktop access.",
        mitre_mappings=[
            ("T1021", "Remote Services", "Lateral Movement"),
            ("T1110", "Brute Force", "Credential Access"),
        ],
        potential_threat="Remote desktop takeover attempts may be possible on VNC.",
    ),
    # --- VNC display 1 ---
    5901: PortInfo(
        port=5901,
        service="VNC-1",
        risk_level="high",
        risk_reason="VNC alternate display",
        purpose="VNC display :1 — second virtual desktop session.",
        security_concern="Same risks as VNC on 5900; weak authentication and no encryption.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- VNC display 2 ---
    5902: PortInfo(
        port=5902,
        service="VNC-2",
        risk_level="medium",
        risk_reason="VNC session port",
        purpose="VNC display :2 — third virtual desktop session.",
        security_concern="Same risks as VNC on 5900.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- CouchDB ---
    5984: PortInfo(
        port=5984,
        service="CouchDB",
        risk_level="high",
        risk_reason="CouchDB — historical unauthenticated admin APIs",
        purpose="Apache CouchDB HTTP API for document-oriented database access.",
        security_concern="Older versions shipped with unauthenticated admin API; data exposure risk.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- Redis ---
    6379: PortInfo(
        port=6379,
        service="Redis",
        risk_level="high",
        risk_reason="Redis — frequently exposed without auth",
        purpose="In-memory key-value store used for caching and messaging.",
        security_concern="Frequently left without authentication, allowing remote command execution.",
        exposed_service_warning="Redis commonly lacks authentication on misconfigured deployments.",
        mitre_mappings=[
            ("T1190", "Exploit Public-Facing Application", "Initial Access"),
            ("T1210", "Exploitation of Remote Services", "Lateral Movement"),
            ("T1059", "Command and Scripting Interpreter", "Execution"),
        ],
        potential_threat="Redis exposure can lead to remote exploitation or command execution if misconfigured.",
    ),
    # --- Alternate HTTP ---
    8000: PortInfo(
        port=8000,
        service="HTTP-Alt",
        risk_level="medium",
        risk_reason="Alternate HTTP — often admin or dev panels",
        purpose="Alternate HTTP port commonly used for admin panels or dev servers.",
        security_concern="May expose management interfaces or unpatched application backends.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- HTTP Proxy / Alternate HTTP ---
    8080: PortInfo(
        port=8080,
        service="HTTP-Proxy",
        risk_level="medium",
        risk_reason="HTTP proxy or alternate web admin interface",
        purpose="Alternate HTTP port for proxies, dev servers, or admin panels.",
        security_concern="May expose management interfaces or unpatched application backends.",
        exposed_service_warning=None,
        mitre_mappings=[
            ("T1190", "Exploit Public-Facing Application", "Initial Access"),
            ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
            ("T1571", "Non-Standard Port", "Defense Evasion"),
        ],
        potential_threat="Public web exploitation may be possible on the alternate HTTP service.",
    ),
    # --- Alternate HTTPS ---
    8443: PortInfo(
        port=8443,
        service="HTTPS-Alt",
        risk_level="medium",
        risk_reason="Alternate HTTPS — admin or application portal",
        purpose="Alternate HTTPS port for web apps, proxies, or admin UIs.",
        security_concern="Non-standard TLS services are easy to misconfigure or forget to patch.",
        exposed_service_warning=None,
        mitre_mappings=[
            ("T1190", "Exploit Public-Facing Application", "Initial Access"),
            ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
            ("T1571", "Non-Standard Port", "Defense Evasion"),
        ],
        potential_threat="Public web exploitation may be possible on the alternate HTTPS service.",
    ),
    # --- Dev/management UI ---
    8888: PortInfo(
        port=8888,
        service="HTTP-Dev",
        risk_level="medium",
        risk_reason="Alternate HTTP — common dev/management UI",
        purpose="Often used by Jupyter Notebook, dev servers, or custom admin UIs.",
        security_concern="Dev UIs frequently lack auth; Jupyter historically allowed unauthenticated code execution.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- SonarQube / PHP-FPM / mgmt ---
    9000: PortInfo(
        port=9000,
        service="SonarQube",
        risk_level="medium",
        risk_reason="SonarQube / PHP-FPM / management services",
        purpose="SonarQube, PHP-FPM FastCGI, or other management service port.",
        security_concern="Management services can expose source code, configs, or code execution.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- Elasticsearch ---
    9200: PortInfo(
        port=9200,
        service="Elasticsearch",
        risk_level="high",
        risk_reason="Elasticsearch — cluster data exposure risk",
        purpose="Elasticsearch REST API for full-text search and analytics.",
        security_concern="Without authentication, the full index contents are readable by anyone.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- Memcached ---
    11211: PortInfo(
        port=11211,
        service="Memcached",
        risk_level="high",
        risk_reason="Memcached — amplification and data leak risk",
        purpose="Distributed memory object caching system.",
        security_concern="No authentication by default; UDP mode used in amplification DDoS attacks.",
        exposed_service_warning=None,
        mitre_mappings=[],
        potential_threat=None,
    ),
    # --- MongoDB ---
    27017: PortInfo(
        port=27017,
        service="MongoDB",
        risk_level="high",
        risk_reason="MongoDB — frequent unauthenticated deployments",
        purpose="Document-oriented NoSQL database for modern applications.",
        security_concern="Historically many deployments allowed unauthenticated access from the internet.",
        exposed_service_warning="MongoDB should not be internet-exposed unless strongly restricted.",
        mitre_mappings=[
            ("T1110", "Brute Force", "Credential Access"),
            ("T1210", "Exploitation of Remote Services", "Lateral Movement"),
            ("T1190", "Exploit Public-Facing Application", "Initial Access"),
        ],
        potential_threat="Database exposure and unauthorized data access may be possible on MongoDB.",
    ),
}


# ---------------------------------------------------------------------------
# Backward-compatible derived views — generated from PORT_REGISTRY so that
# every existing import site works without modification.
# ---------------------------------------------------------------------------

# Replaces the old hard-coded 19-port dict in port_scanner.py.
# Now covers all 48 ports in the registry.
COMMON_PORTS: dict[int, str] = {p: info.service for p, info in PORT_REGISTRY.items()}

# Risk-level groupings (as used by port_risk.py)
HIGH_RISK_PORTS: dict[int, str] = {
    p: info.risk_reason for p, info in PORT_REGISTRY.items() if info.risk_level == "high"
}
MEDIUM_RISK_PORTS: dict[int, str] = {
    p: info.risk_reason for p, info in PORT_REGISTRY.items() if info.risk_level == "medium"
}
LOW_RISK_PORTS: dict[int, str] = {
    p: info.risk_reason for p, info in PORT_REGISTRY.items() if info.risk_level == "low"
}

# Exposed-service warnings (port_scanner.py EXPOSED_SERVICE_PORTS)
EXPOSED_SERVICE_PORTS: dict[int, str] = {
    p: info.exposed_service_warning
    for p, info in PORT_REGISTRY.items()
    if info.exposed_service_warning is not None
}

# MITRE ATT&CK mappings (port_scanner.py MITRE_PORT_MAPPINGS)
MITRE_PORT_MAPPINGS: dict[int, list[tuple[str, str, str]]] = {
    p: list(info.mitre_mappings)
    for p, info in PORT_REGISTRY.items()
    if info.mitre_mappings
}

# Potential threats (port_scanner.py POTENTIAL_THREATS)
POTENTIAL_THREATS: dict[int, str] = {
    p: info.potential_threat
    for p, info in PORT_REGISTRY.items()
    if info.potential_threat is not None
}
