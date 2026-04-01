import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class CVEEntry:
    id: str
    cvss_score: float
    severity: str
    description: str


WELL_KNOWN_CVES = {
    ("openssh", "7.4"): [
        CVEEntry(
            id="CVE-2017-15906",
            cvss_score=5.3,
            severity="Medium",
            description="OpenSSH before 7.6 is prone to a pre-authentication denial of service vulnerability.",
        )
    ],
    ("openssh", "7.6"): [
        CVEEntry(
            id="CVE-2018-15473",
            cvss_score=5.3,
            severity="Medium",
            description="OpenSSH through 7.7 is prone to an user enumeration vulnerability via timing attacks.",
        )
    ],
    ("openssh", "8.0"): [
        CVEEntry(
            id="CVE-2019-6109",
            cvss_score=4.8,
            severity="Medium",
            description="OpenSSH 7.9 has a cleartext credential vulnerability in scp.",
        )
    ],
    ("openssh", "8.4"): [
        CVEEntry(
            id="CVE-2021-28041",
            cvss_score=7.0,
            severity="High",
            description="OpenSSH before 8.5 is susceptible to a command injection vulnerability.",
        )
    ],
    ("openssh", "9.0"): [
        CVEEntry(
            id="CVE-2023-38408",
            cvss_score=7.8,
            severity="High",
            description="OpenSSH through 9.3 has a remote code execution vulnerability via /usr/bin/ssh-agent.",
        )
    ],
    ("apache", "2.4"): [
        CVEEntry(
            id="CVE-2021-41773",
            cvss_score=7.5,
            severity="High",
            description="Apache HTTP Server 2.4.49 allows path traversal and remote code execution.",
        )
    ],
    ("nginx", "1.14"): [
        CVEEntry(
            id="CVE-2019-9511",
            cvss_score=7.5,
            severity="High",
            description="nginx before 1.16.1 is vulnerable to HTTP/2 request handling issues (Data Dribble).",
        )
    ],
    ("nginx", "1.16"): [
        CVEEntry(
            id="CVE-2021-23017",
            cvss_score=8.1,
            severity="High",
            description="nginx resolver vulnerable to DNS cache poisoning.",
        )
    ],
    ("nginx", "1.20"): [
        CVEEntry(
            id="CVE-2022-41741",
            cvss_score=5.3,
            severity="Medium",
            description="nginx vulnerability in mp4 module.",
        )
    ],
    ("mysql", "5.7"): [
        CVEEntry(
            id="CVE-2019-2627",
            cvss_score=6.5,
            severity="Medium",
            description="MySQL Server MySQL 5.7.26 and earlier vulnerable to unspecified impact.",
        )
    ],
    ("mysql", "8.0"): [
        CVEEntry(
            id="CVE-2020-2574",
            cvss_score=6.5,
            severity="Medium",
            description="MySQL Server 8.0.19 and earlier vulnerable to unspecified impact via Audit Log component.",
        )
    ],
    ("postgresql", "11"): [
        CVEEntry(
            id="CVE-2019-9193",
            cvss_score=8.8,
            severity="High",
            description="PostgreSQL 9.3 through 11.2 allows COPY to execute arbitrary programs.",
        )
    ],
    ("postgresql", "12"): [
        CVEEntry(
            id="CVE-2020-14349",
            cvss_score=7.5,
            severity="High",
            description="PostgreSQL 12.4 has a vulnerability in the INFORMATION_SCHEMA.",
        )
    ],
    ("postgresql", "13"): [
        CVEEntry(
            id="CVE-2022-1552",
            cvss_score=8.1,
            severity="High",
            description="PostgreSQL 13.x before 13.7 allows autovacuum, REINDEX, and others to execute arbitrary code.",
        )
    ],
    ("redis", "4.0"): [
        CVEEntry(
            id="CVE-2018-11218",
            cvss_score=8.8,
            severity="High",
            description="Redis before 4.0.10 allows Lua script execution of arbitrary commands.",
        )
    ],
    ("redis", "5.0"): [
        CVEEntry(
            id="CVE-2019-10192",
            cvss_score=8.8,
            severity="High",
            description="Redis before 5.0.4 allows arbitrary Lua script execution.",
        )
    ],
    ("redis", "6.0"): [
        CVEEntry(
            id="CVE-2021-32625",
            cvss_score=9.1,
            severity="Critical",
            description="Redis 6.x before 6.2.5 has a heap overflow vulnerability.",
        )
    ],
    ("vsftpd", "3.0"): [
        CVEEntry(
            id="CVE-2015-3306",
            cvss_score=10.0,
            severity="Critical",
            description="The mod_copy module in vsftpd 2.3.4 to 3.0.3 allows remote attackers to write to arbitrary files.",
        )
    ],
    ("proftpd", "1.3"): [
        CVEEntry(
            id="CVE-2019-12815",
            cvss_score=9.8,
            severity="Critical",
            description="ProFTPD up to 1.3.5b allows remote code execution via mod_copy.",
        )
    ],
    ("smtp", None): [
        CVEEntry(
            id="CVE-2019-15846",
            cvss_score=7.5,
            severity="High",
            description="Exim before 4.92.2 allows remote attackers to execute arbitrary code.",
        )
    ],
    ("smb", None): [
        CVEEntry(
            id="CVE-2017-0144",
            cvss_score=9.8,
            severity="Critical",
            description="EternalBlue - Remote code execution via SMBv1.",
        )
    ],
    ("samba", "4.0"): [
        CVEEntry(
            id="CVE-2017-0144",
            cvss_score=9.8,
            severity="Critical",
            description="Samba vulnerable to EternalBlue-equivalent remote code execution.",
        )
    ],
    ("openssl", "1.0"): [
        CVEEntry(
            id="CVE-2014-0160",
            cvss_score=5.0,
            severity="Medium",
            description="Heartbleed - OpenSSL 1.0.1 through 1.0.1f allows information disclosure.",
        )
    ],
    ("openssl", "1.0.2"): [
        CVEEntry(
            id="CVE-2016-2107",
            cvss_score=5.9,
            severity="Medium",
            description="OpenSSL 1.0.2 before 1.0.2n has a padding oracle in AES-NI CBC MAC check.",
        )
    ],
    ("openssl", "1.1.0"): [
        CVEEntry(
            id="CVE-2017-3735",
            cvss_score=5.9,
            severity="Medium",
            description="OpenSSL 1.1.0 before 1.1.0d has a 1-byte buffer overread in SSL_get_shared_ciphers.",
        )
    ],
    ("telnet", None): [
        CVEEntry(
            id="CVE-2020-10188",
            cvss_score=9.8,
            severity="Critical",
            description="Telnetd vulnerability allows remote code execution.",
        )
    ],
    ("http", None): [
        CVEEntry(
            id="CVE-2021-41773",
            cvss_score=7.5,
            severity="High",
            description="Apache path traversal vulnerability.",
        ),
        CVEEntry(
            id="CVE-2021-42013",
            cvss_score=9.8,
            severity="Critical",
            description="Apache 2.4.50 path traversal and remote code execution.",
        ),
    ],
    ("elasticsearch", "7.0"): [
        CVEEntry(
            id="CVE-2015-1427",
            cvss_score=9.8,
            severity="Critical",
            description="Elasticsearch Groovy sandbox bypass leading to remote code execution.",
        )
    ],
    ("mongodb", "3.0"): [
        CVEEntry(
            id="CVE-2019-2389",
            cvss_score=7.5,
            severity="High",
            description="MongoDB Server JavaScript engine may incorrectly provide access to objects.",
        )
    ],
    ("memcached", "1.5"): [
        CVEEntry(
            id="CVE-2018-11212",
            cvss_score=8.1,
            severity="High",
            description="Memcached versions 1.5.5 and earlier allow remote attackers to cause denial of service.",
        )
    ],
    ("docker", None): [
        CVEEntry(
            id="CVE-2019-13139",
            cvss_score=8.8,
            severity="High",
            description="Docker Engine vulnerable to command injection in docker build.",
        )
    ],
}


class CVELookup:
    def __init__(self) -> None:
        self._cache: dict[str, list[CVEEntry]] = {}
        self._nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def _get_cache_key(self, service: str, version: str | None) -> str:
        service_lower = service.lower().split()[0]
        return f"{service_lower}:{version or 'any'}"

    def lookup(self, service: str, version: str | None = None) -> list[CVEEntry]:
        cache_key = self._get_cache_key(service, version)

        if cache_key in self._cache:
            return self._cache[cache_key]

        cves = self._lookup_fallback(service, version)
        self._cache[cache_key] = cves

        return cves

    def _lookup_fallback(self, service: str, version: str | None) -> list[CVEEntry]:
        service_lower = service.lower().split()[0]

        if (service_lower, version) in WELL_KNOWN_CVES:
            return WELL_KNOWN_CVES[(service_lower, version)]

        if (service_lower, None) in WELL_KNOWN_CVES:
            return WELL_KNOWN_CVES[(service_lower, None)]

        if version:
            version_major = version.split(".")[0] if "." in version else version
            if (service_lower, version_major) in WELL_KNOWN_CVES:
                return WELL_KNOWN_CVES[(service_lower, version_major)]

        return []

    def severity_from_score(self, score: float) -> str:
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        else:
            return "Low"
