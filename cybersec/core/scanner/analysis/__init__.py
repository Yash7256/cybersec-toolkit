try:
    from cybersec.core.scanner.analysis.service_detect import ServiceDetector, ServiceDetectionResult
except ImportError:
    ServiceDetector = None
    ServiceDetectionResult = None

try:
    from cybersec.core.scanner.analysis.service_detect_v2 import ServiceInfo
except ImportError:
    ServiceInfo = None

try:
    from cybersec.core.scanner.analysis.port_analyzer import PortAnalyzer, PortRisk
except ImportError:
    PortAnalyzer = None
    PortRisk = None

try:
    from cybersec.core.scanner.analysis.os_fingerprint import OSFingerprinter, OSFingerprint
except ImportError:
    OSFingerprinter = None
    OSFingerprint = None

try:
    from cybersec.core.scanner.analysis.tls_fingerprint import TLSFingerprinter, TLSInfo
except ImportError:
    TLSFingerprinter = None
    TLSInfo = None

try:
    from cybersec.core.security.cve_lookup import CVELookup, CVEEntry
except ImportError:
    CVELookup = None
    CVEEntry = None