try:
    from cybersec.core.scanner.scans.syn import SYNScanner, RetryStats, RetryConfig
except (ImportError, PermissionError):
    SYNScanner = None
    RetryStats = None
    RetryConfig = None

try:
    from cybersec.core.scanner.scans.udp import UDPScanner, UDPResult, RetryStats as UdpRetryStats, RetryConfig as UdpRetryConfig
except (ImportError, PermissionError):
    UDPScanner = None
    UDPResult = None
    UdpRetryStats = None
    UdpRetryConfig = None

try:
    from cybersec.core.scanner.scans.stealth import StealthScanner
except (ImportError, PermissionError):
    StealthScanner = None

try:
    from cybersec.core.scanner.scans.zombie import ZombieScanner
except (ImportError, PermissionError):
    ZombieScanner = None