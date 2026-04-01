import dataclasses
import logging
import time
from typing import Optional

try:
    import dns.asyncresolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

logger = logging.getLogger(__name__)


@dataclasses.dataclass(slots=True)
class DNSResult:
    target: str
    a_records: list[str] = dataclasses.field(default_factory=list)
    aaaa_records: list[str] = dataclasses.field(default_factory=list)
    mx_records: list[str] = dataclasses.field(default_factory=list)
    ns_records: list[str] = dataclasses.field(default_factory=list)
    txt_records: list[str] = dataclasses.field(default_factory=list)
    soa_record: Optional[str] = None
    cname_records: list[str] = dataclasses.field(default_factory=list)
    query_time_ms: float = 0.0
    error: Optional[str] = None


class DNSTool:
    async def lookup(self, target: str, record_type: str = "ALL") -> DNSResult:
        result = DNSResult(target=target)

        if not HAS_DNSPYTHON:
            result.error = "dnspython not installed"
            return result

        start_time = time.monotonic()
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 10.0

        types_to_fetch = ["ALL"] if record_type == "ALL" else [record_type.upper()]
        all_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"] if "ALL" in types_to_fetch else types_to_fetch

        for rtype in all_types:
            try:
                if rtype == "A":
                    answers = await resolver.resolve(target, "A")
                    result.a_records = [str(rdata) for rdata in answers]
                elif rtype == "AAAA":
                    answers = await resolver.resolve(target, "AAAA")
                    result.aaaa_records = [str(rdata) for rdata in answers]
                elif rtype == "MX":
                    answers = await resolver.resolve(target, "MX")
                    result.mx_records = [f"{r.preference} {r.exchange}" for r in answers]
                elif rtype == "NS":
                    answers = await resolver.resolve(target, "NS")
                    result.ns_records = [str(rdata) for rdata in answers]
                elif rtype == "TXT":
                    answers = await resolver.resolve(target, "TXT")
                    txt_records = []
                    for rdata in answers:
                        for string in rdata.strings:
                            txt_records.append(string.decode("utf-8", errors="replace"))
                    result.txt_records = txt_records
                elif rtype == "SOA":
                    answers = await resolver.resolve(target, "SOA")
                    if answers:
                        rdata = answers[0]
                        result.soa_record = f"{rdata.mname} {rdata.rname} (serial: {rdata.serial})"
                elif rtype == "CNAME":
                    answers = await resolver.resolve(target, "CNAME")
                    result.cname_records = [str(rdata) for rdata in answers]
            except dns.exception.DNSException as e:
                logger.debug(f"{rtype} record lookup failed for {target}: {e}")

        result.query_time_ms = (time.monotonic() - start_time) * 1000
        return result
