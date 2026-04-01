import asyncio
import dataclasses
import logging
from typing import Optional

logger = logging.getLogger(__name__)


@dataclasses.dataclass(slots=True)
class WhoisResult:
    target: str
    domain_name: Optional[str] = None
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    name_servers: list[str] = dataclasses.field(default_factory=list)
    status: Optional[str] = None
    emails: list[str] = dataclasses.field(default_factory=list)
    org: Optional[str] = None
    country: Optional[str] = None
    raw_text: Optional[str] = None
    error: Optional[str] = None


class WhoisTool:
    def _sync_lookup(self, target: str) -> WhoisResult:
        result = WhoisResult(target=target)

        try:
            import whois

            domain = whois.whois(target)

            if domain:
                result.domain_name = domain.domain_name
                result.registrar = domain.registrar

                if domain.creation_date:
                    if isinstance(domain.creation_date, list):
                        result.creation_date = str(domain.creation_date[0])
                    else:
                        result.creation_date = str(domain.creation_date)

                if domain.expiration_date:
                    if isinstance(domain.expiration_date, list):
                        result.expiration_date = str(domain.expiration_date[0])
                    else:
                        result.expiration_date = str(domain.expiration_date)

                if domain.updated_date:
                    if isinstance(domain.updated_date, list):
                        result.updated_date = str(domain.updated_date[0])
                    else:
                        result.updated_date = str(domain.updated_date)

                if domain.name_servers:
                    if isinstance(domain.name_servers, list):
                        result.name_servers = [str(ns) for ns in domain.name_servers]
                    else:
                        result.name_servers = [str(domain.name_servers)]

                if domain.status:
                    if isinstance(domain.status, list):
                        result.status = "; ".join(str(s) for s in domain.status[:5])
                    else:
                        result.status = str(domain.status)

                if domain.emails:
                    if isinstance(domain.emails, list):
                        result.emails = [str(e) for e in domain.emails]
                    else:
                        result.emails = [str(domain.emails)]

                result.org = domain.org
                result.country = domain.country
                result.raw_text = str(domain)

        except ImportError:
            result.error = "python-whois not installed"
        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {target}: {type(e).__name__}: {e}")
            result.error = str(e)

        return result

    async def lookup(self, target: str) -> WhoisResult:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._sync_lookup, target)
