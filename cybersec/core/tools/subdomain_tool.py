import asyncio
import dataclasses
import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)


SMALL_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
    "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
    "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
    "docs", "beta", "shop", "sql", "secure", "demo", "v2", "api", "cdn", "stats",
    "web", "bbs", "ns4", "email", "git", "staging", "stage", "beta", "backup",
    "irc", "ssh", "sftp", "cvs", "svn", "gitlab", "jenkins", "ci", "proxy",
    "passport", "auth", "oauth", "sso", "ldap", "ad", " vpn", "owa", "exchange",
]

MEDIUM_WORDLIST = SMALL_WORDLIST + [
    "panel", "control", "manage", "manage", "office", "corporate", "intranet",
    "portal", "gateway", "router", "firewall", "vpn", "vpn2", "remote", "access",
    "monitor", "zabbix", "nagios", "grafana", "prometheus", "kibana", "logstash",
    "docker", "k8s", "kubernetes", "etcd", "consul", "vault", "minio", "s3",
    "backup", "backups", "archive", "db", "database", "mysql", "postgres", "mongo",
    "redis", "rabbitmq", "kafka", "elasticsearch", "solr", "zookeeper", "hadoop",
    "spark", "flink", "storm", "k8s-api", "kube-apiserver", "metrics", "alertmanager",
    "pagerduty", "slack", "discord", "teams", "zoom", "jitsi", "meet", "webinar",
    "crm", "erp", "sap", "salesforce", "hubspot", "zoho", "mailchimp", "sendgrid",
    "twilio", "nexmo", "plivo", "stripe", "braintree", "paypal", "square", "shopify",
    "magento", "woocommerce", "prestashop", "opencart", "bigcommerce", "lightspeed",
    "cloudsync", "dropbox", "box", "gdrive", "onedrive", "s3", "backblaze", "wasabi",
    "cloudfront", "fastly", "akamai", "cloudflare", "incapsula", "sucuri", "imperva",
    "akamai", "limelight", "edgecast", "level3", "verizon", "att", "comcast", "verizon",
    "t-mobile", "sprint", "at&t", "vodafone", "orange", "telefonica", "deutsche-telekom",
    "gpon", "ont", "olt", "switch", "router", "firewall", "asa", "pfsense", "opnsense",
    "fortinet", "sophos", "watchguard", "citrix", "vmware", "hyperv", "proxmox",
    "esxi", "vcenter", "horizon", "xen", "kvm", "qemu", "virtualbox", "parallels",
    "plesk", "cpanel", "directadmin", "virtualmin", "webmin", "vestacp", "ispconfig",
    "cyberpanel", "fastpanel", "runcloud", "laravel", "forge", "vapor", "heroku",
    "netlify", "vercel", "render", "firebase", "supabase", "amplify", "cloudflare",
    "workers", "pages", "r2", "d1", "durable-objects", "kv", "do", "s3",
]

LARGE_WORDLIST = MEDIUM_WORDLIST + [
    "host1", "host2", "host3", "server", "server1", "server2", "server3",
    "node", "node1", "node2", "master", "worker", "lb", "loadbalancer", "ha",
    "dr", "disaster", "recovery", "uat", "staging", "production", "prod",
    "dev1", "dev2", "test1", "test2", "qa", "training", "demo1", "demo2",
    "uat1", "uat2", "perf", "loadtest", "bench", "monitoring", "alerts",
    "ops", "sre", "devops", "platform", "infra", "infrastructure", "cloud",
    "aws", "azure", "gcp", "digitalocean", "linode", "vultr", "scaleway",
    "hetzner", "ovh", "contabo", "leaseweb", "softlayer", "rackspace",
    "bluehost", "godaddy", "namecheap", "domain", "dns", "mx1", "mx2",
    "spf", "dkim", "dmarc", "webdisk", "cpcalendars", "cpcontacts",
    "autoconfig", "msoid", "sip", "sips", "lb1", "lb2", "vip", "cluster",
    "k8s", "eks", "gke", "aks", "rancher", "openshift", "tectonic",
    "argocd", "tekton", "gitlab", "github", "bitbucket", "source", "repo",
    "nexus", "artifactory", "harbor", "quay", "dockerhub", "ghcr",
    "squid", "varnish", "nginx", "apache", "httpd", "tomcat", "jboss",
    "wildfly", "jetty", "undertow", "resin", "iis", "kestrel", "kestrel",
    "grpc", "thrift", "rest", "soap", "graphql", "odata", "webapi",
    "socket", "websocket", "mqtt", "amqp", "stomp", "xmpp", "irc",
    "snmp", "syslog", "rsyslog", "fluentd", "loggly", "papertrail",
    "sumologic", "splunk", "elk", "graylog", "loki", "promtail",
    "thanos", "cortex", "mimir", "grafana", "kiali", "jaeger", "zipkin",
    "opentelemetry", "otel", "tempo", "honeycomb", "datadog", "newrelic",
    "appdynamics", "dynatrace", "ca", "boundary", "telnet", "rlogin",
]


@dataclasses.dataclass(slots=True)
class SubdomainEntry:
    subdomain: str
    ip_addresses: list[str] = dataclasses.field(default_factory=list)
    cname: Optional[str] = None


@dataclasses.dataclass(slots=True)
class SubdomainResult:
    domain: str
    found: list[SubdomainEntry] = dataclasses.field(default_factory=list)
    total_checked: int = 0
    scan_time_ms: float = 0.0
    error: Optional[str] = None


class SubdomainTool:
    def _get_wordlist(self, size: str) -> list[str]:
        if size == "small":
            return SMALL_WORDLIST
        elif size == "large":
            return LARGE_WORDLIST
        else:
            return MEDIUM_WORDLIST

    async def find(self, domain: str, wordlist_size: str = "small") -> SubdomainResult:
        result = SubdomainResult(domain=domain)

        if not domain:
            result.error = "Domain is required"
            return result

        wordlist = self._get_wordlist(wordlist_size)
        result.total_checked = len(wordlist)

        start_time = time.monotonic()
        found: list[SubdomainEntry] = []
        semaphore = asyncio.Semaphore(50)

        try:
            import dns.asyncresolver
            import dns.resolver
            HAS_DNS = True
        except ImportError:
            HAS_DNS = False

        if not HAS_DNS:
            result.error = "dnspython not installed"
            return result

        async def check_subdomain(prefix: str) -> Optional[SubdomainEntry]:
            subdomain = f"{prefix}.{domain}"

            async with semaphore:
                try:
                    try:
                        answers = await dns.asyncresolver.resolve(subdomain, "A")
                        ips = [str(rdata) for rdata in answers]

                        cname = None
                        try:
                            cname_answers = await dns.asyncresolver.resolve(subdomain, "CNAME")
                            if cname_answers:
                                cname = str(cname_answers[0])
                        except dns.resolver.NoAnswer:
                            pass
                        except dns.resolver.NXDOMAIN:
                            pass

                        return SubdomainEntry(
                            subdomain=subdomain,
                            ip_addresses=ips,
                            cname=cname,
                        )

                    except dns.resolver.NXDOMAIN:
                        return None
                    except dns.resolver.NoAnswer:
                        return None
                    except dns.exception.DNSException as e:
                        logger.debug(f"DNS error for {subdomain}: {e}")
                        return None

                except Exception as e:
                    logger.debug(f"Error checking {subdomain}: {e}")
                    return None

        tasks = [check_subdomain(prefix) for prefix in wordlist]

        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for r in results:
                if isinstance(r, SubdomainEntry) and r is not None:
                    found.append(r)

        except Exception as e:
            logger.warning(f"Subdomain enumeration error: {e}")
            result.error = str(e)

        result.found = found
        result.scan_time_ms = round((time.monotonic() - start_time) * 1000, 2)
        return result
