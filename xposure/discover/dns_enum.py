"""DNS enumeration for X-POSURE v5.0.

Performs comprehensive DNS reconnaissance on a target domain: zone-transfer
attempts (AXFR), record enumeration (MX, TXT, SRV, CNAME), and extraction
of additional domains from SPF, DKIM, and DMARC records.

Uses :mod:`aiodns` for fully async DNS queries.
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Optional

import aiodns

from ..config import Config


# Common SRV prefixes to enumerate
_SRV_PREFIXES: list[str] = [
    "_http._tcp",
    "_https._tcp",
    "_sip._tcp",
    "_sip._udp",
    "_sips._tcp",
    "_xmpp-client._tcp",
    "_xmpp-server._tcp",
    "_imaps._tcp",
    "_imap._tcp",
    "_submission._tcp",
    "_pop3s._tcp",
    "_caldav._tcp",
    "_carddav._tcp",
    "_ldap._tcp",
    "_kerberos._tcp",
    "_kerberos._udp",
    "_autodiscover._tcp",
    "_matrix._tcp",
]

# Regex helpers for parsing DNS record payloads
_SPF_INCLUDE_RE = re.compile(r"include:(\S+)", re.IGNORECASE)
_SPF_REDIRECT_RE = re.compile(r"redirect=(\S+)", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}"
)


@dataclass
class DNSEnumResult:
    """Aggregated DNS enumeration results for a domain."""

    domain: str
    subdomains: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    srv_records: list[dict] = field(default_factory=list)
    cname_records: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    axfr_results: list[str] = field(default_factory=list)
    spf_includes: list[str] = field(default_factory=list)
    dkim_domains: list[str] = field(default_factory=list)
    dmarc_domains: list[str] = field(default_factory=list)
    additional_domains: list[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "subdomains": self.subdomains,
            "mx_records": self.mx_records,
            "txt_records": self.txt_records,
            "srv_records": self.srv_records,
            "cname_records": self.cname_records,
            "ns_records": self.ns_records,
            "axfr_results": self.axfr_results,
            "spf_includes": self.spf_includes,
            "dkim_domains": self.dkim_domains,
            "dmarc_domains": self.dmarc_domains,
            "additional_domains": self.additional_domains,
            "error": self.error,
        }


class DNSEnumerator:
    """Enumerate DNS records for a domain.

    Usage::

        enumerator = DNSEnumerator(config)
        subdomains = await enumerator.enumerate("example.com")
    """

    def __init__(self, config: Config, timeout: float = 5.0):
        self.config = config
        self.timeout = timeout
        self._resolver: Optional[aiodns.DNSResolver] = None
        self.stats = {
            "queries": 0,
            "successful": 0,
            "failed": 0,
            "domains_found": 0,
        }

    async def enumerate(self, domain: str) -> list[str]:
        """Perform full DNS enumeration and return discovered subdomains.

        Args:
            domain: Target domain (e.g. ``"example.com"``).

        Returns:
            Deduplicated list of all discovered domain names / subdomains.
        """
        self._resolver = aiodns.DNSResolver(timeout=self.timeout)
        result = DNSEnumResult(domain=domain)
        discovered: set[str] = set()

        # 1. AXFR (zone transfer) attempt
        axfr_names = await self._try_axfr(domain)
        result.axfr_results = axfr_names
        discovered.update(axfr_names)

        # 2. NS records (useful for AXFR and general recon)
        ns_records = await self._query_ns(domain)
        result.ns_records = ns_records
        discovered.update(ns_records)

        # 3. MX records
        mx_records = await self._query_mx(domain)
        result.mx_records = mx_records
        discovered.update(mx_records)

        # 4. TXT records (SPF / DKIM / DMARC parsing)
        txt_records = await self._query_txt(domain)
        result.txt_records = txt_records

        # Parse SPF
        spf_domains = self._parse_spf(txt_records)
        result.spf_includes = spf_domains
        discovered.update(spf_domains)

        # Parse DMARC
        dmarc_domains = await self._parse_dmarc(domain)
        result.dmarc_domains = dmarc_domains
        discovered.update(dmarc_domains)

        # Parse DKIM (common selectors)
        dkim_domains = await self._parse_dkim(domain)
        result.dkim_domains = dkim_domains
        discovered.update(dkim_domains)

        # 5. SRV records
        srv_records = await self._query_srv(domain)
        result.srv_records = srv_records
        for srv in srv_records:
            host = srv.get("host", "")
            if host:
                discovered.add(host)

        # 6. CNAME for common sub-prefixes
        cname_records = await self._query_cnames(domain)
        result.cname_records = cname_records
        discovered.update(cname_records)

        # Compile additional domains (those not under the target domain)
        all_names = sorted(discovered)
        subdomains = [
            name for name in all_names
            if name.endswith(f".{domain}") or name == domain
        ]
        additional = [
            name for name in all_names
            if not name.endswith(f".{domain}") and name != domain
        ]

        result.subdomains = subdomains
        result.additional_domains = additional

        self.stats["domains_found"] = len(discovered)

        return all_names

    # ------------------------------------------------------------------
    # AXFR zone transfer
    # ------------------------------------------------------------------

    async def _try_axfr(self, domain: str) -> list[str]:
        """Attempt AXFR zone transfer against each NS for *domain*.

        Most authoritative name servers reject AXFR from untrusted sources,
        but misconfigured ones may allow it and leak all records.
        """
        names: list[str] = []

        # First get NS records
        ns_servers = await self._query_ns(domain)
        if not ns_servers:
            return names

        for ns in ns_servers:
            try:
                # aiodns does not support AXFR directly; we use a subprocess
                # call to ``dig`` as a fallback.
                proc = await asyncio.create_subprocess_exec(
                    "dig", f"@{ns}", domain, "AXFR", "+short", "+time=3",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=10
                )
                output = stdout.decode(errors="replace")

                # Extract domain names from the AXFR output
                for match in _DOMAIN_RE.finditer(output):
                    name = match.group(0).rstrip(".")
                    if name:
                        names.append(name)

                self.stats["queries"] += 1
                if names:
                    self.stats["successful"] += 1
                    if not self.config.quiet:
                        print(
                            f"[dns_enum] AXFR success on {ns} for {domain} "
                            f"({len(names)} records)"
                        )

            except FileNotFoundError:
                # dig not installed -- skip AXFR
                break
            except (asyncio.TimeoutError, Exception):
                self.stats["failed"] += 1
                continue

        return list(set(names))

    # ------------------------------------------------------------------
    # Standard record queries
    # ------------------------------------------------------------------

    async def _query_ns(self, domain: str) -> list[str]:
        self.stats["queries"] += 1
        try:
            answers = await self._resolver.query(domain, "NS")
            self.stats["successful"] += 1
            return [r.host.rstrip(".") for r in answers]
        except Exception:
            self.stats["failed"] += 1
            return []

    async def _query_mx(self, domain: str) -> list[str]:
        self.stats["queries"] += 1
        try:
            answers = await self._resolver.query(domain, "MX")
            self.stats["successful"] += 1
            return [r.host.rstrip(".") for r in answers]
        except Exception:
            self.stats["failed"] += 1
            return []

    async def _query_txt(self, domain: str) -> list[str]:
        self.stats["queries"] += 1
        try:
            answers = await self._resolver.query(domain, "TXT")
            self.stats["successful"] += 1
            records: list[str] = []
            for r in answers:
                text = r.text if hasattr(r, "text") else str(r)
                records.append(text)
            return records
        except Exception:
            self.stats["failed"] += 1
            return []

    async def _query_srv(self, domain: str) -> list[dict]:
        results: list[dict] = []

        tasks = []
        for prefix in _SRV_PREFIXES:
            srv_name = f"{prefix}.{domain}"
            tasks.append(self._query_single_srv(srv_name))

        answers = await asyncio.gather(*tasks, return_exceptions=True)
        for answer in answers:
            if isinstance(answer, list):
                results.extend(answer)

        return results

    async def _query_single_srv(self, srv_name: str) -> list[dict]:
        self.stats["queries"] += 1
        try:
            answers = await self._resolver.query(srv_name, "SRV")
            self.stats["successful"] += 1
            return [
                {
                    "name": srv_name,
                    "host": r.host.rstrip("."),
                    "port": r.port,
                    "priority": r.priority,
                    "weight": r.weight,
                }
                for r in answers
            ]
        except Exception:
            self.stats["failed"] += 1
            return []

    async def _query_cnames(self, domain: str) -> list[str]:
        """Query CNAME for a set of common sub-prefixes."""
        prefixes = [
            "www", "mail", "ftp", "webmail", "smtp", "pop", "imap",
            "admin", "api", "dev", "staging", "test", "cdn",
        ]
        cnames: list[str] = []
        tasks = [
            self._query_single_cname(f"{p}.{domain}") for p in prefixes
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, str) and result:
                cnames.append(result)
        return cnames

    async def _query_single_cname(self, fqdn: str) -> str:
        self.stats["queries"] += 1
        try:
            answer = await self._resolver.query(fqdn, "CNAME")
            self.stats["successful"] += 1
            if hasattr(answer, "cname"):
                return answer.cname.rstrip(".")
            return ""
        except Exception:
            self.stats["failed"] += 1
            return ""

    # ------------------------------------------------------------------
    # SPF / DKIM / DMARC parsing
    # ------------------------------------------------------------------

    def _parse_spf(self, txt_records: list[str]) -> list[str]:
        """Extract ``include:`` and ``redirect=`` domains from SPF TXT."""
        domains: list[str] = []
        for txt in txt_records:
            if "v=spf1" not in txt.lower():
                continue
            for match in _SPF_INCLUDE_RE.finditer(txt):
                domains.append(match.group(1).rstrip("."))
            for match in _SPF_REDIRECT_RE.finditer(txt):
                domains.append(match.group(1).rstrip("."))
        return list(set(domains))

    async def _parse_dmarc(self, domain: str) -> list[str]:
        """Query ``_dmarc.<domain>`` TXT and extract ``rua``/``ruf`` domains."""
        domains: list[str] = []
        dmarc_name = f"_dmarc.{domain}"
        txt_records = await self._query_txt(dmarc_name)

        for txt in txt_records:
            if "v=dmarc1" not in txt.lower():
                continue
            # Extract mailto: URIs from rua= and ruf= tags
            for tag in ("rua", "ruf"):
                pattern = re.compile(rf"{tag}=([^;]+)", re.IGNORECASE)
                match = pattern.search(txt)
                if match:
                    uris = match.group(1)
                    # mailto:user@domain
                    for email_match in re.finditer(r"mailto:(\S+?)(?:,|$)", uris):
                        email = email_match.group(1).strip()
                        if "@" in email:
                            domains.append(email.split("@")[1].rstrip("."))

        return list(set(domains))

    async def _parse_dkim(self, domain: str) -> list[str]:
        """Try common DKIM selector names and extract domains."""
        domains: list[str] = []
        selectors = [
            "default", "google", "selector1", "selector2",
            "k1", "k2", "mail", "dkim", "s1", "s2",
        ]

        tasks = []
        for sel in selectors:
            dkim_name = f"{sel}._domainkey.{domain}"
            tasks.append(self._query_txt(dkim_name))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if not isinstance(result, list):
                continue
            for txt in result:
                # Look for p= (public key exists) -- confirms DKIM
                if "p=" in txt:
                    # Extract any domains referenced
                    for match in _DOMAIN_RE.finditer(txt):
                        name = match.group(0).rstrip(".")
                        if name and name != domain:
                            domains.append(name)

        return list(set(domains))

    def get_stats(self) -> dict:
        return dict(self.stats)
