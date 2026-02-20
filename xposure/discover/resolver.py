"""Async DNS resolver — map discovered domains to IPs."""

import asyncio
import socket
from dataclasses import dataclass, field
from typing import Optional

import aiodns

from ..config import Config


@dataclass
class DNSRecord:
    """A single DNS resolution result."""
    domain: str
    record_type: str  # A, AAAA, CNAME, MX, TXT
    value: str
    ttl: int = 0


@dataclass
class ResolvedHost:
    """Full resolution for a single domain."""
    domain: str
    ips: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    reverse_dns: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "ips": self.ips,
            "ipv6": self.ipv6,
            "cnames": self.cnames,
            "mx_records": self.mx_records,
            "txt_records": self.txt_records,
            "reverse_dns": self.reverse_dns,
            "error": self.error,
        }


class BulkResolver:
    """Async bulk DNS resolver using aiodns."""

    def __init__(self, config: Config, max_concurrent: int = 20):
        self.config = config
        self.max_concurrent = max_concurrent
        self._resolver: Optional[aiodns.DNSResolver] = None
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self.stats = {"resolved": 0, "failed": 0, "unique_ips": 0}

    async def resolve_domains(self, domains: list[str]) -> dict[str, ResolvedHost]:
        """Resolve a list of domains concurrently.

        Args:
            domains: List of domain names (not full URLs).

        Returns:
            Map of domain -> ResolvedHost.
        """
        self._resolver = aiodns.DNSResolver(
            timeout=self.config.dns_timeout,
        )

        unique_domains = list(set(domains))
        tasks = [self._resolve_one(d) for d in unique_domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        resolved_map: dict[str, ResolvedHost] = {}
        all_ips: set[str] = set()

        for domain, result in zip(unique_domains, results):
            if isinstance(result, Exception):
                host = ResolvedHost(domain=domain, error=str(result))
                self.stats["failed"] += 1
            else:
                host = result
                self.stats["resolved"] += 1
                all_ips.update(host.ips)
                all_ips.update(host.ipv6)
            resolved_map[domain] = host

        self.stats["unique_ips"] = len(all_ips)
        return resolved_map

    async def _resolve_one(self, domain: str) -> ResolvedHost:
        """Resolve a single domain for all record types."""
        host = ResolvedHost(domain=domain)

        async with self._semaphore:
            # A records
            try:
                answers = await self._resolver.query(domain, "A")
                host.ips = [r.host for r in answers]
            except Exception:
                pass

            # AAAA records
            try:
                answers = await self._resolver.query(domain, "AAAA")
                host.ipv6 = [r.host for r in answers]
            except Exception:
                pass

            # CNAME records
            try:
                answer = await self._resolver.query(domain, "CNAME")
                host.cnames = [answer.cname] if hasattr(answer, 'cname') else []
            except Exception:
                pass

            # MX records
            try:
                answers = await self._resolver.query(domain, "MX")
                host.mx_records = [r.host for r in answers]
            except Exception:
                pass

            # TXT records
            try:
                answers = await self._resolver.query(domain, "TXT")
                host.txt_records = [r.text for r in answers]
            except Exception:
                pass

            # Reverse DNS for first IP
            if host.ips:
                try:
                    result = await asyncio.get_event_loop().run_in_executor(
                        None, socket.gethostbyaddr, host.ips[0]
                    )
                    host.reverse_dns = result[0]
                except Exception:
                    pass

        return host

    def get_unique_ips(self, resolved: dict[str, ResolvedHost]) -> list[str]:
        """Extract unique IPs from resolution results."""
        ips: set[str] = set()
        for host in resolved.values():
            ips.update(host.ips)
        return sorted(ips)

    def get_stats(self) -> dict:
        return dict(self.stats)
