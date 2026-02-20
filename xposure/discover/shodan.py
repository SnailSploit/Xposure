"""Shodan integration — map IPs to infrastructure."""

import asyncio
from dataclasses import dataclass, field
from typing import Optional

import aiohttp

from ..config import Config


@dataclass
class ShodanHostInfo:
    """Shodan data for a single IP."""
    ip: str
    hostnames: list[str] = field(default_factory=list)
    os: Optional[str] = None
    organization: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    ports: list[int] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    last_update: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostnames": self.hostnames,
            "os": self.os,
            "organization": self.organization,
            "isp": self.isp,
            "asn": self.asn,
            "country": self.country,
            "city": self.city,
            "ports": self.ports,
            "services": self.services,
            "vulns": self.vulns,
            "tags": self.tags,
            "last_update": self.last_update,
            "error": self.error,
        }

    @property
    def has_critical_services(self) -> bool:
        """Check if host exposes risky services."""
        risky_ports = {21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 27017}
        return bool(set(self.ports) & risky_ports)


class ShodanMapper:
    """Query Shodan API for infrastructure mapping."""

    BASE_URL = "https://api.shodan.io"

    def __init__(self, config: Config, api_key: str, rate_limit: float = 1.0):
        """
        Args:
            config: Global config.
            api_key: Shodan API key.
            rate_limit: Seconds between requests (free tier = 1/s).
        """
        self.config = config
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.stats = {"queried": 0, "found": 0, "errors": 0, "vulns_total": 0}

    async def map_ips(self, ips: list[str]) -> dict[str, ShodanHostInfo]:
        """Query Shodan for each IP.

        Args:
            ips: List of IP addresses.

        Returns:
            Map of IP -> ShodanHostInfo.
        """
        results: dict[str, ShodanHostInfo] = {}

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
        ) as session:
            for ip in ips:
                if not self.config.quiet:
                    print(f"[shodan] querying {ip}...")

                info = await self._query_host(session, ip)
                results[ip] = info

                self.stats["queried"] += 1
                if info.error:
                    self.stats["errors"] += 1
                else:
                    self.stats["found"] += 1
                    self.stats["vulns_total"] += len(info.vulns)

                # Rate limit between requests
                await asyncio.sleep(self.rate_limit)

        return results

    async def _query_host(self, session: aiohttp.ClientSession, ip: str) -> ShodanHostInfo:
        """Query Shodan /shodan/host/{ip} endpoint."""
        url = f"{self.BASE_URL}/shodan/host/{ip}?key={self.api_key}"

        try:
            async with session.get(url) as response:
                if response.status == 404:
                    return ShodanHostInfo(ip=ip, error="not_found")

                if response.status == 401:
                    return ShodanHostInfo(ip=ip, error="invalid_api_key")

                if response.status == 429:
                    return ShodanHostInfo(ip=ip, error="rate_limited")

                if response.status != 200:
                    return ShodanHostInfo(
                        ip=ip, error=f"http_{response.status}"
                    )

                data = await response.json()
                return self._parse_host(ip, data)

        except Exception as e:
            return ShodanHostInfo(ip=ip, error=str(e))

    def _parse_host(self, ip: str, data: dict) -> ShodanHostInfo:
        """Parse Shodan host response into our model."""
        services = []
        for item in data.get("data", []):
            svc = {
                "port": item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product": item.get("product"),
                "version": item.get("version"),
                "banner": (item.get("data", "") or "")[:500],
            }
            # Check for HTTP info
            if "http" in item:
                svc["http_title"] = item["http"].get("title")
                svc["http_server"] = item["http"].get("server")
            # Check for SSL info
            if "ssl" in item:
                ssl_info = item["ssl"]
                svc["ssl_issuer"] = ssl_info.get("cert", {}).get("issuer", {}).get("O")
                svc["ssl_expires"] = ssl_info.get("cert", {}).get("expires")
            services.append(svc)

        return ShodanHostInfo(
            ip=ip,
            hostnames=data.get("hostnames", []),
            os=data.get("os"),
            organization=data.get("org"),
            isp=data.get("isp"),
            asn=data.get("asn"),
            country=data.get("country_name"),
            city=data.get("city"),
            ports=sorted(data.get("ports", [])),
            services=services,
            vulns=sorted(data.get("vulns", [])),
            tags=data.get("tags", []),
            last_update=data.get("last_update"),
        )

    def get_stats(self) -> dict:
        return dict(self.stats)
