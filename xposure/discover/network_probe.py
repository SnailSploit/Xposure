"""Network probing for X-POSURE v5.0.

TCP connect-scans common service ports and probes HTTP endpoints to
discover internal services that may leak configuration or secrets.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Optional

import aiohttp

from ..config import Config


@dataclass
class ServiceInfo:
    """Information about a discovered network service."""

    ip: str
    port: int
    service_name: str = ""
    banner: str = ""
    headers: dict = field(default_factory=dict)
    http_status: Optional[int] = None
    http_body_preview: str = ""

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "port": self.port,
            "service_name": self.service_name,
            "banner": self.banner,
            "headers": self.headers,
            "http_status": self.http_status,
            "http_body_preview": self.http_body_preview,
        }


# Well-known port -> service name mapping
_PORT_SERVICE_MAP: dict[int, str] = {
    80: "http",
    443: "https",
    2379: "etcd",
    3000: "grafana/dev-server",
    3306: "mysql",
    4443: "https-alt",
    5432: "postgresql",
    5672: "rabbitmq-amqp",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    9090: "prometheus",
    9200: "elasticsearch-http",
    9300: "elasticsearch-transport",
    15672: "rabbitmq-mgmt",
    27017: "mongodb",
}

# Default ports to scan
DEFAULT_PORTS: list[int] = sorted(_PORT_SERVICE_MAP.keys())

# HTTP paths to probe on discovered HTTP services
_HTTP_PROBE_PATHS: list[str] = [
    "/healthz",
    "/metrics",
    "/debug/vars",
    "/.env",
    "/swagger.json",
]


class NetworkProber:
    """Probe internal network hosts for open services.

    Usage::

        prober = NetworkProber(config)
        results = await prober.probe(["10.0.0.1", "10.0.0.2"])
        for svc in results:
            print(svc.ip, svc.port, svc.service_name)
    """

    # TCP connect timeout per port
    CONNECT_TIMEOUT: float = 3.0

    # HTTP probe timeout
    HTTP_TIMEOUT: float = 3.0

    # Maximum concurrent probes
    MAX_CONCURRENT: int = 100

    def __init__(
        self,
        config: Config,
        ports: Optional[list[int]] = None,
        connect_timeout: float = 3.0,
        max_concurrent: int = 100,
    ):
        self.config = config
        self.ports = ports or DEFAULT_PORTS
        self.CONNECT_TIMEOUT = connect_timeout
        self.MAX_CONCURRENT = max_concurrent
        self._semaphore = asyncio.Semaphore(self.MAX_CONCURRENT)
        self.stats = {
            "hosts_probed": 0,
            "ports_scanned": 0,
            "ports_open": 0,
            "http_probes": 0,
            "errors": 0,
        }

    async def probe(self, ips: list[str]) -> list[dict]:
        """Probe a list of IP addresses for open services.

        Args:
            ips: IP addresses (or hostnames) to probe.

        Returns:
            List of :class:`ServiceInfo` dicts for every open port found.
        """
        all_results: list[ServiceInfo] = []

        # Phase 1 -- TCP connect scan on all ports
        scan_tasks = []
        for ip in ips:
            self.stats["hosts_probed"] += 1
            for port in self.ports:
                scan_tasks.append(self._tcp_probe(ip, port))

        scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)

        for result in scan_results:
            if isinstance(result, ServiceInfo):
                all_results.append(result)

        # Phase 2 -- HTTP probes on HTTP-capable ports
        http_ports = {80, 443, 3000, 4443, 8080, 8443, 9090, 9200, 15672}
        http_services = [
            svc for svc in all_results if svc.port in http_ports
        ]

        if http_services:
            http_tasks = []
            for svc in http_services:
                http_tasks.append(self._http_probe(svc))
            http_results = await asyncio.gather(
                *http_tasks, return_exceptions=True
            )
            for result in http_results:
                if isinstance(result, list):
                    all_results.extend(result)

        return [svc.to_dict() for svc in all_results]

    async def _tcp_probe(self, ip: str, port: int) -> Optional[ServiceInfo]:
        """Attempt a TCP connect to *ip:port*.

        Returns a :class:`ServiceInfo` on success, ``None`` on failure.
        """
        async with self._semaphore:
            self.stats["ports_scanned"] += 1
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.CONNECT_TIMEOUT,
                )

                # Try to grab a banner (non-HTTP services)
                banner = ""
                try:
                    # Some services send a banner immediately
                    data = await asyncio.wait_for(
                        reader.read(1024), timeout=1.0
                    )
                    banner = data.decode(errors="replace").strip()[:512]
                except (asyncio.TimeoutError, Exception):
                    pass

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                self.stats["ports_open"] += 1

                service_name = _PORT_SERVICE_MAP.get(port, f"unknown-{port}")

                return ServiceInfo(
                    ip=ip,
                    port=port,
                    service_name=service_name,
                    banner=banner,
                )

            except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
                return None
            except Exception:
                self.stats["errors"] += 1
                return None

    async def _http_probe(self, svc: ServiceInfo) -> list[ServiceInfo]:
        """Probe HTTP endpoints on a discovered open port.

        Returns a list of :class:`ServiceInfo` for each endpoint that
        responds with useful data.
        """
        results: list[ServiceInfo] = []
        scheme = "https" if svc.port in (443, 4443, 8443) else "http"
        base = f"{scheme}://{svc.ip}:{svc.port}"

        timeout = aiohttp.ClientTimeout(total=self.HTTP_TIMEOUT)

        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(
                timeout=timeout, connector=connector
            ) as session:
                for path in _HTTP_PROBE_PATHS:
                    url = f"{base}{path}"
                    self.stats["http_probes"] += 1

                    try:
                        async with session.get(url) as resp:
                            headers = dict(resp.headers)
                            body = ""
                            try:
                                body = await resp.text()
                                body = body[:2048]
                            except Exception:
                                pass

                            results.append(
                                ServiceInfo(
                                    ip=svc.ip,
                                    port=svc.port,
                                    service_name=f"{svc.service_name}{path}",
                                    headers=headers,
                                    http_status=resp.status,
                                    http_body_preview=body,
                                )
                            )
                    except (asyncio.TimeoutError, aiohttp.ClientError):
                        continue
                    except Exception:
                        self.stats["errors"] += 1
                        continue
        except Exception:
            self.stats["errors"] += 1

        return results

    def get_stats(self) -> dict:
        return dict(self.stats)
