"""TLS certificate harvesting for X-POSURE v5.0.

Connects to TLS-enabled services, extracts the server certificate, and
returns structured data including subject CN, SANs, issuer, expiry, and
key information.  Useful for discovering additional hostnames and
detecting misconfigured or expired certificates.
"""

import asyncio
import ssl
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from ..config import Config


@dataclass
class CertInfo:
    """Parsed TLS certificate information."""

    host: str
    port: int
    subject_cn: str = ""
    sans: list[str] = field(default_factory=list)
    issuer: str = ""
    issuer_org: str = ""
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    expired: bool = False
    key_type: str = ""
    key_size: int = 0
    serial_number: str = ""
    version: int = 0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "subject_cn": self.subject_cn,
            "sans": self.sans,
            "issuer": self.issuer,
            "issuer_org": self.issuer_org,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "expired": self.expired,
            "key_type": self.key_type,
            "key_size": self.key_size,
            "serial_number": self.serial_number,
            "version": self.version,
            "error": self.error,
        }

    @property
    def all_names(self) -> list[str]:
        """Return subject CN plus all SANs as a deduplicated list."""
        names: set[str] = set()
        if self.subject_cn:
            names.add(self.subject_cn)
        names.update(self.sans)
        return sorted(names)


class TLSHarvester:
    """Harvest TLS certificates from remote hosts.

    Usage::

        harvester = TLSHarvester(config)
        info = await harvester.harvest("example.com", 443)
        print(info.subject_cn, info.sans)
    """

    # Connection timeout in seconds
    CONNECT_TIMEOUT: float = 5.0

    def __init__(self, config: Config, connect_timeout: float = 5.0):
        self.config = config
        self.CONNECT_TIMEOUT = connect_timeout
        self.stats = {
            "hosts_probed": 0,
            "certs_collected": 0,
            "errors": 0,
        }

    async def harvest(self, host: str, port: int = 443) -> dict:
        """Connect to *host:port* via TLS and extract the certificate.

        Args:
            host: Hostname or IP address.
            port: TLS port (default 443).

        Returns:
            A :class:`CertInfo` dict with parsed certificate fields,
            or a dict with an ``error`` key if the connection failed.
        """
        self.stats["hosts_probed"] += 1

        try:
            cert_info = await asyncio.wait_for(
                self._grab_cert(host, port),
                timeout=self.CONNECT_TIMEOUT,
            )
            self.stats["certs_collected"] += 1
            return cert_info.to_dict()

        except asyncio.TimeoutError:
            self.stats["errors"] += 1
            return CertInfo(
                host=host, port=port, error="connection_timeout"
            ).to_dict()
        except Exception as exc:
            self.stats["errors"] += 1
            return CertInfo(
                host=host, port=port, error=str(exc)[:300]
            ).to_dict()

    async def harvest_many(
        self, targets: list[tuple[str, int]], max_concurrent: int = 20
    ) -> list[dict]:
        """Harvest certificates from multiple hosts concurrently.

        Args:
            targets: List of ``(host, port)`` tuples.
            max_concurrent: Maximum number of parallel connections.

        Returns:
            List of :class:`CertInfo` dicts.
        """
        sem = asyncio.Semaphore(max_concurrent)

        async def _limited(host: str, port: int) -> dict:
            async with sem:
                return await self.harvest(host, port)

        tasks = [_limited(h, p) for h, p in targets]
        return list(await asyncio.gather(*tasks, return_exceptions=False))

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _grab_cert(self, host: str, port: int) -> CertInfo:
        """Low-level TLS connect and cert extraction."""

        # Build an SSL context that does NOT verify -- we just want the cert
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.open_connection(
            host, port, ssl=ctx
        )

        try:
            # Retrieve the peer certificate from the transport
            transport = writer.transport
            ssl_object = transport.get_extra_info("ssl_object")

            if ssl_object is None:
                return CertInfo(host=host, port=port, error="no_ssl_object")

            peer_cert = ssl_object.getpeercert(binary_form=False)
            # binary_form=False requires CERT_REQUIRED normally but some
            # implementations still return it.  Fall back to binary parse.
            if peer_cert is None:
                peer_cert_der = ssl_object.getpeercert(binary_form=True)
                if peer_cert_der is None:
                    return CertInfo(
                        host=host, port=port, error="no_peer_cert"
                    )
                return self._parse_der_cert(host, port, peer_cert_der, ssl_object)

            return self._parse_dict_cert(host, port, peer_cert, ssl_object)

        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    def _parse_dict_cert(
        self, host: str, port: int, cert: dict, ssl_object
    ) -> CertInfo:
        """Parse a certificate returned as a Python dict (getpeercert)."""
        info = CertInfo(host=host, port=port)

        # Subject CN
        subject = cert.get("subject", ())
        for rdn in subject:
            for attr_type, attr_value in rdn:
                if attr_type == "commonName":
                    info.subject_cn = attr_value

        # SANs
        san_entries = cert.get("subjectAltName", ())
        for san_type, san_value in san_entries:
            if san_type in ("DNS", "IP Address"):
                info.sans.append(san_value)

        # Issuer
        issuer = cert.get("issuer", ())
        issuer_parts: list[str] = []
        for rdn in issuer:
            for attr_type, attr_value in rdn:
                if attr_type == "organizationName":
                    info.issuer_org = attr_value
                issuer_parts.append(f"{attr_type}={attr_value}")
        info.issuer = ", ".join(issuer_parts)

        # Validity dates
        info.not_before = cert.get("notBefore")
        info.not_after = cert.get("notAfter")

        # Check expiry
        if info.not_after:
            try:
                # Python ssl date format: 'Mon DD HH:MM:SS YYYY GMT'
                expiry = datetime.strptime(
                    info.not_after, "%b %d %H:%M:%S %Y %Z"
                )
                info.expired = expiry < datetime.utcnow()
            except (ValueError, TypeError):
                pass

        # Serial number
        info.serial_number = str(cert.get("serialNumber", ""))

        # Version
        info.version = cert.get("version", 0)

        # Key info from the ssl_object cipher
        try:
            cipher = ssl_object.cipher()
            if cipher:
                info.key_type = cipher[0]
                info.key_size = cipher[2] if len(cipher) > 2 else 0
        except Exception:
            pass

        return info

    def _parse_der_cert(
        self, host: str, port: int, der_bytes: bytes, ssl_object
    ) -> CertInfo:
        """Minimal parse when only DER binary form is available.

        We decode what we can via :func:`ssl.DER_cert_to_PEM_cert` and
        the ssl_object metadata.
        """
        info = CertInfo(host=host, port=port)

        try:
            pem = ssl.DER_cert_to_PEM_cert(der_bytes)
            info.subject_cn = f"(DER cert, {len(der_bytes)} bytes)"
        except Exception:
            info.subject_cn = "(unparseable DER cert)"

        # Key info from cipher
        try:
            cipher = ssl_object.cipher()
            if cipher:
                info.key_type = cipher[0]
                info.key_size = cipher[2] if len(cipher) > 2 else 0
        except Exception:
            pass

        return info

    def get_stats(self) -> dict:
        return dict(self.stats)
