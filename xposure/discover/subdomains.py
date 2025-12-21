"""Subdomain discovery for X-POSURE."""

import asyncio
import re
from typing import AsyncGenerator, Set

from .base import BaseDiscoverer


class SubdomainDiscoverer(BaseDiscoverer):
    """Discover subdomains via certificate transparency logs and DNS."""

    def __init__(self, config):
        """Initialize subdomain discoverer."""
        super().__init__(config)
        self.seen: Set[str] = set()

    async def discover(self) -> AsyncGenerator[dict, None]:
        """
        Discover subdomains.

        Yields:
            dict: Result with type='subdomain', url, metadata
        """
        target = self.config.target

        # 1. Certificate Transparency (crt.sh)
        async for result in self._discover_crtsh(target):
            yield result

        # 2. Common subdomain wordlist
        async for result in self._discover_common(target):
            yield result

    async def _discover_crtsh(self, domain: str) -> AsyncGenerator[dict, None]:
        """
        Query crt.sh for certificate transparency logs.

        Args:
            domain: Target domain

        Yields:
            Subdomain results
        """
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            data = await self.fetch_json(url)

            if not data:
                return

            # Extract unique subdomains
            for entry in data:
                name_value = entry.get('name_value', '')
                # Handle multiple names (newline separated)
                for subdomain in name_value.split('\n'):
                    subdomain = subdomain.strip().lower()

                    # Remove wildcards
                    subdomain = subdomain.replace('*.', '')

                    # Skip if already seen or invalid
                    if not subdomain or subdomain in self.seen:
                        continue

                    # Must end with target domain
                    if not subdomain.endswith(domain):
                        continue

                    self.seen.add(subdomain)

                    yield {
                        'type': 'subdomain',
                        'url': f"https://{subdomain}",
                        'subdomain': subdomain,
                        'metadata': {
                            'source': 'crt.sh',
                            'issuer': entry.get('issuer_name', ''),
                        }
                    }

                    await self.rate_limit()

        except Exception as e:
            if self.config.verbose:
                print(f"[discover] crt.sh error: {e}")

    async def _discover_common(self, domain: str) -> AsyncGenerator[dict, None]:
        """
        Try common subdomain names.

        Args:
            domain: Target domain

        Yields:
            Subdomain results
        """
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1',
            'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
            'dev', 'staging', 'test', 'demo', 'beta', 'admin', 'api', 'app',
            'mobile', 'static', 'cdn', 'assets', 'media', 'img', 'images',
            'vpn', 'portal', 'ssh', 'git', 'gitlab', 'github', 'bitbucket',
            'jenkins', 'ci', 'dashboard', 'monitoring', 'metrics', 'grafana',
            'kibana', 'elastic', 'logs', 'sentry', 'status', 'support',
        ]

        for subdomain_prefix in common_subdomains:
            subdomain = f"{subdomain_prefix}.{domain}"

            if subdomain in self.seen:
                continue

            # Quick DNS check (A or CNAME record)
            if await self._dns_exists(subdomain):
                self.seen.add(subdomain)

                yield {
                    'type': 'subdomain',
                    'url': f"https://{subdomain}",
                    'subdomain': subdomain,
                    'metadata': {
                        'source': 'dns_bruteforce',
                    }
                }

            await self.rate_limit()

    async def _dns_exists(self, domain: str) -> bool:
        """
        Check if domain has DNS records.

        Args:
            domain: Domain to check

        Returns:
            True if DNS record exists
        """
        try:
            import socket

            # Run in executor to avoid blocking
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyname, domain),
                timeout=self.config.dns_timeout
            )
            return result is not None
        except (socket.gaierror, asyncio.TimeoutError):
            return False
        except Exception:
            return False
