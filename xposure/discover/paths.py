"""Path and endpoint discovery for X-POSURE."""

import asyncio
import re
import secrets
from typing import AsyncGenerator, Set
from urllib.parse import urljoin, urlparse

import aiohttp

from .base import BaseDiscoverer


class PathDiscoverer(BaseDiscoverer):
    """Discover interesting paths and endpoints."""

    # Circuit breaker: skip remaining paths after this many consecutive failures
    CIRCUIT_BREAKER_THRESHOLD = 5

    def __init__(self, config):
        """Initialize path discoverer."""
        super().__init__(config)
        self.seen: Set[str] = set()
        self._consecutive_failures = 0
        self._is_wildcard = False

    async def _detect_wildcard(self, base_url: str) -> bool:
        """Check if the server responds 200/403 for random non-existent paths."""
        canary = f"/{secrets.token_hex(16)}-{secrets.token_hex(8)}.html"
        canary_url = urljoin(base_url, canary)
        result = await self._path_exists(canary_url)
        # Reset failure counter since this was a test probe
        self._consecutive_failures = 0
        return result

    async def discover(self) -> AsyncGenerator[dict, None]:
        """
        Discover paths and endpoints.

        Yields:
            dict: Result with type='path', url, metadata
        """
        target = self.config.target
        base_url = f"https://{target}"

        # Wildcard detection: if a random path returns 200/403, skip path brute-force
        self._is_wildcard = await self._detect_wildcard(base_url)
        if self._is_wildcard:
            if not self.config.quiet:
                print(f"[discover] {target} returns 200/403 for all paths (wildcard/catch-all), "
                      f"skipping path brute-force")
            # Still parse robots.txt and sitemap (those are content-based, not status-based)
            async for result in self._parse_robots(base_url):
                yield result
            async for result in self._parse_sitemap(base_url):
                yield result
            return

        # Load paths wordlist (falls back to hardcoded if no file)
        interesting_paths = self.config.get_wordlist('paths')

        # Fallback to basic list if wordlist not available
        if not interesting_paths:
            interesting_paths = [
                # Config/secrets
                '/.env',
                '/.env.local',
                '/.env.production',
                '/.env.development',
                '/config.json',
                '/config.yml',
                '/config.yaml',
                '/secrets.json',
                '/credentials.json',

                # Version control
                '/.git/config',
                '/.git/HEAD',
                '/.gitignore',
                '/.gitlab-ci.yml',
                '/.github/workflows',

                # Documentation
                '/robots.txt',
                '/sitemap.xml',
                '/sitemap_index.xml',
                '/humans.txt',
                '/.well-known/security.txt',

                # API endpoints
                '/api',
                '/api/v1',
                '/api/v2',
                '/graphql',
                '/swagger.json',
                '/swagger.yml',
                '/openapi.json',
                '/api-docs',
                '/docs',

                # Admin/debug
                '/admin',
                '/dashboard',
                '/debug',
                '/phpinfo.php',
                '/status',
                '/health',
                '/metrics',

                # Package managers
                '/package.json',
                '/composer.json',
                '/requirements.txt',
                '/Gemfile',
                '/yarn.lock',
                '/package-lock.json',

                # Backups
                '/backup',
                '/backup.sql',
                '/dump.sql',
                '/database.sql',
                '/.bak',

                # Cloud configs
                '/.aws/credentials',
                '/.azure/credentials',
                '/gcp-key.json',
            ]

        if not self.config.quiet:
            print(f"[discover] Testing {len(interesting_paths)} paths...")

        for path in interesting_paths:
            # Circuit breaker: if target is unreachable, stop wasting time
            if self._consecutive_failures >= self.CIRCUIT_BREAKER_THRESHOLD:
                if not self.config.quiet:
                    print(f"[discover] target unreachable after {self._consecutive_failures} "
                          f"consecutive failures, skipping remaining paths")
                break

            url = urljoin(base_url, path)

            if url in self.seen:
                continue

            # Check if path exists
            if await self._path_exists(url):
                self.seen.add(url)

                yield {
                    'type': 'path',
                    'url': url,
                    'path': path,
                    'metadata': {
                        'source': 'common_paths',
                    }
                }

            await self.rate_limit()

        # Parse robots.txt for additional paths
        async for result in self._parse_robots(base_url):
            yield result

        # Parse sitemap for URLs
        async for result in self._parse_sitemap(base_url):
            yield result

    async def _path_exists(self, url: str) -> bool:
        """
        Check if a path exists.

        Args:
            url: URL to check

        Returns:
            True if path exists (200 or 403)
        """
        if not self.session:
            return False

        self.stats.requests_made += 1

        try:
            async with self.session.head(
                url,
                allow_redirects=False,
                timeout=self.session.timeout
            ) as response:
                self._consecutive_failures = 0  # reset on any HTTP response
                # 200 = exists, 403 = exists but forbidden
                if response.status in (200, 403):
                    self.stats.requests_successful += 1
                    return True
                return False

        except asyncio.TimeoutError:
            self._consecutive_failures += 1
            self.stats.timeouts += 1
            self.stats.requests_failed += 1
            return False

        except aiohttp.ClientConnectorError as e:
            self._consecutive_failures += 1
            error_type = self._classify_error(e)
            self._record_error(error_type, url, e)
            return False

        except Exception as e:
            self._consecutive_failures += 1
            self.stats.other_errors += 1
            self.stats.requests_failed += 1
            if self.config.verbose:
                print(f"[discover] Error checking path {url}: {e}")
            return False

    async def _parse_robots(self, base_url: str) -> AsyncGenerator[dict, None]:
        """
        Parse robots.txt for disallowed paths.

        Args:
            base_url: Base URL of target

        Yields:
            Path results from robots.txt
        """
        robots_url = urljoin(base_url, '/robots.txt')
        content = await self.fetch(robots_url)

        if not content:
            return

        # Extract Disallow and Allow paths
        pattern = r'^(?:Disallow|Allow):\s*(.+)$'

        for line in content.split('\n'):
            match = re.match(pattern, line.strip(), re.IGNORECASE)
            if match:
                path = match.group(1).strip()

                # Skip wildcards and empty
                if not path or path == '/' or '*' in path:
                    continue

                url = urljoin(base_url, path)

                if url in self.seen:
                    continue

                self.seen.add(url)

                yield {
                    'type': 'path',
                    'url': url,
                    'path': path,
                    'metadata': {
                        'source': 'robots.txt',
                    }
                }

    async def _parse_sitemap(self, base_url: str) -> AsyncGenerator[dict, None]:
        """
        Parse sitemap.xml for URLs.

        Args:
            base_url: Base URL of target

        Yields:
            URL results from sitemap
        """
        sitemap_url = urljoin(base_url, '/sitemap.xml')
        content = await self.fetch(sitemap_url)

        if not content:
            return

        # Extract <loc> tags
        pattern = r'<loc>([^<]+)</loc>'

        for match in re.finditer(pattern, content):
            url = match.group(1).strip()

            if url in self.seen:
                continue

            self.seen.add(url)

            yield {
                'type': 'path',
                'url': url,
                'path': urlparse(url).path,
                'metadata': {
                    'source': 'sitemap.xml',
                }
            }

            await self.rate_limit()
