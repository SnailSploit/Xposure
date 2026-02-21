"""Base discovery class for X-POSURE."""

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import AsyncGenerator, Optional

import aiohttp

from ..config import Config


@dataclass
class DiscoveryStats:
    """Track discovery statistics and errors."""

    requests_made: int = 0
    requests_successful: int = 0
    requests_failed: int = 0
    timeouts: int = 0
    connection_errors: int = 0
    dns_errors: int = 0
    ssl_errors: int = 0
    rate_limited: int = 0
    other_errors: int = 0
    retries: int = 0
    errors: list = field(default_factory=list)

    def record_error(self, error_type: str, url: str, error: str):
        """Record an error for later analysis."""
        self.errors.append({
            'type': error_type,
            'url': url,
            'error': str(error)[:200],  # Truncate long errors
        })
        # Keep only last 100 errors to prevent memory bloat
        if len(self.errors) > 100:
            self.errors = self.errors[-100:]


class BaseDiscoverer(ABC):
    """Base class for all discovery modules."""

    # Default retry configuration
    MAX_RETRIES = 3
    RETRY_BACKOFF = [1, 2, 4]  # Exponential backoff delays

    def __init__(self, config: Config):
        """
        Initialize discoverer.

        Args:
            config: Global configuration
        """
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.stats = DiscoveryStats()

    async def __aenter__(self):
        """Context manager entry."""
        # Use explicit connect timeout so DNS/TCP hangs don't block forever
        timeout = aiohttp.ClientTimeout(
            total=self.config.request_timeout,
            connect=min(self.config.request_timeout, 10),
            sock_connect=min(self.config.request_timeout, 10),
        )
        connector = aiohttp.TCPConnector(
            limit=self.config.max_concurrent_requests,
            enable_cleanup_closed=True,
        )
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            headers={'User-Agent': self.config.user_agent},
            connector=connector,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self.session:
            await self.session.close()

    @abstractmethod
    async def discover(self) -> AsyncGenerator[dict, None]:
        """
        Discover and yield results.

        Yields:
            dict: Discovery result with keys:
                - type: str (subdomain, js_file, path, etc.)
                - url: str
                - metadata: dict (optional additional data)
        """
        raise NotImplementedError

    def _classify_error(self, error: Exception) -> str:
        """
        Classify an exception into an error category.

        Args:
            error: The exception to classify

        Returns:
            Error category string
        """
        error_str = str(type(error).__name__).lower()
        error_msg = str(error).lower()

        if 'timeout' in error_str or 'timeout' in error_msg:
            return 'timeout'
        elif 'connection' in error_str or 'connect' in error_msg:
            return 'connection'
        elif 'dns' in error_msg or 'getaddrinfo' in error_msg or 'nodename' in error_msg:
            return 'dns'
        elif 'ssl' in error_str or 'certificate' in error_msg or 'ssl' in error_msg:
            return 'ssl'
        else:
            return 'other'

    def _record_error(self, error_type: str, url: str, error: Exception):
        """Record an error in stats."""
        self.stats.requests_failed += 1
        self.stats.record_error(error_type, url, str(error))

        if error_type == 'timeout':
            self.stats.timeouts += 1
        elif error_type == 'connection':
            self.stats.connection_errors += 1
        elif error_type == 'dns':
            self.stats.dns_errors += 1
        elif error_type == 'ssl':
            self.stats.ssl_errors += 1
        else:
            self.stats.other_errors += 1

    async def fetch(self, url: str, retry: bool = True, **kwargs) -> Optional[str]:
        """
        Fetch URL content with retry logic.

        Args:
            url: URL to fetch
            retry: Whether to retry on transient failures
            **kwargs: Additional arguments for aiohttp

        Returns:
            Response text or None if failed
        """
        if not self.session:
            raise RuntimeError("Session not initialized. Use async context manager.")

        max_attempts = self.MAX_RETRIES if retry else 1

        for attempt in range(max_attempts):
            self.stats.requests_made += 1

            try:
                async with self.session.get(url, **kwargs) as response:
                    # Handle rate limiting (429)
                    if response.status == 429:
                        self.stats.rate_limited += 1
                        retry_after = response.headers.get('Retry-After', '5')
                        try:
                            wait_time = int(retry_after)
                        except ValueError:
                            wait_time = 5
                        if attempt < max_attempts - 1:
                            self.stats.retries += 1
                            await asyncio.sleep(min(wait_time, 30))  # Cap at 30s
                            continue
                        return None

                    if response.status == 200:
                        self.stats.requests_successful += 1
                        return await response.text()

                    # Non-retryable HTTP errors
                    if response.status in (400, 401, 403, 404, 410):
                        return None

                    # Server errors - retry
                    if response.status >= 500 and attempt < max_attempts - 1:
                        self.stats.retries += 1
                        await asyncio.sleep(self.RETRY_BACKOFF[attempt])
                        continue

                    return None

            except asyncio.TimeoutError as e:
                error_type = 'timeout'
                if attempt < max_attempts - 1:
                    self.stats.retries += 1
                    await asyncio.sleep(self.RETRY_BACKOFF[attempt])
                    continue
                self._record_error(error_type, url, e)
                if self.config.verbose:
                    print(f"[discover] Timeout fetching {url}")
                return None

            except aiohttp.ClientConnectorError as e:
                error_type = self._classify_error(e)
                # DNS and SSL errors are not retryable
                if error_type in ('dns', 'ssl'):
                    self._record_error(error_type, url, e)
                    if self.config.verbose:
                        print(f"[discover] {error_type.upper()} error for {url}: {e}")
                    return None
                # Connection errors can be retried
                if attempt < max_attempts - 1:
                    self.stats.retries += 1
                    await asyncio.sleep(self.RETRY_BACKOFF[attempt])
                    continue
                self._record_error(error_type, url, e)
                if self.config.verbose:
                    print(f"[discover] Connection error for {url}: {e}")
                return None

            except Exception as e:
                error_type = self._classify_error(e)
                self._record_error(error_type, url, e)
                if self.config.verbose:
                    print(f"[discover] Error fetching {url}: {e}")
                return None

        return None

    async def fetch_json(self, url: str, retry: bool = True, **kwargs) -> Optional[dict]:
        """
        Fetch JSON response with retry logic.

        Args:
            url: URL to fetch
            retry: Whether to retry on transient failures
            **kwargs: Additional arguments for aiohttp

        Returns:
            JSON dict or None if failed
        """
        if not self.session:
            raise RuntimeError("Session not initialized. Use async context manager.")

        max_attempts = self.MAX_RETRIES if retry else 1

        for attempt in range(max_attempts):
            self.stats.requests_made += 1

            try:
                async with self.session.get(url, **kwargs) as response:
                    # Handle rate limiting
                    if response.status == 429:
                        self.stats.rate_limited += 1
                        retry_after = response.headers.get('Retry-After', '5')
                        try:
                            wait_time = int(retry_after)
                        except ValueError:
                            wait_time = 5
                        if attempt < max_attempts - 1:
                            self.stats.retries += 1
                            await asyncio.sleep(min(wait_time, 30))
                            continue
                        return None

                    if response.status == 200:
                        self.stats.requests_successful += 1
                        try:
                            return await response.json()
                        except Exception as e:
                            self._record_error('json_parse', url, e)
                            if self.config.verbose:
                                print(f"[discover] JSON parse error for {url}: {e}")
                            return None

                    # Non-retryable HTTP errors
                    if response.status in (400, 401, 403, 404, 410):
                        return None

                    # Server errors - retry
                    if response.status >= 500 and attempt < max_attempts - 1:
                        self.stats.retries += 1
                        await asyncio.sleep(self.RETRY_BACKOFF[attempt])
                        continue

                    return None

            except asyncio.TimeoutError as e:
                if attempt < max_attempts - 1:
                    self.stats.retries += 1
                    await asyncio.sleep(self.RETRY_BACKOFF[attempt])
                    continue
                self._record_error('timeout', url, e)
                if self.config.verbose:
                    print(f"[discover] Timeout fetching JSON {url}")
                return None

            except aiohttp.ClientConnectorError as e:
                error_type = self._classify_error(e)
                if error_type in ('dns', 'ssl'):
                    self._record_error(error_type, url, e)
                    return None
                if attempt < max_attempts - 1:
                    self.stats.retries += 1
                    await asyncio.sleep(self.RETRY_BACKOFF[attempt])
                    continue
                self._record_error(error_type, url, e)
                return None

            except Exception as e:
                error_type = self._classify_error(e)
                self._record_error(error_type, url, e)
                if self.config.verbose:
                    print(f"[discover] Error fetching JSON {url}: {e}")
                return None

        return None

    async def rate_limit(self):
        """Apply rate limiting delay."""
        await asyncio.sleep(self.config.rate_limit_delay)

    def get_stats(self) -> dict:
        """
        Get discovery statistics.

        Returns:
            Statistics dictionary
        """
        return {
            'requests_made': self.stats.requests_made,
            'requests_successful': self.stats.requests_successful,
            'requests_failed': self.stats.requests_failed,
            'success_rate': (
                self.stats.requests_successful / self.stats.requests_made * 100
                if self.stats.requests_made > 0 else 0
            ),
            'timeouts': self.stats.timeouts,
            'connection_errors': self.stats.connection_errors,
            'dns_errors': self.stats.dns_errors,
            'ssl_errors': self.stats.ssl_errors,
            'rate_limited': self.stats.rate_limited,
            'other_errors': self.stats.other_errors,
            'retries': self.stats.retries,
            'recent_errors': self.stats.errors[-10:],  # Last 10 errors
        }
