"""Base discovery class for X-POSURE."""

import asyncio
from abc import ABC, abstractmethod
from typing import AsyncGenerator, Optional

import aiohttp

from ..config import Config


class BaseDiscoverer(ABC):
    """Base class for all discovery modules."""

    def __init__(self, config: Config):
        """
        Initialize discoverer.

        Args:
            config: Global configuration
        """
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        """Context manager entry."""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.config.request_timeout),
            headers={'User-Agent': self.config.user_agent},
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

    async def fetch(self, url: str, **kwargs) -> Optional[str]:
        """
        Fetch URL content.

        Args:
            url: URL to fetch
            **kwargs: Additional arguments for aiohttp

        Returns:
            Response text or None if failed
        """
        if not self.session:
            raise RuntimeError("Session not initialized. Use async context manager.")

        try:
            async with self.session.get(url, **kwargs) as response:
                if response.status == 200:
                    return await response.text()
                return None
        except Exception as e:
            if self.config.verbose:
                print(f"[discover] Error fetching {url}: {e}")
            return None

    async def fetch_json(self, url: str, **kwargs) -> Optional[dict]:
        """
        Fetch JSON response.

        Args:
            url: URL to fetch
            **kwargs: Additional arguments for aiohttp

        Returns:
            JSON dict or None if failed
        """
        if not self.session:
            raise RuntimeError("Session not initialized. Use async context manager.")

        try:
            async with self.session.get(url, **kwargs) as response:
                if response.status == 200:
                    return await response.json()
                return None
        except Exception as e:
            if self.config.verbose:
                print(f"[discover] Error fetching JSON {url}: {e}")
            return None

    async def rate_limit(self):
        """Apply rate limiting delay."""
        await asyncio.sleep(self.config.rate_limit_delay)
