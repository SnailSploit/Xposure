"""Wayback Machine discovery for X-POSURE v5.0.

Queries the Internet Archive CDX API to find historical snapshots of a
target domain, filtering for file types likely to contain secrets or
configuration data (.js, .json, .env, .config, .yml, .xml).  Each
matching snapshot can be fetched for further analysis.
"""

import asyncio
from typing import AsyncGenerator, Optional
from urllib.parse import urlparse

import aiohttp

from ..config import Config


# File extensions worth fetching from the Wayback Machine
_INTERESTING_EXTENSIONS: set[str] = {
    ".js",
    ".json",
    ".env",
    ".config",
    ".yml",
    ".yaml",
    ".xml",
    ".conf",
    ".toml",
    ".ini",
    ".properties",
    ".cfg",
}

# CDX API base
_CDX_API = "http://web.archive.org/cdx/search/cdx"

# Wayback raw content URL template
_WAYBACK_RAW = "https://web.archive.org/web/{timestamp}id_/{url}"


class WaybackDiscoverer:
    """Discover historical content via the Wayback Machine CDX API.

    Usage::

        async with WaybackDiscoverer(config) as wb:
            async for item in wb.discover("example.com"):
                print(item["url"], item["timestamp"])

    Each yielded dict contains:
        url        - original URL of the archived resource
        timestamp  - Wayback Machine snapshot timestamp
        mimetype   - MIME type as recorded by the archive
        status     - HTTP status code at crawl time
        content    - fetched historical content (if retrieval succeeded)
        source     - ``"wayback"``
    """

    # CDX API fetch timeout
    CDX_TIMEOUT: float = 30.0

    # Snapshot content fetch timeout
    CONTENT_TIMEOUT: float = 15.0

    # Maximum number of CDX results to process
    MAX_CDX_RESULTS: int = 5000

    # Maximum concurrent snapshot fetches
    MAX_CONCURRENT_FETCHES: int = 5

    # Rate limit delay between snapshot fetches (be polite to IA)
    FETCH_DELAY: float = 1.0

    def __init__(
        self,
        config: Config,
        max_results: int = 5000,
        fetch_content: bool = True,
    ):
        self.config = config
        self.MAX_CDX_RESULTS = max_results
        self._fetch_content = fetch_content
        self._session: Optional[aiohttp.ClientSession] = None
        self.stats = {
            "cdx_results": 0,
            "interesting_urls": 0,
            "fetched": 0,
            "fetch_errors": 0,
        }

    # ------------------------------------------------------------------
    # Async context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "WaybackDiscoverer":
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.CDX_TIMEOUT),
            headers={"User-Agent": self.config.user_agent},
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._session:
            await self._session.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def discover(self, domain: str) -> AsyncGenerator[dict, None]:
        """Query the CDX API and yield interesting archived resources.

        Args:
            domain: Target domain (e.g. ``"example.com"``).

        Yields:
            Dicts with keys ``url``, ``timestamp``, ``mimetype``,
            ``status``, ``content``, ``source``.
        """
        if not self._session:
            raise RuntimeError(
                "Session not initialized. Use async context manager."
            )

        if not self.config.quiet:
            print(f"[wayback] querying CDX API for *.{domain}/*...")

        # Query CDX
        cdx_url = (
            f"{_CDX_API}"
            f"?url=*.{domain}/*"
            f"&output=json"
            f"&fl=urlkey,timestamp,original,mimetype,statuscode,digest,length"
            f"&collapse=digest"
            f"&limit={self.MAX_CDX_RESULTS}"
        )

        try:
            async with self._session.get(cdx_url) as resp:
                if resp.status != 200:
                    if not self.config.quiet:
                        print(
                            f"[wayback] CDX API returned status {resp.status}"
                        )
                    return

                data = await resp.json(content_type=None)
        except Exception as exc:
            if not self.config.quiet:
                print(f"[wayback] CDX API error: {exc}")
            return

        if not isinstance(data, list) or len(data) < 2:
            if not self.config.quiet:
                print("[wayback] no CDX results found")
            return

        # First row is the header
        headers = data[0]
        rows = data[1:]
        self.stats["cdx_results"] = len(rows)

        if not self.config.quiet:
            print(f"[wayback] {len(rows)} CDX entries found")

        # Map header names to indices
        col = {name: idx for idx, name in enumerate(headers)}

        # Deduplicate by original URL (keep latest timestamp)
        seen_urls: dict[str, dict] = {}

        for row in rows:
            try:
                original = row[col.get("original", 2)]
                timestamp = row[col.get("timestamp", 1)]
                mimetype = row[col.get("mimetype", 3)]
                statuscode = row[col.get("statuscode", 4)]
            except (IndexError, KeyError):
                continue

            # Filter for interesting file extensions
            if not self._is_interesting(original):
                continue

            # Keep latest snapshot per URL
            if original not in seen_urls or timestamp > seen_urls[original]["timestamp"]:
                seen_urls[original] = {
                    "url": original,
                    "timestamp": timestamp,
                    "mimetype": mimetype,
                    "status": statuscode,
                }

        self.stats["interesting_urls"] = len(seen_urls)

        if not self.config.quiet:
            print(
                f"[wayback] {len(seen_urls)} interesting URLs after filtering"
            )

        # Yield results, optionally fetching content
        sem = asyncio.Semaphore(self.MAX_CONCURRENT_FETCHES)

        for entry in seen_urls.values():
            content = ""

            if self._fetch_content:
                async with sem:
                    content = await self._fetch_snapshot(
                        entry["url"], entry["timestamp"]
                    )
                    await asyncio.sleep(self.FETCH_DELAY)

            yield {
                "url": entry["url"],
                "timestamp": entry["timestamp"],
                "mimetype": entry["mimetype"],
                "status": entry["status"],
                "content": content,
                "source": "wayback",
            }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_interesting(self, url: str) -> bool:
        """Check if a URL has an interesting file extension."""
        try:
            parsed = urlparse(url)
            path = parsed.path.lower()

            # Direct extension check
            for ext in _INTERESTING_EXTENSIONS:
                if path.endswith(ext):
                    return True

            # Also catch query-string variants like file.js?v=123
            base_path = path.split("?")[0]
            for ext in _INTERESTING_EXTENSIONS:
                if base_path.endswith(ext):
                    return True

            return False
        except Exception:
            return False

    async def _fetch_snapshot(self, url: str, timestamp: str) -> str:
        """Fetch the raw content of a Wayback Machine snapshot.

        Args:
            url: Original URL.
            timestamp: Wayback timestamp (e.g. ``"20230415123456"``).

        Returns:
            Content string, or empty string on failure.
        """
        if not self._session:
            return ""

        wayback_url = _WAYBACK_RAW.format(timestamp=timestamp, url=url)

        try:
            timeout = aiohttp.ClientTimeout(total=self.CONTENT_TIMEOUT)
            async with self._session.get(wayback_url, timeout=timeout) as resp:
                if resp.status != 200:
                    self.stats["fetch_errors"] += 1
                    return ""

                content = await resp.text(errors="replace")
                self.stats["fetched"] += 1
                # Cap content size
                return content[:512_000]

        except asyncio.TimeoutError:
            self.stats["fetch_errors"] += 1
            return ""
        except Exception:
            self.stats["fetch_errors"] += 1
            return ""

    def get_stats(self) -> dict:
        return dict(self.stats)
