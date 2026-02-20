"""Recursive web crawler with evasion capabilities.

Wraps external tools (katana) when available, falls back to a built-in
async BFS crawler. Runs in the background and feeds discovered URLs
into an asyncio.Queue for the main scan pipeline to consume.
"""

import asyncio
import random
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import AsyncGenerator, Optional
from urllib.parse import urljoin, urlparse

import aiohttp

from ..config import Config
from .fingerprints import FingerprintRotator


@dataclass
class CrawlResult:
    """A single crawl result."""
    url: str
    content: str = ""
    content_type: str = ""
    status_code: int = 0
    depth: int = 0
    source: str = "crawler"  # "katana" or "builtin"
    metadata: dict = field(default_factory=dict)


class RecursiveCrawler:
    """Recursive crawler that wraps katana or falls back to built-in BFS.

    Designed to run as a background task, pushing discovered URLs into a
    shared asyncio.Queue so the main X-POSURE pipeline keeps running.
    """

    def __init__(
        self,
        config: Config,
        url_queue: asyncio.Queue,
        max_depth: int = 5,
        max_pages: int = 500,
        workers: int = 10,
        min_sleep: float = 1.0,
        max_sleep: float = 3.0,
    ):
        self.config = config
        self.url_queue = url_queue
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.workers = workers
        self.min_sleep = min_sleep
        self.max_sleep = max_sleep

        self.fingerprints = FingerprintRotator()
        self.visited: set[str] = set()
        self.pages_crawled = 0
        self._stop = False

        # Stats
        self.stats = {
            "pages_crawled": 0,
            "urls_found": 0,
            "errors": 0,
            "backend": "unknown",
        }

    async def crawl(self) -> AsyncGenerator[CrawlResult, None]:
        """Run the recursive crawl, yielding results as they come.

        Tries katana first (fast, headless browser support), falls back
        to built-in async BFS crawler.
        """
        katana_path = shutil.which("katana")
        if katana_path:
            self.stats["backend"] = "katana"
            if not self.config.quiet:
                print("[crawl] using katana backend")
            async for result in self._crawl_katana(katana_path):
                yield result
        else:
            self.stats["backend"] = "builtin"
            if not self.config.quiet:
                print("[crawl] katana not found, using built-in crawler")
            async for result in self._crawl_builtin():
                yield result

    def stop(self):
        """Signal the crawler to stop."""
        self._stop = True

    # ── katana backend ─────────────────────────────────────────────

    async def _crawl_katana(self, katana_path: str) -> AsyncGenerator[CrawlResult, None]:
        """Run katana as a subprocess, stream its output."""
        target = f"https://{self.config.target}"

        cmd = [
            katana_path,
            "-u", target,
            "-d", str(self.max_depth),
            "-silent",
            "-nc",  # no color
            "-jc",  # crawl JS
            "-kf", "all",  # known file types
            "-fx",  # extract form actions
            "-ef", "css,png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot",  # exclude static
            "-c", str(self.workers),
            "-rd", str(int(self.max_sleep)),  # delay
            "-rl", str(max(1, int(1.0 / self.min_sleep))),  # rate limit
        ]

        # Rotate headers via katana -H flag
        fp = self.fingerprints.next()
        cmd.extend(["-H", f"User-Agent: {fp.user_agent}"])

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            async for line in proc.stdout:
                if self._stop:
                    proc.terminate()
                    break

                url = line.decode().strip()
                if not url or url in self.visited:
                    continue

                self.visited.add(url)
                self.stats["urls_found"] += 1
                self.stats["pages_crawled"] += 1

                result = CrawlResult(
                    url=url,
                    source="katana",
                    metadata={"depth": -1},  # katana doesn't report depth
                )
                # Push to shared queue for extraction pipeline
                await self.url_queue.put(url)
                yield result

            await proc.wait()

        except FileNotFoundError:
            # katana binary vanished mid-run, fall back
            if not self.config.quiet:
                print("[crawl] katana failed, falling back to built-in")
            async for result in self._crawl_builtin():
                yield result
        except Exception as e:
            if not self.config.quiet:
                print(f"[crawl] katana error: {e}")

    # ── built-in BFS backend ───────────────────────────────────────

    async def _crawl_builtin(self) -> AsyncGenerator[CrawlResult, None]:
        """Built-in async BFS crawler with fingerprint rotation."""
        target = f"https://{self.config.target}"
        target_domain = self.config.target

        # BFS queue: (url, depth)
        crawl_queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        crawl_queue.put_nowait((target, 0))
        crawl_queue.put_nowait((f"https://www.{target_domain}", 0))

        self.visited.add(target)
        result_queue: asyncio.Queue[Optional[CrawlResult]] = asyncio.Queue()

        async def worker():
            connector = aiohttp.TCPConnector(ssl=False, limit_per_host=5)
            timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                while not self._stop:
                    try:
                        url, depth = await asyncio.wait_for(
                            crawl_queue.get(), timeout=10
                        )
                    except asyncio.TimeoutError:
                        break

                    if depth > self.max_depth:
                        crawl_queue.task_done()
                        continue

                    if self.pages_crawled >= self.max_pages:
                        crawl_queue.task_done()
                        break

                    # Random sleep for evasion
                    await asyncio.sleep(
                        random.uniform(self.min_sleep, self.max_sleep)
                    )

                    # Rotate fingerprint per request
                    headers = self.fingerprints.next_headers()

                    try:
                        async with session.get(
                            url,
                            headers=headers,
                            allow_redirects=True,
                            max_redirects=3,
                        ) as response:
                            content_type = response.headers.get("Content-Type", "")

                            # Only process text content
                            if not any(t in content_type for t in (
                                "text/html", "text/plain", "application/json",
                                "application/javascript", "text/javascript",
                                "application/xml", "text/xml",
                            )):
                                crawl_queue.task_done()
                                continue

                            body = await response.text(errors="replace")
                            self.pages_crawled += 1
                            self.stats["pages_crawled"] += 1

                            result = CrawlResult(
                                url=url,
                                content=body,
                                content_type=content_type,
                                status_code=response.status,
                                depth=depth,
                                source="builtin",
                            )
                            await result_queue.put(result)
                            await self.url_queue.put(url)
                            self.stats["urls_found"] += 1

                            # Extract links if HTML
                            if "text/html" in content_type:
                                links = self._extract_links(body, url, target_domain)
                                for link in links:
                                    if link not in self.visited:
                                        self.visited.add(link)
                                        crawl_queue.put_nowait((link, depth + 1))

                    except Exception as e:
                        self.stats["errors"] += 1
                        if self.config.verbose:
                            print(f"[crawl] error {url}: {e}")
                    finally:
                        crawl_queue.task_done()

            # Signal this worker is done
            await result_queue.put(None)

        # Spawn workers
        worker_tasks = [asyncio.create_task(worker()) for _ in range(self.workers)]

        # Yield results as they come
        workers_done = 0
        while workers_done < self.workers:
            result = await result_queue.get()
            if result is None:
                workers_done += 1
                continue
            yield result

        # Cleanup
        for task in worker_tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*worker_tasks, return_exceptions=True)

    def _extract_links(self, html: str, base_url: str, target_domain: str) -> list[str]:
        """Extract same-domain links from HTML content."""
        links = []

        # Match href and src attributes
        patterns = [
            r'href=["\']([^"\'#]+)["\']',
            r'src=["\']([^"\'#]+)["\']',
            r'action=["\']([^"\'#]+)["\']',
            r'data-url=["\']([^"\'#]+)["\']',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                raw_url = match.group(1).strip()

                # Skip javascript:, data:, mailto:, etc.
                if re.match(r'^(javascript|data|mailto|tel|blob):', raw_url, re.I):
                    continue

                # Resolve relative URLs
                try:
                    full_url = urljoin(base_url, raw_url)
                except Exception:
                    continue

                # Only follow same-domain links
                parsed = urlparse(full_url)
                if not parsed.hostname:
                    continue
                if not (
                    parsed.hostname == target_domain or
                    parsed.hostname.endswith(f".{target_domain}")
                ):
                    continue

                # Skip common static extensions
                path_lower = parsed.path.lower()
                skip_ext = (
                    '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
                    '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3',
                    '.pdf', '.zip', '.tar', '.gz',
                )
                if any(path_lower.endswith(ext) for ext in skip_ext):
                    continue

                # Normalize: strip fragments, keep query
                clean_url = f"{parsed.scheme}://{parsed.hostname}"
                if parsed.port and parsed.port not in (80, 443):
                    clean_url += f":{parsed.port}"
                clean_url += parsed.path
                if parsed.query:
                    clean_url += f"?{parsed.query}"

                links.append(clean_url)

        return links

    def get_stats(self) -> dict:
        return dict(self.stats)
