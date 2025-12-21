"""JavaScript file discovery for X-POSURE."""

import re
from typing import AsyncGenerator, Set
from urllib.parse import urljoin, urlparse

from .base import BaseDiscoverer


class JSDiscoverer(BaseDiscoverer):
    """Discover JavaScript files from HTML pages."""

    def __init__(self, config):
        """Initialize JS discoverer."""
        super().__init__(config)
        self.seen: Set[str] = set()

    async def discover(self, start_urls: list[str] = None) -> AsyncGenerator[dict, None]:
        """
        Discover JavaScript files.

        Args:
            start_urls: List of URLs to parse for JS files

        Yields:
            dict: Result with type='js_file', url, metadata
        """
        if not start_urls:
            # Default to target root
            start_urls = [f"https://{self.config.target}"]

        for url in start_urls:
            async for result in self._discover_from_page(url):
                yield result

    async def _discover_from_page(self, page_url: str) -> AsyncGenerator[dict, None]:
        """
        Extract JS files from a single page.

        Args:
            page_url: URL of page to parse

        Yields:
            JS file results
        """
        content = await self.fetch(page_url)

        if not content:
            return

        # Parse domain for relative URL resolution
        parsed_url = urlparse(page_url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        # 1. Extract <script src="..."> tags
        async for result in self._extract_script_tags(content, base_url, page_url):
            yield result

        # 2. Extract inline <script> content
        async for result in self._extract_inline_scripts(content, page_url):
            yield result

        # 3. Extract module imports (import statements)
        async for result in self._extract_module_imports(content, base_url, page_url):
            yield result

    async def _extract_script_tags(
        self,
        html: str,
        base_url: str,
        source_url: str
    ) -> AsyncGenerator[dict, None]:
        """
        Extract external script sources from <script src="..."> tags.

        Args:
            html: HTML content
            base_url: Base URL for relative paths
            source_url: URL where this HTML was found

        Yields:
            JS file results
        """
        # Match <script src="...">
        pattern = r'<script[^>]+src=["\']([^"\']+)["\']'

        for match in re.finditer(pattern, html, re.IGNORECASE):
            src = match.group(1)

            # Resolve relative URLs
            if src.startswith('//'):
                js_url = 'https:' + src
            elif src.startswith('http://') or src.startswith('https://'):
                js_url = src
            else:
                js_url = urljoin(base_url, src)

            if js_url in self.seen:
                continue

            # Only track .js files or URLs with JS extensions/patterns
            if not self._is_js_url(js_url):
                continue

            self.seen.add(js_url)

            yield {
                'type': 'js_file',
                'url': js_url,
                'metadata': {
                    'source': 'script_tag',
                    'found_in': source_url,
                }
            }

    async def _extract_inline_scripts(
        self,
        html: str,
        source_url: str
    ) -> AsyncGenerator[dict, None]:
        """
        Extract inline <script> content.

        Args:
            html: HTML content
            source_url: URL where this HTML was found

        Yields:
            Inline script results
        """
        # Match <script>...</script> without src attribute
        pattern = r'<script(?![^>]*src=)[^>]*>(.*?)</script>'

        for i, match in enumerate(re.finditer(pattern, html, re.IGNORECASE | re.DOTALL)):
            script_content = match.group(1).strip()

            if not script_content or len(script_content) < 50:
                continue

            # Generate pseudo-URL for inline script
            pseudo_url = f"{source_url}#inline-script-{i}"

            if pseudo_url in self.seen:
                continue

            self.seen.add(pseudo_url)

            yield {
                'type': 'js_file',
                'url': pseudo_url,
                'content': script_content,
                'metadata': {
                    'source': 'inline_script',
                    'found_in': source_url,
                    'inline': True,
                }
            }

    async def _extract_module_imports(
        self,
        html: str,
        base_url: str,
        source_url: str
    ) -> AsyncGenerator[dict, None]:
        """
        Extract ES6 module imports from inline scripts.

        Args:
            html: HTML content
            base_url: Base URL for relative paths
            source_url: URL where this HTML was found

        Yields:
            JS module results
        """
        # Find import statements in inline scripts
        # import ... from "path"
        # import("path")
        patterns = [
            r'import\s+.*?\s+from\s+["\']([^"\']+)["\']',
            r'import\(["\']([^"\']+)["\']\)',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, html):
                module_path = match.group(1)

                # Resolve to full URL
                if module_path.startswith('http://') or module_path.startswith('https://'):
                    js_url = module_path
                else:
                    js_url = urljoin(base_url, module_path)

                if js_url in self.seen:
                    continue

                if not self._is_js_url(js_url):
                    continue

                self.seen.add(js_url)

                yield {
                    'type': 'js_file',
                    'url': js_url,
                    'metadata': {
                        'source': 'es6_import',
                        'found_in': source_url,
                    }
                }

    def _is_js_url(self, url: str) -> bool:
        """
        Check if URL is likely a JavaScript file.

        Args:
            url: URL to check

        Returns:
            True if likely a JS file
        """
        # Must be .js or contain js in path/query
        url_lower = url.lower()

        # Explicit .js extension
        if url_lower.endswith('.js'):
            return True

        # Webpack chunks: app.abc123.js
        if '.js?' in url_lower or '.js#' in url_lower:
            return True

        # Common JS patterns
        if any(pattern in url_lower for pattern in [
            '/js/',
            '/javascript/',
            '/static/js/',
            '/assets/js/',
            '.min.js',
            'bundle.js',
            'chunk.js',
            'vendor.js',
            'app.js',
            'main.js',
        ]):
            return True

        return False
