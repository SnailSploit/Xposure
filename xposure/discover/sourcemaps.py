"""Source map discovery and parsing for X-POSURE."""

import re
import json
from typing import AsyncGenerator, Optional
from urllib.parse import urljoin

from .base import BaseDiscoverer


class SourceMapDiscoverer(BaseDiscoverer):
    """Discover and parse JavaScript source maps for original source code."""

    # Pattern to find sourceMappingURL in JS files
    SOURCE_MAP_PATTERN = re.compile(
        r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)',
        re.IGNORECASE
    )
    
    # Common source map file extensions and paths
    SOURCE_MAP_EXTENSIONS = ['.map', '.js.map', '.min.js.map']

    async def discover(self, js_urls: list[str]) -> AsyncGenerator[dict, None]:
        """
        Discover source maps from JavaScript files.

        Args:
            js_urls: List of JavaScript file URLs to check

        Yields:
            dict: Result with type='source_map', url, original_sources
        """
        seen_maps = set()
        
        for js_url in js_urls:
            # Skip inline scripts
            if '#inline' in js_url:
                continue
                
            # Check for sourceMappingURL in JS content
            js_content = await self.fetch(js_url)
            if js_content:
                map_url = self._extract_map_url(js_content, js_url)
                if map_url and map_url not in seen_maps:
                    seen_maps.add(map_url)
                    async for result in self._process_source_map(map_url, js_url):
                        yield result
            
            # Try common source map paths
            for ext in self.SOURCE_MAP_EXTENSIONS:
                if js_url.endswith('.js'):
                    map_url = js_url.rsplit('.js', 1)[0] + ext
                else:
                    map_url = js_url + '.map'
                    
                if map_url not in seen_maps:
                    seen_maps.add(map_url)
                    async for result in self._process_source_map(map_url, js_url):
                        yield result

    def _extract_map_url(self, js_content: str, js_url: str) -> Optional[str]:
        """
        Extract sourceMappingURL from JavaScript content.

        Args:
            js_content: JavaScript file content
            js_url: URL of the JavaScript file

        Returns:
            Full URL to source map, or None
        """
        # Check last 500 chars (sourceMappingURL is usually at the end)
        search_content = js_content[-500:] if len(js_content) > 500 else js_content
        
        match = self.SOURCE_MAP_PATTERN.search(search_content)
        if not match:
            return None
            
        map_path = match.group(1).strip()
        
        # Handle data URLs (inline source maps)
        if map_path.startswith('data:'):
            return None  # TODO: Handle inline source maps
            
        # Resolve relative URLs
        if not map_path.startswith(('http://', 'https://')):
            map_path = urljoin(js_url, map_path)
            
        return map_path

    async def _process_source_map(self, map_url: str, js_url: str) -> AsyncGenerator[dict, None]:
        """
        Fetch and parse a source map.

        Args:
            map_url: URL to the source map
            js_url: URL of the original JS file

        Yields:
            Source map results with original sources
        """
        map_content = await self.fetch(map_url)
        
        if not map_content:
            return
            
        # Parse source map JSON
        try:
            source_map = json.loads(map_content)
        except json.JSONDecodeError:
            return
            
        if not isinstance(source_map, dict):
            return
            
        # Extract original sources
        sources = source_map.get('sources', [])
        sources_content = source_map.get('sourcesContent', [])
        
        if not sources and not sources_content:
            return
            
        # Build result with original source code
        original_sources = []
        
        for i, source_path in enumerate(sources):
            source_data = {
                'path': source_path,
                'content': None,
            }
            
            # Get content if available
            if i < len(sources_content) and sources_content[i]:
                source_data['content'] = sources_content[i]
                
            original_sources.append(source_data)
        
        # Calculate value score
        value_score = self._calculate_value(original_sources)
        
        yield {
            'type': 'source_map',
            'url': map_url,
            'js_url': js_url,
            'metadata': {
                'sources_count': len(sources),
                'has_content': any(s.get('content') for s in original_sources),
                'value_score': value_score,
                'source_root': source_map.get('sourceRoot', ''),
            },
            'original_sources': original_sources,
        }

    def _calculate_value(self, sources: list[dict]) -> float:
        """
        Calculate how valuable the source map is for secret detection.
        
        Args:
            sources: List of original source data
            
        Returns:
            Score from 0.0 to 1.0
        """
        if not sources:
            return 0.0
            
        score = 0.3  # Base score for any source map
        
        # Check for high-value source paths
        high_value_paths = [
            'config', 'env', 'settings', 'secret', 'auth',
            'api', 'service', 'client', 'credential',
            'firebase', 'aws', 'azure', 'gcp',
        ]
        
        for source in sources:
            path = source.get('path', '').lower()
            if any(hv in path for hv in high_value_paths):
                score += 0.1
                
            content = source.get('content', '')
            if content:
                # Check content for secret indicators
                if any(kw in content.lower() for kw in ['api_key', 'apikey', 'secret', 'password', 'token']):
                    score += 0.2
                    break
        
        return min(1.0, score)


class SourceMapExtractor:
    """Extract secrets from source map content."""
    
    # Patterns that indicate interesting variable names in original source
    INTERESTING_VARS = re.compile(
        r'\b(api[_-]?key|apikey|secret[_-]?key|access[_-]?key|auth[_-]?token|'
        r'password|passwd|credential|private[_-]?key|client[_-]?secret|'
        r'connection[_-]?string|database[_-]?url|db[_-]?pass|'
        r'stripe[_-]?key|aws[_-]?secret|firebase[_-]?config)\s*[=:]\s*["\']([^"\']+)["\']',
        re.IGNORECASE
    )
    
    # Environment variable patterns
    ENV_PATTERNS = re.compile(
        r'process\.env\.([A-Z_][A-Z0-9_]*)|'
        r'import\.meta\.env\.([A-Z_][A-Z0-9_]*)|'
        r'env\[[\'"]([\w_]+)[\'"]\]',
        re.IGNORECASE
    )

    def extract_from_sources(self, sources: list[dict]) -> list[dict]:
        """
        Extract potential secrets from source map content.
        
        Args:
            sources: List of source data from source map
            
        Returns:
            List of extracted candidates
        """
        candidates = []
        
        for source in sources:
            content = source.get('content')
            if not content:
                continue
                
            path = source.get('path', 'unknown')
            
            # Find interesting variable assignments
            for match in self.INTERESTING_VARS.finditer(content):
                var_name = match.group(1)
                value = match.group(2)
                
                # Skip placeholders
                if self._is_placeholder(value):
                    continue
                    
                candidates.append({
                    'type': 'source_map_secret',
                    'variable': var_name,
                    'value': value,
                    'source_path': path,
                    'context': content[max(0, match.start()-50):match.end()+50],
                })
            
            # Find environment variable references
            env_vars = set()
            for match in self.ENV_PATTERNS.finditer(content):
                env_var = match.group(1) or match.group(2) or match.group(3)
                if env_var:
                    env_vars.add(env_var)
                    
            if env_vars:
                candidates.append({
                    'type': 'env_reference',
                    'source_path': path,
                    'env_vars': list(env_vars),
                })
        
        return candidates

    def _is_placeholder(self, value: str) -> bool:
        """Check if value is a placeholder, not a real secret."""
        placeholders = [
            'your_', 'xxx', 'example', 'test', 'demo', 'fake',
            'placeholder', 'insert', 'change_me', 'todo',
            '${', '{{', '%', '<', 'null', 'undefined', 'none',
        ]
        value_lower = value.lower()
        return any(p in value_lower for p in placeholders) or len(value) < 8
