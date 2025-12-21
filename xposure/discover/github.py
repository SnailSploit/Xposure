"""GitHub code search (dorking) for X-POSURE."""

import re
import asyncio
from typing import AsyncGenerator, Optional
from urllib.parse import quote_plus

from .base import BaseDiscoverer


class GitHubDorker(BaseDiscoverer):
    """Search GitHub for exposed secrets related to target domain."""

    # GitHub API endpoints
    GITHUB_API = "https://api.github.com"
    SEARCH_CODE = f"{GITHUB_API}/search/code"
    
    # Rate limiting
    REQUESTS_PER_MINUTE = 10  # GitHub search API limit for authenticated users
    
    # Dork templates - {domain} and {org} are replaced with target
    DORK_TEMPLATES = [
        # Domain-based searches
        '"{domain}" password',
        '"{domain}" api_key',
        '"{domain}" apikey',
        '"{domain}" secret',
        '"{domain}" token',
        '"{domain}" credentials',
        '"{domain}" AWS_SECRET',
        '"{domain}" PRIVATE_KEY',
        
        # Filename-based searches
        'filename:.env {domain}',
        'filename:credentials {domain}',
        'filename:config.json {domain}',
        'filename:settings.py {domain}',
        'filename:.npmrc {domain}',
        'filename:docker-compose {domain}',
        'filename:id_rsa {domain}',
        
        # Extension-based searches  
        'extension:pem {domain}',
        'extension:key {domain}',
        'extension:env {domain}',
        
        # Secret patterns with domain context
        '"{domain}" "sk_live_"',
        '"{domain}" "AKIA"',
        '"{domain}" "ghp_"',
        '"{domain}" "xox"',  # Slack tokens
        
        # Connection strings
        '"{domain}" "mongodb://"',
        '"{domain}" "postgres://"',
        '"{domain}" "mysql://"',
        '"{domain}" "redis://"',
    ]
    
    # Organization-based dorks (if we can detect org name)
    ORG_DORK_TEMPLATES = [
        'org:{org} filename:.env',
        'org:{org} filename:credentials',
        'org:{org} filename:secrets',
        'org:{org} password NOT example',
        'org:{org} api_key NOT example',
        'org:{org} AWS_SECRET_ACCESS_KEY',
        'org:{org} PRIVATE_KEY',
        'org:{org} "BEGIN RSA PRIVATE KEY"',
        'org:{org} "BEGIN OPENSSH PRIVATE KEY"',
        'org:{org} extension:pem',
        'org:{org} extension:key',
    ]

    def __init__(self, config, github_token: Optional[str] = None):
        """
        Initialize GitHub dorker.
        
        Args:
            config: X-POSURE config
            github_token: GitHub personal access token
        """
        super().__init__(config)
        self.github_token = github_token or config.github_token
        self.request_count = 0
        self.last_request_time = 0

    async def discover(self, org_name: Optional[str] = None) -> AsyncGenerator[dict, None]:
        """
        Search GitHub for exposed secrets.

        Args:
            org_name: Optional GitHub organization name to search

        Yields:
            dict: Result with type='github_result', url, content, metadata
        """
        if not self.github_token:
            return
            
        domain = self.config.target
        
        # Run domain-based dorks
        for template in self.DORK_TEMPLATES:
            query = template.format(domain=domain)
            async for result in self._search(query):
                yield result
            
            # Rate limiting
            await self._rate_limit()
        
        # Run org-based dorks if org name provided
        if org_name:
            for template in self.ORG_DORK_TEMPLATES:
                query = template.format(org=org_name)
                async for result in self._search(query):
                    yield result
                    
                await self._rate_limit()

    async def _search(self, query: str) -> AsyncGenerator[dict, None]:
        """
        Execute a GitHub code search.

        Args:
            query: Search query

        Yields:
            Search results
        """
        import aiohttp
        
        headers = {
            'Authorization': f'token {self.github_token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'X-POSURE Security Scanner',
        }
        
        params = {
            'q': query,
            'per_page': 10,  # Limit results per query
        }
        
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    self.SEARCH_CODE,
                    headers=headers,
                    params=params
                ) as response:
                    
                    self.request_count += 1
                    
                    if response.status == 403:
                        # Rate limited
                        return
                    
                    if response.status != 200:
                        return
                        
                    data = await response.json()
                    
                    for item in data.get('items', []):
                        result = await self._process_result(item, query)
                        if result:
                            yield result
                            
        except Exception as e:
            if self.config.verbose:
                print(f"[github] Search error: {e}")

    async def _process_result(self, item: dict, query: str) -> Optional[dict]:
        """
        Process a search result item.

        Args:
            item: GitHub API result item
            query: Original search query

        Returns:
            Processed result or None
        """
        repo = item.get('repository', {})
        
        result = {
            'type': 'github_result',
            'url': item.get('html_url', ''),
            'metadata': {
                'query': query,
                'repo_name': repo.get('full_name', ''),
                'repo_url': repo.get('html_url', ''),
                'file_path': item.get('path', ''),
                'file_name': item.get('name', ''),
                'score': item.get('score', 0),
                'is_fork': repo.get('fork', False),
                'is_private': repo.get('private', False),
            }
        }
        
        # Fetch file content if possible
        raw_url = self._get_raw_url(item)
        if raw_url:
            content = await self._fetch_raw_content(raw_url)
            if content:
                result['content'] = content
                result['metadata']['content_size'] = len(content)
        
        return result

    def _get_raw_url(self, item: dict) -> Optional[str]:
        """
        Get raw content URL for a GitHub file.

        Args:
            item: GitHub API result item

        Returns:
            Raw content URL or None
        """
        html_url = item.get('html_url', '')
        
        # Convert github.com URL to raw.githubusercontent.com
        # https://github.com/user/repo/blob/branch/path
        # -> https://raw.githubusercontent.com/user/repo/branch/path
        
        match = re.match(
            r'https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)',
            html_url
        )
        
        if match:
            user, repo, branch, path = match.groups()
            return f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}"
            
        return None

    async def _fetch_raw_content(self, url: str) -> Optional[str]:
        """
        Fetch raw file content from GitHub.

        Args:
            url: Raw content URL

        Returns:
            File content or None
        """
        import aiohttp
        
        headers = {
            'Authorization': f'token {self.github_token}',
            'User-Agent': 'X-POSURE Security Scanner',
        }
        
        try:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        content = await response.text()
                        # Limit content size
                        return content[:50000] if len(content) > 50000 else content
        except Exception:
            pass
            
        return None

    async def _rate_limit(self):
        """Apply rate limiting between requests."""
        import time
        
        # Simple rate limiting: wait between requests
        current_time = time.time()
        elapsed = current_time - self.last_request_time
        
        if elapsed < 6:  # ~10 requests per minute
            await asyncio.sleep(6 - elapsed)
            
        self.last_request_time = time.time()

    @staticmethod
    def detect_org_from_domain(domain: str) -> Optional[str]:
        """
        Try to detect GitHub organization from domain.

        Args:
            domain: Target domain

        Returns:
            Potential organization name or None
        """
        # Remove TLD and common subdomains
        parts = domain.split('.')
        
        if len(parts) >= 2:
            # Get the main domain part (before TLD)
            org_candidate = parts[-2]
            
            # Skip generic names
            generic = ['www', 'api', 'app', 'dev', 'staging', 'test']
            if org_candidate.lower() not in generic and len(org_candidate) > 2:
                return org_candidate
                
        return None


class GitHubResultAnalyzer:
    """Analyze GitHub search results for secrets."""
    
    # Patterns to look for in GitHub results
    SECRET_PATTERNS = [
        # API Keys
        (r'api[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', 'api_key'),
        (r'apikey\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', 'api_key'),
        
        # AWS
        (r'(AKIA[A-Z0-9]{16})', 'aws_access_key'),
        (r'aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?', 'aws_secret_key'),
        
        # Private Keys
        (r'-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----', 'private_key'),
        
        # Database URLs
        (r'((?:mongodb|postgres|mysql|redis)://[^\s"\'<>]+)', 'database_url'),
        
        # Tokens
        (r'(ghp_[A-Za-z0-9]{36})', 'github_pat'),
        (r'(xox[baprs]-[A-Za-z0-9\-]+)', 'slack_token'),
        (r'(sk_live_[A-Za-z0-9]{24,})', 'stripe_key'),
        
        # Generic secrets
        (r'password\s*[=:]\s*["\']([^"\']{8,})["\']', 'password'),
        (r'secret\s*[=:]\s*["\']([^"\']{8,})["\']', 'secret'),
    ]
    
    def analyze(self, content: str, metadata: dict) -> list[dict]:
        """
        Analyze GitHub result content for secrets.
        
        Args:
            content: File content
            metadata: Result metadata
            
        Returns:
            List of found secrets
        """
        secrets = []
        
        for pattern, secret_type in self.SECRET_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                value = match.group(1) if match.lastindex else match.group(0)
                
                # Skip placeholders
                if self._is_placeholder(value):
                    continue
                    
                secrets.append({
                    'type': secret_type,
                    'value': value,
                    'source': 'github',
                    'repo': metadata.get('repo_name', ''),
                    'file_path': metadata.get('file_path', ''),
                    'context': content[max(0, match.start()-50):match.end()+50],
                })
        
        return secrets

    def _is_placeholder(self, value: str) -> bool:
        """Check if value is a placeholder."""
        placeholders = [
            'your_', 'xxx', 'example', 'test', 'demo', 'fake',
            'placeholder', 'insert', 'change_me', 'todo', 'sample',
            '${', '{{', '%', '<your', 'CHANGE', 'REPLACE',
        ]
        value_lower = value.lower()
        return any(p.lower() in value_lower for p in placeholders)
