"""X-POSURE configuration and settings."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Config:
    """Global configuration for X-POSURE."""

    # Target
    target: str

    # Authentication tokens
    github_token: Optional[str] = None
    shodan_key: Optional[str] = None
    anthropic_key: Optional[str] = None

    # Behavior
    verify: bool = True
    follow_redirects: bool = True
    user_agent: str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    # Rate limiting
    max_concurrent_requests: int = 50
    rate_limit_delay: float = 0.1  # seconds between requests

    # Timeouts
    request_timeout: int = 30
    dns_timeout: int = 5

    # Discovery
    discover_subdomains: bool = True
    discover_js: bool = True
    discover_github: bool = True
    discover_buckets: bool = True
    discover_wayback: bool = True
    discover_configs: bool = True      # Config file discovery
    discover_sourcemaps: bool = True   # Source map mining

    # Recursive crawl
    recursive_crawl: bool = False
    crawl_depth: int = 5               # max link-follow depth
    crawl_max_pages: int = 500         # max pages to crawl
    crawl_workers: int = 10            # concurrent crawl workers
    crawl_min_sleep: float = 1.0       # min delay between requests (seconds)
    crawl_max_sleep: float = 3.0       # max delay between requests (seconds)
    use_trufflehog: bool = True        # run trufflehog alongside crawl

    # Extraction
    max_decode_depth: int = 5  # recursive decode limit
    min_entropy: float = 3.0   # minimum entropy for candidate
    ast_parse_timeout: int = 10  # seconds

    # Verification
    verify_timeout: int = 10
    verify_retries: int = 2

    # Scan modes
    scan_internal: bool = False        # Internal container/server scan
    scan_git: Optional[str] = None     # Git repo path or URL
    scan_file: Optional[str] = None    # Local directory path
    scan_combined: bool = False        # Run all modes

    # Output
    output_file: Optional[str] = None
    quiet: bool = False
    verbose: bool = False
    unmask: bool = False               # Show raw credential values

    # Output formats
    output_sarif: Optional[str] = None
    output_html: Optional[str] = None

    # Paths
    state_dir: Path = field(default_factory=lambda: Path.home() / ".xposure")
    cache_dir: Path = field(default_factory=lambda: Path.home() / ".xposure" / "cache")
    rules_dir: Optional[Path] = None
    wordlists_dir: Optional[Path] = None

    # Custom wordlist files (optional overrides)
    subdomains_wordlist: Optional[Path] = None
    paths_wordlist: Optional[Path] = None

    # Ignore patterns
    ignore_patterns: list[str] = field(default_factory=list)

    def __post_init__(self):
        """Ensure directories exist."""
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Set rules directory if not specified
        if self.rules_dir is None:
            # Use package rules directory
            self.rules_dir = Path(__file__).parent / "rules"

        # Set wordlists directory if not specified
        if self.wordlists_dir is None:
            self.wordlists_dir = Path(__file__).parent / "wordlists"

        # Override with environment variables
        self.github_token = self.github_token or os.getenv("GITHUB_TOKEN")
        self.shodan_key = self.shodan_key or os.getenv("SHODAN_API_KEY")
        self.anthropic_key = self.anthropic_key or os.getenv("ANTHROPIC_API_KEY")

    def get_wordlist(self, name: str) -> list[str]:
        """
        Load wordlist from file.

        Args:
            name: Wordlist name (e.g., 'subdomains', 'paths')

        Returns:
            List of wordlist entries
        """
        # Check for custom wordlist first
        custom_wordlist = getattr(self, f'{name}_wordlist', None)
        if custom_wordlist and custom_wordlist.exists():
            return self._load_wordlist_file(custom_wordlist)

        # Fall back to default wordlist
        default_path = self.wordlists_dir / f'{name}.txt'
        if default_path.exists():
            return self._load_wordlist_file(default_path)

        return []

    def _load_wordlist_file(self, path: Path) -> list[str]:
        """Load wordlist from file, one entry per line."""
        try:
            with open(path, 'r') as f:
                return [
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith('#')
                ]
        except Exception:
            return []

    def get_state_file(self, scan_id: str) -> Path:
        """Get state file path for a scan."""
        return self.state_dir / f"{scan_id}.json"

    def get_cache_file(self, key: str) -> Path:
        """Get cache file path."""
        # Simple cache key to filename
        safe_key = "".join(c if c.isalnum() else "_" for c in key)
        return self.cache_dir / f"{safe_key}.cache"


# Default configuration
DEFAULT_CONFIG = Config(target="example.com")
