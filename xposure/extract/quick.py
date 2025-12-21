"""Quick regex-based filtering to catch obvious patterns."""

import math
import re
from typing import Generator, Optional

from ..core.models import Candidate, Source


class QuickScanner:
    """Fast regex scanner to filter out 99% of junk before deep analysis."""

    # Patterns for quick detection (broad matches)
    PATTERNS = {
        # AWS
        'aws_access_key': r'(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}',
        'aws_secret': r'(?:aws_secret|AWS_SECRET|secret_key)["\']?\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',

        # API Keys (generic)
        'api_key': r'(?:api[_-]?key|apikey|API[_-]?KEY)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?',
        'bearer_token': r'Bearer\s+([a-zA-Z0-9\-._~+/]+=*)',

        # GitHub
        'github_token': r'(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}',
        'github_fine': r'github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}',

        # Cloud & providers
        'gcp_api_key': r'AIza[0-9A-Za-z\-_]{35}',
        'digitalocean_pat': r'dop_v1_[a-f0-9]{64}',
        'cloudflare_token': r'(?:CFP|CFU|cfp|cfu)[a-zA-Z0-9_-]{30,}',
        'supabase_service_key': r'sb[a-z]{2}_[a-zA-Z0-9]{40,}',

        # Slack
        'slack_token': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}',
        'slack_webhook': r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{24}',

        # Stripe
        'stripe_key': r'(?:sk|rk|pk)_(?:live|test)_[a-zA-Z0-9]{24,}',

        # OpenAI
        'openai_key': r'sk-(?:proj-)?[a-zA-Z0-9\-_]{48,}',

        # Anthropic
        'anthropic_key': r'sk-ant-[a-zA-Z0-9\-_]{90,}',

        # Database URIs
        'mongodb_uri': r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s"\']+',
        'postgres_uri': r'postgres(?:ql)?://[^:]+:[^@]+@[^\s"\']+',
        'mysql_uri': r'mysql://[^:]+:[^@]+@[^\s"\']+',

        # JWT
        'jwt': r'eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+',

        # Private Keys
        'rsa_private': r'-----BEGIN RSA PRIVATE KEY-----',
        'ec_private': r'-----BEGIN EC PRIVATE KEY-----',
        'openssh_private': r'-----BEGIN OPENSSH PRIVATE KEY-----',
        'pkcs8_private': r'-----BEGIN PRIVATE KEY-----',

        # Generic secrets (high entropy required)
        'password': r'(?:password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^\s"\']{8,})["\']?',
        'secret': r'(?:secret|SECRET)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?',
        'token': r'(?:token|TOKEN)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?',
    }

    # Patterns to exclude (false positives)
    EXCLUDE_PATTERNS = [
        r'example',
        r'sample',
        r'test(?:ing)?',
        r'demo',
        r'fake',
        r'your[_-]?(?:key|token|secret)',
        r'(?:xxx+|000+|111+)',
        r'\*{3,}',
        r'(?:abc|def)12345',
        r'changeme',
        r'replace[_-]?(?:this|me)',
    ]

    def __init__(self, min_entropy: float = 3.0):
        """
        Initialize quick scanner.

        Args:
            min_entropy: Minimum entropy threshold for candidates
        """
        self.min_entropy = min_entropy
        self.exclude_regex = re.compile('|'.join(self.EXCLUDE_PATTERNS), re.IGNORECASE)

    def scan(self, content: str, source: Source) -> Generator[Candidate, None, None]:
        """
        Quick scan content for potential secrets.

        Args:
            content: Content to scan
            source: Source information

        Yields:
            Candidate objects for potential secrets
        """
        if not content:
            return

        # Scan with each pattern
        for pattern_name, pattern in self.PATTERNS.items():
            try:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    # Extract the matched value
                    value = match.group(1) if match.lastindex else match.group(0)
                    value = value.strip().strip('"\'`')

                    # Skip if empty or too short
                    if not value or len(value) < 8:
                        continue

                    # Skip excluded patterns
                    if self.exclude_regex.search(value):
                        continue

                    # Calculate entropy
                    entropy = self._calculate_entropy(value)

                    # Skip low entropy (unless it's a known high-confidence pattern)
                    high_confidence_patterns = {
                        'github_token', 'github_fine', 'slack_token',
                        'stripe_key', 'openai_key', 'anthropic_key',
                        'aws_access_key', 'gcp_api_key', 'digitalocean_pat',
                        'cloudflare_token', 'supabase_service_key'
                    }

                    if entropy < self.min_entropy and pattern_name not in high_confidence_patterns:
                        continue

                    # Extract context (50 chars before and after)
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end]

                    # Create candidate
                    yield Candidate(
                        type=pattern_name,
                        value=value,
                        source=source,
                        entropy=entropy,
                        context=context,
                        confidence=self._initial_confidence(pattern_name, entropy)
                    )

            except re.error:
                # Skip patterns with regex errors
                continue

    def _calculate_entropy(self, s: str) -> float:
        """
        Calculate Shannon entropy of a string.

        Args:
            s: String to analyze

        Returns:
            Entropy value (0-8, where higher is more random)
        """
        if not s:
            return 0.0

        # Count character frequencies
        prob = [float(s.count(c)) / len(s) for c in set(s)]

        # Calculate Shannon entropy
        entropy = -sum(p * math.log2(p) for p in prob if p > 0)

        return entropy

    def _initial_confidence(self, pattern_name: str, entropy: float) -> float:
        """
        Calculate initial confidence score for a match.

        Args:
            pattern_name: Name of the pattern that matched
            entropy: Entropy of the matched value

        Returns:
            Confidence score (0.0-1.0)
        """
        # Base confidence by pattern type
        high_confidence = {
            'github_token', 'github_fine', 'slack_token',
            'stripe_key', 'openai_key', 'anthropic_key',
            'aws_access_key', 'slack_webhook',
            'gcp_api_key', 'digitalocean_pat', 'cloudflare_token',
            'supabase_service_key'
        }

        medium_confidence = {
            'mongodb_uri', 'postgres_uri', 'mysql_uri',
            'jwt', 'bearer_token'
        }

        if pattern_name in high_confidence:
            base = 0.8
        elif pattern_name in medium_confidence:
            base = 0.6
        else:
            base = 0.4

        # Adjust based on entropy
        if entropy > 4.5:
            base += 0.1
        elif entropy < 3.0:
            base -= 0.2

        return max(0.0, min(1.0, base))


def quick_scan_content(content: str, source: Source, min_entropy: float = 3.0) -> list[Candidate]:
    """
    Convenience function to quick scan content.

    Args:
        content: Content to scan
        source: Source information
        min_entropy: Minimum entropy threshold

    Returns:
        List of candidates
    """
    scanner = QuickScanner(min_entropy=min_entropy)
    return list(scanner.scan(content, source))
