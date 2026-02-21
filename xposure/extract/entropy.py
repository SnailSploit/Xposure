"""Enhanced entropy analysis and false positive detection for X-POSURE."""

import re
import math
from typing import Optional
from dataclasses import dataclass


@dataclass
class EntropyResult:
    """Result of entropy analysis."""
    shannon_entropy: float
    charset_score: float
    randomness_score: float
    normalized_score: float
    is_likely_secret: bool
    reason: str


# Charset-aware entropy thresholds
ENTROPY_THRESHOLDS = {
    'hex': 3.5,
    'base64': 4.5,
    'base64url': 4.5,
    'alphanumeric': 4.8,
    'mixed': 5.0,
}

# Token delimiter pattern for entropy pre-filter
TOKEN_SPLIT_PATTERN = re.compile(r'[\s"\'`=:,;{}\[\]()<>|&\n\r\t]+')


class EntropyAnalyzer:
    """Advanced entropy analysis for secret detection."""

    # Character classes
    UPPERCASE = set('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    LOWERCASE = set('abcdefghijklmnopqrstuvwxyz')
    DIGITS = set('0123456789')
    SPECIAL = set('/+=_-')
    HEX_CHARS = set('0123456789abcdefABCDEF')
    BASE64_CHARS = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
    BASE64URL_CHARS = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=')

    # Minimum entropy thresholds by length
    MIN_ENTROPY_BY_LENGTH = {
        20: 3.0,
        30: 3.5,
        40: 4.0,
        50: 4.2,
    }

    def analyze(self, value: str) -> EntropyResult:
        """
        Perform comprehensive entropy analysis.

        Args:
            value: String to analyze

        Returns:
            EntropyResult with detailed analysis
        """
        if not value or len(value) < 8:
            return EntropyResult(
                shannon_entropy=0,
                charset_score=0,
                randomness_score=0,
                normalized_score=0,
                is_likely_secret=False,
                reason="Too short"
            )

        # Calculate Shannon entropy
        shannon = self._shannon_entropy(value)

        # Calculate charset diversity score
        charset_score = self._charset_score(value)

        # Calculate randomness score (detects patterns)
        randomness_score = self._randomness_score(value)

        # Normalize and combine scores
        normalized = self._normalize_score(value, shannon, charset_score, randomness_score)

        # Determine if likely secret
        is_secret, reason = self._evaluate(value, shannon, charset_score, randomness_score)

        return EntropyResult(
            shannon_entropy=round(shannon, 3),
            charset_score=round(charset_score, 3),
            randomness_score=round(randomness_score, 3),
            normalized_score=round(normalized, 3),
            is_likely_secret=is_secret,
            reason=reason
        )

    def scan_for_high_entropy_strings(
        self, content: str, min_length: int = 20, max_length: int = 500
    ) -> list[dict]:
        """
        Scan content for high-entropy strings that might be secrets,
        regardless of whether they match any known pattern.

        Strategy:
        1. Tokenize content by whitespace, quotes, delimiters
        2. For each token 20-500 chars, calculate Shannon entropy
        3. Use charset-aware thresholds
        4. Return high-entropy tokens with position, context, entropy score

        This catches secrets with no known regex pattern — custom internal tokens,
        proprietary API keys, etc.

        Args:
            content: Raw content to scan
            min_length: Minimum token length to consider
            max_length: Maximum token length to consider

        Returns:
            List of dicts with keys: value, start, end, entropy, charset, context
        """
        results = []

        for match in TOKEN_SPLIT_PATTERN.split(content):
            token = match.strip()
            if len(token) < min_length or len(token) > max_length:
                continue

            # Skip tokens that are clearly not secrets
            if token.startswith(('http://', 'https://', '//', '#', '/*')):
                continue

            # Detect charset and get appropriate threshold
            charset = self._detect_charset(token)
            threshold = ENTROPY_THRESHOLDS.get(charset, 5.0)

            # Calculate entropy
            entropy = self._shannon_entropy(token)
            if entropy < threshold:
                continue

            # Check randomness score
            randomness = self._randomness_score(token)
            if randomness < 0.5:
                continue

            # Find position in original content
            start = content.find(token)
            if start == -1:
                continue

            end = start + len(token)

            # Extract context
            ctx_start = max(0, start - 100)
            ctx_end = min(len(content), end + 100)
            context = content[ctx_start:ctx_end]

            results.append({
                'value': token,
                'start': start,
                'end': end,
                'entropy': round(entropy, 3),
                'charset': charset,
                'context': context,
            })

        return results

    def _detect_charset(self, s: str) -> str:
        """
        Detect dominant charset of a string.

        Args:
            s: String to analyze

        Returns:
            Charset name: 'hex', 'base64', 'base64url', 'alphanumeric', 'mixed'
        """
        chars = set(s)
        if chars <= self.HEX_CHARS:
            return 'hex'
        if chars <= self.BASE64_CHARS:
            return 'base64'
        if chars <= self.BASE64URL_CHARS:
            return 'base64url'
        if all(c.isalnum() or c in '-_' for c in s):
            return 'alphanumeric'
        return 'mixed'

    def _shannon_entropy(self, s: str) -> float:
        """Calculate Shannon entropy."""
        if not s:
            return 0.0

        prob = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in prob if p > 0)

    def _charset_score(self, s: str) -> float:
        """
        Calculate charset diversity score.

        Real secrets typically use multiple character classes.
        Font data/binary often uses limited charset.
        """
        chars = set(s)

        has_upper = bool(chars & self.UPPERCASE)
        has_lower = bool(chars & self.LOWERCASE)
        has_digit = bool(chars & self.DIGITS)
        has_special = bool(chars & self.SPECIAL)

        # Count unique characters relative to length
        uniqueness = len(chars) / len(s)

        # Score based on diversity
        diversity = sum([has_upper, has_lower, has_digit, has_special])

        # Bonus for high uniqueness
        return (diversity / 4) * 0.6 + uniqueness * 0.4

    def _randomness_score(self, s: str) -> float:
        """
        Detect patterns that indicate non-random data.

        Binary/font data often has:
        - Repeated sequences
        - Long runs of same character
        - Predictable patterns
        """
        if not s:
            return 0.0

        score = 1.0

        # Check for repeated characters (AAAA, etc.)
        max_repeat = 1
        current_repeat = 1
        for i in range(1, len(s)):
            if s[i] == s[i-1]:
                current_repeat += 1
                max_repeat = max(max_repeat, current_repeat)
            else:
                current_repeat = 1

        if max_repeat >= 4:
            score -= 0.3
        elif max_repeat >= 3:
            score -= 0.1

        # Check for repeated sequences (like "ABAB")
        for seq_len in [2, 3, 4]:
            if len(s) >= seq_len * 3:
                for i in range(len(s) - seq_len * 2):
                    seq = s[i:i+seq_len]
                    if s.count(seq) >= 3:
                        score -= 0.2
                        break

        # Check for ascending/descending sequences
        if re.search(r'(?:abc|bcd|cde|def|efg|012|123|234|345|456|567|678|789){2,}', s.lower()):
            score -= 0.3

        return max(0.0, score)

    def _normalize_score(self, value: str, shannon: float, charset: float, randomness: float) -> float:
        """Combine scores into normalized value."""
        # Weight: Shannon most important, then randomness, then charset
        combined = (shannon / 5.0) * 0.5 + randomness * 0.3 + charset * 0.2
        return min(1.0, combined)

    def _evaluate(self, value: str, shannon: float, charset: float, randomness: float) -> tuple[bool, str]:
        """Evaluate if value is likely a real secret."""

        # Use charset-aware threshold if possible
        detected_charset = self._detect_charset(value)
        charset_threshold = ENTROPY_THRESHOLDS.get(detected_charset)

        # Get minimum entropy for this length
        min_entropy = 3.5
        for length, threshold in sorted(self.MIN_ENTROPY_BY_LENGTH.items()):
            if len(value) >= length:
                min_entropy = threshold

        # Use the charset threshold if it's more appropriate
        if charset_threshold and charset_threshold < min_entropy:
            min_entropy = charset_threshold

        # Check entropy
        if shannon < min_entropy:
            return False, f"Low entropy ({shannon:.2f} < {min_entropy})"

        # Check charset diversity
        if charset < 0.3:
            return False, f"Low charset diversity ({charset:.2f})"

        # Check randomness
        if randomness < 0.5:
            return False, f"Detected patterns ({randomness:.2f})"

        # All checks passed
        return True, "Passes entropy analysis"


class FalsePositiveDetector:
    """Detect and filter false positives."""

    # Known false positive patterns
    FALSE_POSITIVE_PATTERNS = [
        # Placeholder/example patterns
        (r'(?i)^(test|example|fake|dummy|placeholder|sample|demo)', 'placeholder'),
        (r'(?i)(your[-_]?api[-_]?key|insert[-_]?here|change[-_]?me)', 'placeholder'),
        (r'(?i)(xxxx|0000|1234|abcd){2,}', 'placeholder'),
        (r'(?i)^(TODO|FIXME|CHANGEME)', 'placeholder'),

        # Template/variable patterns
        (r'\$\{[^}]+\}', 'template'),
        (r'\{\{[^}]+\}\}', 'template'),
        (r'%[A-Z_]+%', 'template'),
        (r'<[A-Z_]+>', 'template'),
        (r'__[A-Z_]+__', 'template'),

        # Common false positive strings
        (r'^[A-Za-z]{40,}$', 'all_letters'),  # Just letters, no numbers
        (r'^[0-9]{20,}$', 'all_numbers'),  # Just numbers
        (r'(.)\1{5,}', 'repeated_chars'),  # Repeated characters

        # Known binary/font data patterns
        (r'^eNp[A-Za-z0-9]', 'zlib_compressed'),  # zlib
        (r'^H4sI[A-Za-z0-9]', 'gzip_compressed'),  # gzip
        (r'^UEs[A-Za-z0-9]', 'zip_data'),  # ZIP
        (r'^AAAA[A-Za-z0-9]{20,}', 'font_data'),  # Common in fonts
        (r'^////[A-Za-z0-9]{20,}', 'binary_data'),  # Binary patterns

        # UUID patterns (not secrets)
        (r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', 'uuid'),

        # Common words that look like secrets
        (r'(?i)^(function|return|const|var|let|import|export|module)', 'js_keyword'),

        # Hash patterns (usually not secrets, but output)
        (r'^[a-f0-9]{32}$', 'md5_hash'),
        (r'^[a-f0-9]{40}$', 'sha1_hash'),
        (r'^[a-f0-9]{64}$', 'sha256_hash'),
    ]

    # Context patterns that indicate false positives
    FALSE_POSITIVE_CONTEXT = [
        (r'(?:example|sample|test|demo|placeholder|mock)[-_]?(?:key|token|secret|password|credential)', 'example_context'),
        (r'(?:your|my|the)[-_]?(?:api[-_]?key|token|secret)', 'placeholder_context'),
        (r'=\s*["\']?(?:example|test|demo|sample|placeholder)', 'example_value'),
    ]

    def __init__(self):
        """Initialize with compiled patterns."""
        self.value_patterns = [
            (re.compile(p), reason) for p, reason in self.FALSE_POSITIVE_PATTERNS
        ]
        self.context_patterns = [
            (re.compile(p), reason) for p, reason in self.FALSE_POSITIVE_CONTEXT
        ]
        self.entropy_analyzer = EntropyAnalyzer()

    def is_false_positive(
        self,
        value: str,
        context: str = "",
        source_type: str = ""
    ) -> tuple[bool, str]:
        """
        Check if a candidate is likely a false positive.

        Args:
            value: The potential secret value
            context: Surrounding context
            source_type: Type of source (js_file, config, etc.)

        Returns:
            Tuple of (is_false_positive, reason)
        """
        # Check value patterns
        for pattern, reason in self.value_patterns:
            if pattern.search(value):
                return True, f"Matches {reason} pattern"

        # Check context patterns
        if context:
            for pattern, reason in self.context_patterns:
                if pattern.search(context):
                    return True, f"Context indicates {reason}"

        # Entropy analysis
        entropy_result = self.entropy_analyzer.analyze(value)
        if not entropy_result.is_likely_secret:
            return True, f"Entropy: {entropy_result.reason}"

        return False, "Passed all checks"

    def get_confidence_adjustment(
        self,
        value: str,
        context: str = "",
        source_type: str = ""
    ) -> float:
        """
        Get confidence score adjustment based on false positive analysis.

        Returns:
            Adjustment value (-1.0 to 1.0)
        """
        is_fp, reason = self.is_false_positive(value, context, source_type)

        if is_fp:
            # Strong negative signals
            if 'placeholder' in reason or 'template' in reason:
                return -0.8
            elif 'compressed' in reason or 'binary' in reason:
                return -0.9
            elif 'Entropy' in reason:
                return -0.5
            else:
                return -0.3

        # Positive signals
        entropy_result = self.entropy_analyzer.analyze(value)

        adjustment = 0.0

        # High entropy is good
        if entropy_result.shannon_entropy > 4.5:
            adjustment += 0.2

        # Good charset diversity is good
        if entropy_result.charset_score > 0.7:
            adjustment += 0.1

        # Found in config file is good
        if source_type in ['config_file', 'dotenv', 'env']:
            adjustment += 0.2

        # Found with assignment context is good
        assignment_patterns = ['=', ':', 'key', 'secret', 'password', 'token']
        if any(p in context.lower() for p in assignment_patterns):
            adjustment += 0.1

        return min(0.5, adjustment)


class SecretValidator:
    """Validate that candidates match expected secret formats."""

    # Known secret formats with validation
    SECRET_FORMATS = {
        'aws_access_key': {
            'pattern': r'^(A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}$',
            'length': 20,
        },
        'aws_secret_key': {
            'pattern': r'^[A-Za-z0-9/+]{40}$',
            'length': 40,
            'charset': 'base64',
        },
        'github_pat': {
            'pattern': r'^ghp_[A-Za-z0-9]{36}$',
            'length': 40,
        },
        'github_fine_grained': {
            'pattern': r'^github_pat_[A-Za-z0-9_]{22,}$',
            'min_length': 40,
        },
        'stripe_secret': {
            'pattern': r'^sk_live_[A-Za-z0-9]{24,}$',
            'min_length': 32,
        },
        'slack_token': {
            'pattern': r'^xox[baprs]-[A-Za-z0-9\\-]+$',
            'min_length': 20,
        },
        'openai_key': {
            'pattern': r'^sk-[A-Za-z0-9]{20,}$',
            'min_length': 40,
        },
        'openai_project_key': {
            'pattern': r'^sk-proj-[A-Za-z0-9\\-_]{20,}$',
            'min_length': 40,
        },
    }

    def validate(self, value: str, secret_type: str) -> tuple[bool, float]:
        """
        Validate a secret matches expected format.

        Args:
            value: Secret value
            secret_type: Type of secret

        Returns:
            Tuple of (is_valid, confidence_boost)
        """
        format_spec = self.SECRET_FORMATS.get(secret_type)

        if not format_spec:
            # Unknown type, no validation
            return True, 0.0

        # Check pattern
        pattern = format_spec.get('pattern')
        if pattern and not re.match(pattern, value):
            return False, -0.5

        # Check length
        expected_length = format_spec.get('length')
        if expected_length and len(value) != expected_length:
            return False, -0.3

        min_length = format_spec.get('min_length')
        if min_length and len(value) < min_length:
            return False, -0.3

        # Valid format
        return True, 0.2
