"""Multi-factor confidence scoring for X-POSURE."""

import math
from typing import Optional

from ..core.models import Finding, Severity


class ConfidenceScorer:
    """Multi-factor confidence scoring system."""

    # Entropy thresholds
    ENTROPY_LOW = 3.0
    ENTROPY_MEDIUM = 4.0
    ENTROPY_HIGH = 5.0

    # Severity weights
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 1.0,
        Severity.HIGH: 0.8,
        Severity.MEDIUM: 0.6,
        Severity.LOW: 0.4,
        Severity.INFO: 0.2,
    }

    # Provider trust levels
    PROVIDER_TRUST = {
        # High-value targets
        'aws': 1.0,
        'gcp': 1.0,
        'azure': 1.0,
        'github': 1.0,
        'stripe': 1.0,
        'openai': 0.9,
        'anthropic': 0.9,

        # Medium-value
        'slack': 0.8,
        'sendgrid': 0.8,
        'twilio': 0.8,
        'mongodb': 0.8,

        # Lower-value but still relevant
        'discord': 0.6,
        'telegram': 0.6,

        # Default
        'unknown': 0.5,
    }

    def __init__(self):
        """Initialize confidence scorer."""
        self.score_cache = {}  # finding_id -> score

    def calculate_score(
        self,
        finding: Finding,
        is_paired: bool = False,
        context_quality: float = 0.5,
    ) -> float:
        """
        Calculate comprehensive confidence score.

        Args:
            finding: Finding to score
            is_paired: Whether finding is part of a credential pair
            context_quality: Quality of surrounding context (0.0-1.0)

        Returns:
            Confidence score (0.0-1.0)
        """
        # Start with base confidence
        score = finding.confidence

        # Factor 1: Entropy bonus
        entropy_bonus = self._score_entropy(finding.entropy)
        score += entropy_bonus

        # Factor 2: Multi-source bonus
        source_bonus = self._score_sources(finding.sources)
        score += source_bonus

        # Factor 3: Context quality
        context_bonus = self._score_context(context_quality)
        score += context_bonus

        # Factor 4: Pairing bonus
        if is_paired:
            score += 0.15

        # Factor 5: Severity weight
        severity_weight = self.SEVERITY_WEIGHTS.get(
            finding.severity,
            self.SEVERITY_WEIGHTS[Severity.INFO]
        )
        score *= severity_weight

        # Factor 6: Provider trust
        provider_trust = self._get_provider_trust(finding.metadata)
        score *= provider_trust

        # Normalize to 0.0-1.0
        score = max(0.0, min(1.0, score))

        # Cache the score
        self.score_cache[finding.id] = score

        return score

    def _score_entropy(self, entropy: float) -> float:
        """
        Score based on entropy level.

        Args:
            entropy: Entropy value

        Returns:
            Entropy bonus (0.0-0.2)
        """
        if entropy >= self.ENTROPY_HIGH:
            return 0.2
        elif entropy >= self.ENTROPY_MEDIUM:
            return 0.1
        elif entropy >= self.ENTROPY_LOW:
            return 0.05
        else:
            return 0.0

    def _score_sources(self, sources: list) -> float:
        """
        Score based on number of sources.

        Args:
            sources: List of sources

        Returns:
            Source bonus (0.0-0.25)
        """
        num_sources = len(sources)

        if num_sources >= 5:
            return 0.25
        elif num_sources >= 3:
            return 0.15
        elif num_sources >= 2:
            return 0.10
        else:
            return 0.0

    def _score_context(self, context_quality: float) -> float:
        """
        Score based on context quality.

        Args:
            context_quality: Context quality score (0.0-1.0)

        Returns:
            Context bonus (0.0-0.15)
        """
        return context_quality * 0.15

    def _get_provider_trust(self, metadata: dict) -> float:
        """
        Get provider trust multiplier.

        Args:
            metadata: Finding metadata

        Returns:
            Trust multiplier (0.0-1.0)
        """
        provider = metadata.get('provider', 'unknown')
        return self.PROVIDER_TRUST.get(provider, self.PROVIDER_TRUST['unknown'])

    def analyze_context_quality(self, content: str, position: int, value: str) -> float:
        """
        Analyze context quality around a finding.

        Args:
            content: Full content where finding was discovered
            position: Position of finding in content
            value: The credential value

        Returns:
            Context quality score (0.0-1.0)
        """
        # Extract context window
        context_size = 200
        start = max(0, position - context_size)
        end = min(len(content), position + len(value) + context_size)
        context = content[start:end].lower()

        score = 0.5  # Base score

        # Positive indicators
        positive_keywords = [
            'key', 'token', 'secret', 'password', 'credential',
            'auth', 'api', 'access', 'private', 'config',
            'env', 'production', 'prod', 'live'
        ]

        # Negative indicators
        negative_keywords = [
            'example', 'test', 'demo', 'sample', 'placeholder',
            'fake', 'mock', 'dummy', 'xxx', 'todo'
        ]

        # Check positive keywords
        positive_count = sum(1 for kw in positive_keywords if kw in context)
        score += min(0.3, positive_count * 0.05)

        # Check negative keywords
        negative_count = sum(1 for kw in negative_keywords if kw in context)
        score -= min(0.4, negative_count * 0.1)

        # Assignment pattern bonus
        if any(pattern in context for pattern in ['=', ':', '->']):
            score += 0.1

        # Variable name pattern bonus
        if any(c.isupper() for c in context[:50]):  # ALL_CAPS variable names
            score += 0.05

        return max(0.0, min(1.0, score))

    def analyze_snippet_context(self, context: str) -> float:
        """
        Score a small snippet of context without requiring exact positions.

        This is useful when only a trimmed context window is available (e.g. regex
        matches). The scoring uses the same keyword heuristics as analyze_context_quality
        but is resilient to missing positional information.
        """
        if not context:
            return 0.0

        lowered = context.lower()
        score = 0.4  # baseline for having any context

        positive_keywords = [
            'key', 'token', 'secret', 'password', 'credential',
            'auth', 'api', 'access', 'private', 'config',
            'env', 'production', 'prod', 'live', 'client_id',
            'client_secret', 'aws', 'gcp', 'azure', 'slack',
            'stripe', 'github', 'gitlab'
        ]
        negative_keywords = [
            'example', 'test', 'demo', 'sample', 'placeholder',
            'fake', 'mock', 'dummy', 'xxx', 'todo', 'spec'
        ]

        positive_hits = sum(1 for kw in positive_keywords if kw in lowered)
        negative_hits = sum(1 for kw in negative_keywords if kw in lowered)

        score += min(0.35, positive_hits * 0.05)
        score -= min(0.35, negative_hits * 0.08)

        if any(token in lowered for token in ['=', ':', '->', '"', "'"]):
            score += 0.1

        if any(fragment.isupper() and len(fragment) > 3 for fragment in lowered.split()):
            score += 0.05

        return max(0.0, min(1.0, score))

    def get_confidence_level(self, score: float) -> str:
        """
        Get human-readable confidence level.

        Args:
            score: Confidence score

        Returns:
            Confidence level string
        """
        if score >= 0.9:
            return "VERY HIGH"
        elif score >= 0.75:
            return "HIGH"
        elif score >= 0.6:
            return "MEDIUM"
        elif score >= 0.4:
            return "LOW"
        else:
            return "VERY LOW"

    def get_stats(self) -> dict:
        """
        Get scoring statistics.

        Returns:
            Statistics dictionary
        """
        if not self.score_cache:
            return {
                'total_scored': 0,
                'avg_score': 0.0,
                'high_confidence': 0,
                'low_confidence': 0,
            }

        scores = list(self.score_cache.values())

        return {
            'total_scored': len(scores),
            'avg_score': sum(scores) / len(scores),
            'min_score': min(scores),
            'max_score': max(scores),
            'high_confidence': sum(1 for s in scores if s >= 0.75),
            'medium_confidence': sum(1 for s in scores if 0.4 <= s < 0.75),
            'low_confidence': sum(1 for s in scores if s < 0.4),
        }


def score_finding(
    finding: Finding,
    is_paired: bool = False,
    context_quality: float = 0.5,
) -> float:
    """
    Convenience function to score a finding.

    Args:
        finding: Finding to score
        is_paired: Whether finding is part of a pair
        context_quality: Context quality score

    Returns:
        Confidence score
    """
    scorer = ConfidenceScorer()
    return scorer.calculate_score(finding, is_paired, context_quality)
