"""Rule matching engine for X-POSURE."""

from typing import Generator, Optional

from ..core.models import Candidate, Source
from .loader import Rule, RuleLoader


class RuleEngine:
    """Engine for matching content against rules."""

    def __init__(self, rules_dir: Optional[str] = None):
        """
        Initialize rule engine.

        Args:
            rules_dir: Directory containing rule files
        """
        self.loader = RuleLoader(rules_dir)
        self.loader.load_all()

    def scan(self, content: str, source: Source) -> Generator[Candidate, None, None]:
        """
        Scan content with all rules.

        Args:
            content: Content to scan
            source: Source information

        Yields:
            Candidate objects for matches
        """
        matches = self.loader.match_all(content)

        for match in matches:
            # Calculate entropy
            entropy = self._calculate_entropy(match['value'])

            # Create candidate
            candidate = Candidate(
                type=match['type'],
                value=match['value'],
                source=source,
                entropy=entropy,
                context=match['context'],
                confidence=self._calculate_confidence(match, entropy),
            )

            # Store additional metadata
            if match.get('metadata'):
                candidate.source.raw_context = str(match.get('metadata'))

            yield candidate

    def scan_with_rule(self, content: str, rule: Rule, source: Source) -> Generator[Candidate, None, None]:
        """
        Scan content with a specific rule.

        Args:
            content: Content to scan
            rule: Rule to use
            source: Source information

        Yields:
            Candidate objects for matches
        """
        matches = rule.match(content)

        for match in matches:
            entropy = self._calculate_entropy(match['value'])

            candidate = Candidate(
                type=match['type'],
                value=match['value'],
                source=source,
                entropy=entropy,
                context=match['context'],
                confidence=self._calculate_confidence(match, entropy),
            )

            yield candidate

    def get_paired_rules(self, rule_id: str) -> list[Rule]:
        """
        Get rules that should be paired with this rule.

        Args:
            rule_id: Rule ID to find pairs for

        Returns:
            List of paired rules
        """
        rule = self.loader.get_rule(rule_id)
        if not rule or not rule.pair_with:
            return []

        paired_rules = []
        for pair_type in rule.pair_with:
            # Try to find rule by type
            rules = self.loader.get_rules_by_type(pair_type)
            paired_rules.extend(rules)

        return paired_rules

    def _calculate_entropy(self, s: str) -> float:
        """
        Calculate Shannon entropy.

        Args:
            s: String to analyze

        Returns:
            Entropy value
        """
        if not s:
            return 0.0

        import math

        prob = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in prob if p > 0)

    def _calculate_confidence(self, match: dict, entropy: float) -> float:
        """
        Calculate confidence score for a match.

        Args:
            match: Match dictionary
            entropy: Calculated entropy

        Returns:
            Confidence score (0.0-1.0)
        """
        # Base confidence by severity
        severity_scores = {
            'critical': 0.9,
            'high': 0.8,
            'medium': 0.6,
            'low': 0.4,
            'info': 0.2,
        }

        base = severity_scores.get(match['severity'], 0.5)

        # Adjust for entropy
        if entropy > 4.5:
            base += 0.1
        elif entropy < 3.0:
            base -= 0.2

        # Adjust for verifier presence
        if match.get('verifier'):
            base += 0.1

        return max(0.0, min(1.0, base))

    def get_stats(self) -> dict:
        """
        Get statistics about loaded rules.

        Returns:
            Statistics dictionary
        """
        rule_types = {}
        severities = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

        for rule in self.loader.rules:
            # Count by type
            if rule.type not in rule_types:
                rule_types[rule.type] = 0
            rule_types[rule.type] += 1

            # Count by severity
            if rule.severity in severities:
                severities[rule.severity] += 1

        return {
            'total_rules': len(self.loader),
            'rule_types': rule_types,
            'severities': severities,
        }

    def __repr__(self):
        return f"RuleEngine(rules={len(self.loader)})"
