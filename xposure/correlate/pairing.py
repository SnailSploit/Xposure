"""Credential pairing logic for X-POSURE."""

from typing import Optional

from ..core.models import Candidate


class CredentialPairer:
    """Pairs related credentials (key + secret, username + password)."""

    # Pairing rules: (type1, type2) -> max_distance
    PAIRING_RULES = {
        # AWS
        ('aws_access_key', 'aws_secret_key'): 500,
        ('aws_secret_key', 'aws_access_key'): 500,

        # Azure
        ('azure_client_id', 'azure_client_secret'): 500,
        ('azure_client_secret', 'azure_client_id'): 500,
        ('azure_tenant_id', 'azure_client_secret'): 500,

        # Twilio
        ('twilio_sid', 'twilio_key'): 500,
        ('twilio_key', 'twilio_sid'): 500,

        # Alibaba Cloud
        ('alibaba_access_key', 'alibaba_secret_key'): 500,
        ('alibaba_secret_key', 'alibaba_access_key'): 500,

        # DigitalOcean Spaces
        ('digitalocean_spaces_key', 'digitalocean_spaces_secret'): 500,

        # Generic patterns
        ('api_key', 'api_secret'): 300,
        ('access_key', 'secret_key'): 300,
        ('client_id', 'client_secret'): 300,
    }

    def __init__(self):
        """Initialize credential pairer."""
        self.candidates_by_source = {}
        self.pairs = []

    def add_candidate(self, candidate: Candidate):
        """
        Add a candidate for pairing consideration.

        Args:
            candidate: Candidate to add
        """
        source_key = self._get_source_key(candidate)

        if source_key not in self.candidates_by_source:
            self.candidates_by_source[source_key] = []

        self.candidates_by_source[source_key].append(candidate)

    def find_pairs(self) -> list[tuple[Candidate, Candidate]]:
        """
        Find all credential pairs.

        Returns:
            List of (candidate1, candidate2) tuples
        """
        pairs = []

        # For each source, try to pair candidates
        for source_key, candidates in self.candidates_by_source.items():
            for i, cand1 in enumerate(candidates):
                for j, cand2 in enumerate(candidates[i+1:], i+1):
                    if self._can_pair(cand1, cand2):
                        pairs.append((cand1, cand2))

        self.pairs = pairs
        return pairs

    def _can_pair(self, cand1: Candidate, cand2: Candidate) -> bool:
        """
        Check if two candidates can be paired.

        Args:
            cand1: First candidate
            cand2: Second candidate

        Returns:
            True if they can be paired
        """
        # Check pairing rules
        pair_key = (cand1.type, cand2.type)

        if pair_key not in self.PAIRING_RULES:
            return False

        max_distance = self.PAIRING_RULES[pair_key]

        # Check if they're from the same source
        if cand1.source.url != cand2.source.url:
            return False

        # Check proximity in context
        # If we have line numbers, use those
        if cand1.source.line and cand2.source.line:
            line_distance = abs(cand1.source.line - cand2.source.line)
            return line_distance <= max_distance

        # Otherwise, check if they appear in each other's context
        if cand1.value in cand2.context or cand2.value in cand1.context:
            return True

        # Check if contexts overlap
        if self._contexts_overlap(cand1.context, cand2.context):
            return True

        return False

    def _contexts_overlap(self, ctx1: str, ctx2: str) -> bool:
        """
        Check if two contexts have significant overlap.

        Args:
            ctx1: First context
            ctx2: Second context

        Returns:
            True if contexts overlap
        """
        if not ctx1 or not ctx2:
            return False

        # Simple overlap check: if >30% of characters match
        min_len = min(len(ctx1), len(ctx2))
        if min_len == 0:
            return False

        # Check for substring
        if ctx1 in ctx2 or ctx2 in ctx1:
            return True

        return False

    def _get_source_key(self, candidate: Candidate) -> str:
        """
        Get a unique key for the candidate's source.

        Args:
            candidate: Candidate

        Returns:
            Source key string
        """
        return f"{candidate.source.type}:{candidate.source.url}"

    def link_pair(self, cand1: Candidate, cand2: Candidate):
        """
        Link two candidates as a pair.

        Args:
            cand1: First candidate
            cand2: Second candidate
        """
        cand1.paired_with = cand2
        cand2.paired_with = cand1

    def get_pairs_for_candidate(self, candidate: Candidate) -> list[Candidate]:
        """
        Get all paired candidates for a given candidate.

        Args:
            candidate: Candidate to find pairs for

        Returns:
            List of paired candidates
        """
        paired = []

        for pair in self.pairs:
            if pair[0] == candidate:
                paired.append(pair[1])
            elif pair[1] == candidate:
                paired.append(pair[0])

        return paired

    def get_stats(self) -> dict:
        """
        Get pairing statistics.

        Returns:
            Statistics dictionary
        """
        total_candidates = sum(len(candidates) for candidates in self.candidates_by_source.values())

        paired_candidates = set()
        for pair in self.pairs:
            paired_candidates.add(id(pair[0]))
            paired_candidates.add(id(pair[1]))

        return {
            'total_candidates': total_candidates,
            'paired_candidates': len(paired_candidates),
            'total_pairs': len(self.pairs),
            'sources': len(self.candidates_by_source),
        }


def pair_candidates(candidates: list[Candidate]) -> list[tuple[Candidate, Candidate]]:
    """
    Convenience function to pair a list of candidates.

    Args:
        candidates: List of candidates to pair

    Returns:
        List of (candidate1, candidate2) tuples
    """
    pairer = CredentialPairer()

    for candidate in candidates:
        pairer.add_candidate(candidate)

    pairs = pairer.find_pairs()

    # Link the pairs
    for cand1, cand2 in pairs:
        pairer.link_pair(cand1, cand2)

    return pairs
