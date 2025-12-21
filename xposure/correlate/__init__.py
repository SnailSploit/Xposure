"""Correlation module for X-POSURE."""

from .dedup import Deduplicator, deduplicate_candidates
from .pairing import CredentialPairer, pair_candidates
from .confidence import ConfidenceScorer, score_finding

__all__ = [
    'Deduplicator',
    'deduplicate_candidates',
    'CredentialPairer',
    'pair_candidates',
    'ConfidenceScorer',
    'score_finding',
]
