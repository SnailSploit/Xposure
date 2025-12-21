"""Advanced deduplication for X-POSURE."""

import hashlib
from typing import Optional

from ..core.models import Candidate, Finding


class Deduplicator:
    """Advanced deduplication with multi-source evidence tracking."""

    def __init__(self):
        """Initialize deduplicator."""
        self.seen_hashes = {}  # hash -> Finding
        self.value_type_map = {}  # (value, type) -> Finding

    def add_or_merge(self, candidate: Candidate) -> tuple[Finding, bool]:
        """
        Add candidate or merge with existing finding.

        Args:
            candidate: Candidate to add

        Returns:
            Tuple of (Finding, is_new)
            - Finding: The finding (new or existing)
            - is_new: True if this is a new finding, False if merged
        """
        # Create hash key
        hash_key = self._create_hash(candidate.value, candidate.type)

        # Check if we've seen this before
        if hash_key in self.seen_hashes:
            # Merge with existing finding
            finding = self.seen_hashes[hash_key]
            self._merge_candidate(finding, candidate)
            return finding, False

        # Create new finding
        finding = self._create_finding(candidate)
        self.seen_hashes[hash_key] = finding
        self.value_type_map[(candidate.value, candidate.type)] = finding

        return finding, True

    def _create_hash(self, value: str, credential_type: str) -> str:
        """
        Create hash for deduplication.

        Args:
            value: Credential value
            credential_type: Type of credential

        Returns:
            Hash string
        """
        key = f"{credential_type}:{value}"
        return hashlib.sha256(key.encode()).hexdigest()

    def _create_finding(self, candidate: Candidate) -> Finding:
        """
        Create a new finding from a candidate.

        Args:
            candidate: Candidate to convert

        Returns:
            New Finding
        """
        # Generate ID
        finding_id = hashlib.md5(f"{candidate.type}:{candidate.value}".encode()).hexdigest()[:8]

        # Mask value for display
        masked_value = self._mask_value(candidate.value)

        finding = Finding(
            id=finding_id,
            credential_type=candidate.type,
            value=candidate.value,
            masked_value=masked_value,
            sources=[candidate.source],
            confidence=candidate.confidence,
            confidence_factors=[],
            entropy=candidate.entropy,
            severity=candidate.severity,
            metadata=candidate.metadata.copy() if candidate.metadata else {},
        )

        # Preserve rule metadata and remediation guidance
        if candidate.rule_id or candidate.rule_name:
            finding.metadata.setdefault("rule", {})
            if candidate.rule_id:
                finding.metadata["rule"]["id"] = candidate.rule_id
            if candidate.rule_name:
                finding.metadata["rule"]["name"] = candidate.rule_name

        if candidate.remediation:
            finding.remediation = candidate.remediation

        if candidate.verifier:
            finding.metadata.setdefault("verification", {})
            finding.metadata["verification"].setdefault("suggested_verifier", candidate.verifier)

        return finding

    def _merge_candidate(self, finding: Finding, candidate: Candidate):
        """
        Merge a candidate into an existing finding.

        Args:
            finding: Existing finding
            candidate: New candidate to merge
        """
        # Add source if not already present
        if candidate.source not in finding.sources:
            finding.add_source(candidate.source)

            # Increase confidence when seen in multiple places
            confidence_boost = 0.1 * len(finding.sources)
            finding.update_confidence(
                min(confidence_boost, 0.3),
                f"seen in {len(finding.sources)} sources"
            )

        # Merge severity if existing finding lacks it
        if not finding.severity and candidate.severity:
            finding.severity = candidate.severity

        # Merge metadata (rule/provider info)
        if candidate.metadata:
            finding.metadata.update({k: v for k, v in candidate.metadata.items() if k not in finding.metadata})

        if candidate.rule_id or candidate.rule_name:
            finding.metadata.setdefault("rule", {})
            if candidate.rule_id:
                finding.metadata["rule"].setdefault("id", candidate.rule_id)
            if candidate.rule_name:
                finding.metadata["rule"].setdefault("name", candidate.rule_name)

        if candidate.remediation and not finding.remediation:
            finding.remediation = candidate.remediation

    def _mask_value(self, value: str, visible: int = 8) -> str:
        """
        Mask credential value for safe display.

        Args:
            value: Value to mask
            visible: Number of visible characters

        Returns:
            Masked value
        """
        if len(value) <= visible:
            return "•" * len(value)

        return value[:visible] + "•" * (len(value) - visible)

    def get_finding(self, value: str, credential_type: str) -> Optional[Finding]:
        """
        Get finding for a specific value and type.

        Args:
            value: Credential value
            credential_type: Type of credential

        Returns:
            Finding or None
        """
        return self.value_type_map.get((value, credential_type))

    def get_all_findings(self) -> list[Finding]:
        """
        Get all findings.

        Returns:
            List of all findings
        """
        return list(self.seen_hashes.values())

    def get_stats(self) -> dict:
        """
        Get deduplication statistics.

        Returns:
            Statistics dictionary
        """
        findings = self.get_all_findings()

        total_sources = sum(len(f.sources) for f in findings)
        multi_source = sum(1 for f in findings if len(f.sources) > 1)

        return {
            'unique_findings': len(findings),
            'total_sources': total_sources,
            'multi_source_findings': multi_source,
            'avg_sources_per_finding': total_sources / len(findings) if findings else 0,
        }


def deduplicate_candidates(candidates: list[Candidate]) -> list[Finding]:
    """
    Convenience function to deduplicate candidates.

    Args:
        candidates: List of candidates

    Returns:
        List of unique findings
    """
    dedup = Deduplicator()

    for candidate in candidates:
        dedup.add_or_merge(candidate)

    return dedup.get_all_findings()
