"""Verifier coordinator for X-POSURE."""

import asyncio
from typing import List, Optional

from .base import BaseVerifier, PassiveVerifier, VerificationResult
from .aws import AWSVerifier
from .github import GitHubVerifier
from .slack import SlackVerifier
from .stripe import StripeVerifier
from .openai import OpenAIVerifier
from .gcp import GCPVerifier
from .azure import AzureVerifier
from ..core.models import Finding, VerificationStatus


class VerifierCoordinator:
    """Coordinates verification across all verifiers."""

    def __init__(
        self,
        timeout: int = 10,
        max_concurrent: int = 5,
        passive_only: bool = False,
    ):
        """
        Initialize verifier coordinator.

        Args:
            timeout: Request timeout in seconds
            max_concurrent: Max concurrent verification requests
            passive_only: Only perform passive verification
        """
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.passive_only = passive_only

        # Initialize verifiers
        self.passive_verifier = PassiveVerifier()

        # Active verifiers
        self.active_verifiers: List[BaseVerifier] = [
            AWSVerifier(timeout=timeout),
            GitHubVerifier(timeout=timeout),
            SlackVerifier(timeout=timeout),
            StripeVerifier(timeout=timeout),
            OpenAIVerifier(timeout=timeout),
            GCPVerifier(timeout=timeout),
            AzureVerifier(timeout=timeout),
        ]

        # Statistics
        self.stats = {
            'total_verified': 0,
            'verified': 0,
            'invalid': 0,
            'errors': 0,
            'unverified': 0,
        }

    async def verify_finding(self, finding: Finding) -> VerificationResult:
        """
        Verify a single finding.

        Args:
            finding: Finding to verify

        Returns:
            Verification result
        """
        # Always try passive verification first
        passive_result = self.passive_verifier.passive_verify(finding)

        # If passive-only mode, return passive result
        if self.passive_only:
            return passive_result

        # Find appropriate active verifier
        verifier = self._get_verifier(finding)

        if not verifier:
            # No active verifier available, return passive result
            return passive_result

        # Perform active verification
        try:
            async with verifier:
                result = await verifier.verify(finding)
                self._update_stats(result.status)
                return result

        except Exception as e:
            # Verification failed, return error result
            result = VerificationResult(
                status=VerificationStatus.ERROR,
                method='unknown',
                error=f'Verification error: {str(e)}',
            )
            self._update_stats(result.status)
            return result

    async def verify_findings(self, findings: List[Finding]) -> List[tuple[Finding, VerificationResult]]:
        """
        Verify multiple findings concurrently.

        Args:
            findings: List of findings to verify

        Returns:
            List of (finding, verification_result) tuples
        """
        # Use semaphore to limit concurrency
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def verify_with_semaphore(finding: Finding) -> tuple[Finding, VerificationResult]:
            async with semaphore:
                result = await self.verify_finding(finding)
                return finding, result

        # Verify all findings concurrently
        tasks = [verify_with_semaphore(finding) for finding in findings]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions
        verified_results = []
        for result in results:
            if isinstance(result, tuple):
                verified_results.append(result)
            else:
                # Exception occurred, create error result
                # We don't know which finding this was for, so skip it
                pass

        return verified_results

    def _get_verifier(self, finding: Finding) -> Optional[BaseVerifier]:
        """
        Get appropriate verifier for a finding.

        Args:
            finding: Finding to verify

        Returns:
            Verifier instance or None
        """
        for verifier in self.active_verifiers:
            if verifier.can_verify(finding):
                return verifier

        return None

    def _update_stats(self, status: VerificationStatus):
        """
        Update verification statistics.

        Args:
            status: Verification status
        """
        self.stats['total_verified'] += 1

        if status == VerificationStatus.VERIFIED:
            self.stats['verified'] += 1
        elif status == VerificationStatus.INVALID:
            self.stats['invalid'] += 1
        elif status == VerificationStatus.ERROR:
            self.stats['errors'] += 1
        else:
            self.stats['unverified'] += 1

    def get_stats(self) -> dict:
        """
        Get verification statistics.

        Returns:
            Statistics dictionary
        """
        return self.stats.copy()

    def get_supported_types(self) -> List[str]:
        """
        Get list of all supported credential types.

        Returns:
            List of credential type strings
        """
        supported = set()

        for verifier in self.active_verifiers:
            if hasattr(verifier, 'SUPPORTED_TYPES'):
                supported.update(verifier.SUPPORTED_TYPES)

        return sorted(list(supported))


async def verify_finding(finding: Finding, passive_only: bool = False) -> VerificationResult:
    """
    Convenience function to verify a single finding.

    Args:
        finding: Finding to verify
        passive_only: Only perform passive verification

    Returns:
        Verification result
    """
    coordinator = VerifierCoordinator(passive_only=passive_only)
    return await coordinator.verify_finding(finding)
