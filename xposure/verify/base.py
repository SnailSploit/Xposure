"""Base verifier interface for X-POSURE."""

import asyncio
import aiohttp
from abc import ABC, abstractmethod
from typing import Optional, Dict, List
from dataclasses import dataclass, field

from ..core.models import Finding, VerificationStatus, Severity


@dataclass
class VerificationResult:
    """Result of credential verification."""

    status: VerificationStatus
    method: str
    identity: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    can_pivot_to: List[str] = field(default_factory=list)
    blast_radius: Severity = Severity.MEDIUM
    environment: Optional[str] = None
    metadata: Dict = field(default_factory=dict)
    error: Optional[str] = None


class BaseVerifier(ABC):
    """Base class for credential verifiers."""

    def __init__(self, timeout: int = 10):
        """
        Initialize verifier.

        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        """Async context manager entry."""
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()

    @abstractmethod
    def can_verify(self, finding: Finding) -> bool:
        """
        Check if this verifier can handle the finding.

        Args:
            finding: Finding to check

        Returns:
            True if verifier supports this credential type
        """
        raise NotImplementedError

    @abstractmethod
    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify a credential.

        Args:
            finding: Finding to verify

        Returns:
            Verification result
        """
        raise NotImplementedError

    def passive_verify(self, finding: Finding) -> VerificationResult:
        """
        Passive verification (format checks, checksums).

        Args:
            finding: Finding to verify

        Returns:
            Verification result
        """
        # Default implementation - override for specific checks
        return VerificationResult(
            status=VerificationStatus.UNVERIFIED,
            method='passive',
            metadata={'note': 'No passive checks implemented'},
        )

    async def safe_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict] = None,
        json: Optional[Dict] = None,
        data: Optional[Dict] = None,
    ) -> tuple[bool, Optional[Dict], Optional[str]]:
        """
        Make a safe API request with error handling.

        Args:
            method: HTTP method
            url: Request URL
            headers: Optional headers
            json: Optional JSON body
            data: Optional form data

        Returns:
            Tuple of (success, response_data, error_message)
        """
        if not self.session:
            return False, None, "Session not initialized"

        try:
            async with self.session.request(
                method=method,
                url=url,
                headers=headers,
                json=json,
                data=data,
            ) as response:
                # Success status codes
                if 200 <= response.status < 300:
                    try:
                        data = await response.json()
                        return True, data, None
                    except Exception:
                        # Non-JSON response but still successful
                        text = await response.text()
                        return True, {'response': text}, None

                # Authentication failures
                elif response.status in [401, 403]:
                    return False, None, f"Authentication failed (HTTP {response.status})"

                # Rate limiting
                elif response.status == 429:
                    return False, None, "Rate limit exceeded"

                # Other errors
                else:
                    text = await response.text()
                    return False, None, f"HTTP {response.status}: {text[:100]}"

        except asyncio.TimeoutError:
            return False, None, "Request timeout"
        except aiohttp.ClientError as e:
            return False, None, f"Network error: {str(e)}"
        except Exception as e:
            return False, None, f"Unexpected error: {str(e)}"

    def _assess_blast_radius(
        self,
        permissions: List[str],
        is_admin: bool = False,
        is_production: bool = False,
    ) -> Severity:
        """
        Assess blast radius based on permissions and environment.

        Args:
            permissions: List of permissions
            is_admin: Whether credential has admin access
            is_production: Whether in production environment

        Returns:
            Severity level
        """
        # Admin in production = critical
        if is_admin and is_production:
            return Severity.CRITICAL

        # Admin anywhere = high
        if is_admin:
            return Severity.HIGH

        # Production with write access = high
        if is_production and any('write' in p.lower() or 'delete' in p.lower() for p in permissions):
            return Severity.HIGH

        # Production read-only = medium
        if is_production:
            return Severity.MEDIUM

        # Non-production with write = medium
        if any('write' in p.lower() or 'delete' in p.lower() for p in permissions):
            return Severity.MEDIUM

        # Read-only, non-production = low
        return Severity.LOW


class PassiveVerifier(BaseVerifier):
    """Passive verification using format checks and patterns."""

    def __init__(self):
        """Initialize passive verifier."""
        super().__init__(timeout=0)  # No network requests

    def can_verify(self, finding: Finding) -> bool:
        """All findings can be passively verified."""
        return True

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Perform passive verification.

        Args:
            finding: Finding to verify

        Returns:
            Verification result
        """
        return self.passive_verify(finding)

    def passive_verify(self, finding: Finding) -> VerificationResult:
        """
        Check credential format and structure.

        Args:
            finding: Finding to verify

        Returns:
            Verification result
        """
        cred_type = finding.credential_type
        value = finding.value

        # AWS Access Key checks
        if cred_type == 'aws_access_key':
            if self._check_aws_access_key_format(value):
                return VerificationResult(
                    status=VerificationStatus.LIKELY_VALID,
                    method='passive_format',
                    metadata={'format': 'valid', 'note': 'Matches AWS access key pattern'},
                )

        # GitHub token checks
        elif cred_type == 'github_token':
            if self._check_github_token_format(value):
                token_type = self._get_github_token_type(value)
                return VerificationResult(
                    status=VerificationStatus.LIKELY_VALID,
                    method='passive_format',
                    metadata={'format': 'valid', 'token_type': token_type},
                )

        # Stripe key checks
        elif 'stripe' in cred_type:
            if self._check_stripe_key_format(value):
                is_live = value.startswith('sk_live_') or value.startswith('pk_live_')
                return VerificationResult(
                    status=VerificationStatus.LIKELY_VALID,
                    method='passive_format',
                    environment='production' if is_live else 'test',
                    metadata={'format': 'valid', 'live_mode': is_live},
                )

        # OpenAI key checks
        elif cred_type == 'openai_key':
            if value.startswith('sk-') or value.startswith('sk-proj-'):
                is_project = value.startswith('sk-proj-')
                return VerificationResult(
                    status=VerificationStatus.LIKELY_VALID,
                    method='passive_format',
                    metadata={'format': 'valid', 'project_key': is_project},
                )

        # Default: format unknown
        return VerificationResult(
            status=VerificationStatus.UNVERIFIED,
            method='passive_format',
            metadata={'format': 'unknown', 'note': 'No format checks for this type'},
        )

    def _check_aws_access_key_format(self, value: str) -> bool:
        """Check if value matches AWS access key format."""
        if len(value) != 20:
            return False

        # Should start with AKIA, ASIA, ABIA, or ACCA
        if not any(value.startswith(prefix) for prefix in ['AKIA', 'ASIA', 'ABIA', 'ACCA']):
            return False

        # Should be alphanumeric uppercase
        return value.isalnum() and value.isupper()

    def _check_github_token_format(self, value: str) -> bool:
        """Check if value matches GitHub token format."""
        # GitHub tokens have specific prefixes and lengths
        valid_prefixes = ['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_']

        for prefix in valid_prefixes:
            if value.startswith(prefix):
                # Remove prefix and check remaining length
                remaining = value[len(prefix):]
                return len(remaining) >= 36

        return False

    def _get_github_token_type(self, value: str) -> str:
        """Get GitHub token type from prefix."""
        if value.startswith('ghp_'):
            return 'Personal Access Token'
        elif value.startswith('gho_'):
            return 'OAuth Access Token'
        elif value.startswith('ghu_'):
            return 'User-to-Server Token'
        elif value.startswith('ghs_'):
            return 'Server-to-Server Token'
        elif value.startswith('ghr_'):
            return 'Refresh Token'
        return 'Unknown'

    def _check_stripe_key_format(self, value: str) -> bool:
        """Check if value matches Stripe key format."""
        # Stripe keys have specific prefixes
        valid_prefixes = [
            'sk_live_', 'sk_test_',  # Secret keys
            'pk_live_', 'pk_test_',  # Publishable keys
            'rk_live_', 'rk_test_',  # Restricted keys
        ]

        return any(value.startswith(prefix) for prefix in valid_prefixes)
