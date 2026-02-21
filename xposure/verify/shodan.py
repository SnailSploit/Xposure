"""Shodan API key verifier for X-POSURE."""

from .base import BaseVerifier, VerificationResult
from ..core.models import Finding, VerificationStatus, Severity


class ShodanVerifier(BaseVerifier):
    """Verifier for Shodan API keys using the api-info endpoint."""

    SUPPORTED_TYPES = [
        'shodan_api_key',
        'shodan_key',
    ]

    def can_verify(self, finding: Finding) -> bool:
        """Check if this is a Shodan credential."""
        return finding.credential_type in self.SUPPORTED_TYPES

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify Shodan API key using the api-info endpoint.

        Args:
            finding: Finding with Shodan API key

        Returns:
            Verification result with account info and usage limits
        """
        api_key = finding.value

        success, data, error = await self.safe_request(
            method='GET',
            url=f'https://api.shodan.io/api-info?key={api_key}',
        )

        if not success:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='shodan_api_info',
                error=error or 'API key is invalid or expired',
            )

        # Extract account information
        plan = data.get('plan', 'unknown')
        query_credits = data.get('query_credits', 0)
        scan_credits = data.get('scan_credits', 0)
        monitored_ips = data.get('monitored_ips', 0)
        unlocked = data.get('unlocked', False)
        telnet = data.get('telnet', False)
        https = data.get('https', False)

        # Build identity
        identity = f'Shodan ({plan} plan)'

        # Determine permissions based on plan and features
        permissions = []
        if query_credits > 0:
            permissions.append(f'query_credits:{query_credits}')
        if scan_credits > 0:
            permissions.append(f'scan_credits:{scan_credits}')
        if unlocked:
            permissions.append('unlocked_api')
        if telnet:
            permissions.append('telnet_access')
        if https:
            permissions.append('https_access')
        if monitored_ips > 0:
            permissions.append(f'monitored_ips:{monitored_ips}')

        # Assess blast radius
        is_admin = plan in ['edu', 'corp', 'enterprise']
        is_production = unlocked or scan_credits > 0
        blast_radius = self._assess_blast_radius(
            permissions=permissions,
            is_admin=is_admin,
            is_production=is_production,
        )

        # Pivot opportunities
        can_pivot_to = ['Internet-wide host search and enumeration']
        if scan_credits > 0:
            can_pivot_to.append('On-demand network scanning')
        if unlocked:
            can_pivot_to.append('Unlocked API access (full results)')
        if monitored_ips > 0:
            can_pivot_to.append(f'Monitoring {monitored_ips} IPs')

        return VerificationResult(
            status=VerificationStatus.VERIFIED,
            method='shodan_api_info',
            identity=identity,
            permissions=permissions,
            can_pivot_to=can_pivot_to,
            blast_radius=blast_radius,
            environment='production',
            metadata={
                'plan': plan,
                'query_credits': query_credits,
                'scan_credits': scan_credits,
                'monitored_ips': monitored_ips,
                'unlocked': unlocked,
                'telnet': telnet,
                'https': https,
            },
        )
