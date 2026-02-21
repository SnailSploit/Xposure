"""DigitalOcean API token verifier for X-POSURE."""

from .base import BaseVerifier, VerificationResult
from ..core.models import Finding, VerificationStatus, Severity


class DigitalOceanVerifier(BaseVerifier):
    """Verifier for DigitalOcean API tokens using the account endpoint."""

    SUPPORTED_TYPES = [
        'digitalocean_token',
        'digitalocean_api_key',
        'do_token',
    ]

    def can_verify(self, finding: Finding) -> bool:
        """Check if this is a DigitalOcean credential."""
        return finding.credential_type in self.SUPPORTED_TYPES

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify DigitalOcean API token using the account endpoint.

        Args:
            finding: Finding with DigitalOcean API token

        Returns:
            Verification result with account info
        """
        token = finding.value

        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }

        success, data, error = await self.safe_request(
            method='GET',
            url='https://api.digitalocean.com/v2/account',
            headers=headers,
        )

        if not success:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='digitalocean_account_api',
                error=error or 'API token is invalid or expired',
            )

        # Extract account information (nested under 'account')
        account = data.get('account', data)
        email = account.get('email', 'Unknown')
        uuid = account.get('uuid', '')
        droplet_limit = account.get('droplet_limit', 0)
        floating_ip_limit = account.get('floating_ip_limit', 0)
        volume_limit = account.get('volume_limit', 0)
        email_verified = account.get('email_verified', False)
        account_status = account.get('status', 'unknown')
        team = account.get('team', {})

        # Build identity
        identity = email
        if team and isinstance(team, dict):
            team_name = team.get('name', '')
            if team_name:
                identity = f'{email} (Team: {team_name})'

        # Determine permissions
        permissions = [
            f'droplet_limit:{droplet_limit}',
            f'volume_limit:{volume_limit}',
            f'status:{account_status}',
        ]
        if email_verified:
            permissions.append('email_verified')
        if floating_ip_limit > 0:
            permissions.append(f'floating_ip_limit:{floating_ip_limit}')

        # Assess blast radius - DO tokens typically have full access
        is_production = account_status == 'active'
        blast_radius = self._assess_blast_radius(
            permissions=permissions,
            is_admin=True,  # DO API tokens grant full account access
            is_production=is_production,
        )

        # Pivot opportunities
        can_pivot_to = [
            'All droplets (VMs) and their configurations',
            'Database clusters and connection strings',
            'Kubernetes clusters',
            'Spaces (S3-compatible object storage)',
            'DNS records and domains',
            'SSH keys',
        ]
        if team:
            can_pivot_to.append('Team resources and members')

        return VerificationResult(
            status=VerificationStatus.VERIFIED,
            method='digitalocean_account_api',
            identity=identity,
            permissions=permissions,
            can_pivot_to=can_pivot_to,
            blast_radius=blast_radius,
            environment='production' if is_production else 'unknown',
            metadata={
                'email': email,
                'uuid': uuid,
                'droplet_limit': droplet_limit,
                'floating_ip_limit': floating_ip_limit,
                'volume_limit': volume_limit,
                'email_verified': email_verified,
                'status': account_status,
            },
        )
