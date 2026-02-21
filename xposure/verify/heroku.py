"""Heroku API key verifier for X-POSURE."""

from .base import BaseVerifier, VerificationResult
from ..core.models import Finding, VerificationStatus, Severity


class HerokuVerifier(BaseVerifier):
    """Verifier for Heroku API keys using the account endpoint."""

    SUPPORTED_TYPES = [
        'heroku_api_key',
        'heroku_key',
    ]

    def can_verify(self, finding: Finding) -> bool:
        """Check if this is a Heroku credential."""
        return finding.credential_type in self.SUPPORTED_TYPES

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify Heroku API key using the account endpoint.

        Args:
            finding: Finding with Heroku API key

        Returns:
            Verification result with account info
        """
        api_key = finding.value

        headers = {
            'Authorization': f'Bearer {api_key}',
            'Accept': 'application/vnd.heroku+json; version=3',
        }

        success, data, error = await self.safe_request(
            method='GET',
            url='https://api.heroku.com/account',
            headers=headers,
        )

        if not success:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='heroku_account_api',
                error=error or 'API key is invalid or expired',
            )

        # Extract account information
        email = data.get('email', 'Unknown')
        name = data.get('name', '')
        account_id = data.get('id', '')
        verified = data.get('verified', False)
        two_factor = data.get('two_factor_authentication', False)
        default_org = data.get('default_organization', {})
        default_team = data.get('default_team', {})

        # Build identity
        identity = email
        if name:
            identity = f'{name} ({email})'

        # Determine permissions
        permissions = ['account_access']
        if verified:
            permissions.append('account_verified')
        if two_factor:
            permissions.append('2fa_enabled')
        if default_org:
            org_name = default_org.get('name', '') if isinstance(default_org, dict) else str(default_org)
            if org_name:
                permissions.append(f'default_org:{org_name}')
        if default_team:
            team_name = default_team.get('name', '') if isinstance(default_team, dict) else str(default_team)
            if team_name:
                permissions.append(f'default_team:{team_name}')

        # Assess blast radius - Heroku keys typically have full account access
        blast_radius = self._assess_blast_radius(
            permissions=permissions,
            is_admin=True,  # Heroku API keys grant full account access
            is_production=True,
        )

        # Pivot opportunities
        can_pivot_to = [
            'All Heroku applications and dynos',
            'Application environment variables (config vars)',
            'Database credentials and connection strings',
            'Deployment and release management',
        ]
        if default_org or default_team:
            can_pivot_to.append('Team/organization resources')

        return VerificationResult(
            status=VerificationStatus.VERIFIED,
            method='heroku_account_api',
            identity=identity,
            permissions=permissions,
            can_pivot_to=can_pivot_to,
            blast_radius=blast_radius,
            environment='production',
            metadata={
                'email': email,
                'name': name,
                'account_id': account_id,
                'verified': verified,
                'two_factor_authentication': two_factor,
            },
        )
