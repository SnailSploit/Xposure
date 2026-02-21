"""NPM registry token verifier for X-POSURE."""

from .base import BaseVerifier, VerificationResult
from ..core.models import Finding, VerificationStatus, Severity


class NPMVerifier(BaseVerifier):
    """Verifier for NPM registry tokens using the whoami endpoint."""

    SUPPORTED_TYPES = [
        'npm_token',
        'npm_auth_token',
        'npmrc_token',
    ]

    def can_verify(self, finding: Finding) -> bool:
        """Check if this is an NPM credential."""
        return finding.credential_type in self.SUPPORTED_TYPES

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify NPM token using the whoami endpoint.

        Args:
            finding: Finding with NPM token

        Returns:
            Verification result with user info
        """
        token = finding.value

        headers = {
            'Authorization': f'Bearer {token}',
        }

        success, data, error = await self.safe_request(
            method='GET',
            url='https://registry.npmjs.org/-/whoami',
            headers=headers,
        )

        if not success:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='npm_whoami_api',
                error=error or 'Token is invalid or expired',
            )

        # Extract user information
        username = data.get('username', 'Unknown')

        # Build identity
        identity = f'npm:{username}'

        # Determine permissions - NPM tokens can be read-only or publish
        permissions = ['authenticated']

        # Try to check token type by listing user packages
        packages = await self._get_user_packages(token, username)
        if packages is not None:
            permissions.append(f'packages:{len(packages)}')

        # Assess blast radius - npm publish tokens are high risk
        # We can't easily determine token type from whoami alone
        blast_radius = self._assess_blast_radius(
            permissions=permissions,
            is_admin=False,
            is_production=True,  # npm registry is always production
        )

        # Pivot opportunities
        can_pivot_to = [
            'View private packages',
        ]
        # Token could be a publish token
        can_pivot_to.append('Potentially publish/modify packages (supply chain attack)')
        if packages and len(packages) > 0:
            can_pivot_to.append(f'Access to {len(packages)} packages')

        return VerificationResult(
            status=VerificationStatus.VERIFIED,
            method='npm_whoami_api',
            identity=identity,
            permissions=permissions,
            can_pivot_to=can_pivot_to,
            blast_radius=blast_radius,
            environment='production',
            metadata={
                'username': username,
                'package_count': len(packages) if packages else 0,
                'packages': packages[:20] if packages else [],
            },
        )

    async def _get_user_packages(self, token: str, username: str) -> list:
        """
        Get list of packages owned by user.

        Args:
            token: NPM token
            username: NPM username

        Returns:
            List of package names or None if failed
        """
        headers = {
            'Authorization': f'Bearer {token}',
        }

        success, data, error = await self.safe_request(
            method='GET',
            url=f'https://registry.npmjs.org/-/user/{username}/package',
            headers=headers,
        )

        if success and data:
            # Response is an object with package names as keys
            if isinstance(data, dict) and 'response' not in data:
                return list(data.keys())

        return None
