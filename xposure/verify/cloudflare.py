"""Cloudflare API token verifier for X-POSURE."""

from .base import BaseVerifier, VerificationResult
from ..core.models import Finding, VerificationStatus, Severity


class CloudflareVerifier(BaseVerifier):
    """Verifier for Cloudflare API tokens using the token verify endpoint."""

    SUPPORTED_TYPES = [
        'cloudflare_api_token',
        'cloudflare_token',
        'cloudflare_api_key',
        'cf_api_token',
    ]

    def can_verify(self, finding: Finding) -> bool:
        """Check if this is a Cloudflare credential."""
        return finding.credential_type in self.SUPPORTED_TYPES

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify Cloudflare API token using the verify endpoint.

        Args:
            finding: Finding with Cloudflare API token

        Returns:
            Verification result with token info
        """
        token = finding.value

        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }

        success, data, error = await self.safe_request(
            method='GET',
            url='https://api.cloudflare.com/client/v4/user/tokens/verify',
            headers=headers,
        )

        if not success:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='cloudflare_token_verify',
                error=error or 'API token is invalid or expired',
            )

        # Extract verification result
        result_data = data.get('result', {})
        token_status = result_data.get('status', 'unknown')
        token_id = result_data.get('id', '')
        messages = data.get('messages', [])

        if token_status != 'active':
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='cloudflare_token_verify',
                error=f'Token status: {token_status}',
            )

        # Try to get more details about the token's capabilities
        user_data = await self._get_user_info(token)
        zone_data = await self._get_zones(token)

        # Build identity
        identity = 'Cloudflare API Token'
        if user_data:
            email = user_data.get('result', {}).get('email', '')
            if email:
                identity = f'Cloudflare ({email})'

        # Determine permissions
        permissions = [f'token_status:{token_status}']
        if user_data:
            user_result = user_data.get('result', {})
            if user_result.get('suspended', False):
                permissions.append('account_suspended')
            if user_result.get('two_factor_authentication_enabled', False):
                permissions.append('2fa_enabled')

        # Add zone information
        zones = []
        if zone_data:
            zone_list = zone_data.get('result', [])
            if isinstance(zone_list, list):
                zones = zone_list
                permissions.append(f'zones_accessible:{len(zones)}')
                for zone in zones[:5]:
                    zone_name = zone.get('name', '') if isinstance(zone, dict) else str(zone)
                    if zone_name:
                        permissions.append(f'zone:{zone_name}')

        # Assess blast radius
        has_zones = len(zones) > 0
        is_admin = user_data is not None  # Global API key has user access
        blast_radius = self._assess_blast_radius(
            permissions=permissions,
            is_admin=is_admin,
            is_production=has_zones,
        )

        # Pivot opportunities
        can_pivot_to = []
        if zones:
            can_pivot_to.append(f'DNS management for {len(zones)} zones')
            can_pivot_to.append('Modify DNS records (potential subdomain takeover)')
        if user_data:
            can_pivot_to.append('Account settings and billing')
        can_pivot_to.append('Cloudflare Workers (serverless code execution)')
        can_pivot_to.append('Page Rules and firewall configuration')

        return VerificationResult(
            status=VerificationStatus.VERIFIED,
            method='cloudflare_token_verify',
            identity=identity,
            permissions=permissions,
            can_pivot_to=can_pivot_to,
            blast_radius=blast_radius,
            environment='production',
            metadata={
                'token_id': token_id,
                'token_status': token_status,
                'zones_count': len(zones),
                'zones': [z.get('name', '') for z in zones[:10]] if zones else [],
                'messages': messages,
            },
        )

    async def _get_user_info(self, token: str) -> dict:
        """
        Get user information associated with the token.

        Args:
            token: Cloudflare API token

        Returns:
            User data or None
        """
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }

        success, data, error = await self.safe_request(
            method='GET',
            url='https://api.cloudflare.com/client/v4/user',
            headers=headers,
        )

        return data if success else None

    async def _get_zones(self, token: str) -> dict:
        """
        Get zones accessible with the token.

        Args:
            token: Cloudflare API token

        Returns:
            Zone data or None
        """
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }

        success, data, error = await self.safe_request(
            method='GET',
            url='https://api.cloudflare.com/client/v4/zones?per_page=10',
            headers=headers,
        )

        return data if success else None
