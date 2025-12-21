"""Stripe credential verifier for X-POSURE."""

import base64

from .base import BaseVerifier, VerificationResult
from ..core.models import Finding, VerificationStatus, Severity


class StripeVerifier(BaseVerifier):
    """Verifier for Stripe keys using the account API."""

    SUPPORTED_TYPES = [
        'stripe_secret_key',
        'stripe_publishable_key',
        'stripe_restricted_key',
    ]

    def can_verify(self, finding: Finding) -> bool:
        """Check if this is a Stripe credential."""
        return finding.credential_type in self.SUPPORTED_TYPES

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify Stripe key using the account API.

        Args:
            finding: Finding with Stripe key

        Returns:
            Verification result with account info
        """
        key = finding.value

        # Publishable keys can't be verified via API (they're client-side)
        if key.startswith('pk_'):
            return VerificationResult(
                status=VerificationStatus.LIKELY_VALID,
                method='stripe_format_check',
                identity='Stripe Publishable Key (client-side only)',
                permissions=['Public key - no server actions'],
                blast_radius=Severity.INFO,
                environment='production' if key.startswith('pk_live_') else 'test',
                metadata={'note': 'Publishable keys cannot be verified server-side'},
            )

        # Verify secret or restricted key
        account_data = await self._get_account_info(key)

        if not account_data:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='stripe_account_api',
                error='Key is invalid or revoked',
            )

        return await self._process_account_data(account_data, key)

    async def _get_account_info(self, key: str) -> dict:
        """
        Get Stripe account information.

        Args:
            key: Stripe secret or restricted key

        Returns:
            Account data or None if failed
        """
        # Stripe uses HTTP Basic Auth with API key as username
        auth_string = f'{key}:'
        auth_bytes = auth_string.encode('utf-8')
        auth_b64 = base64.b64encode(auth_bytes).decode('utf-8')

        headers = {
            'Authorization': f'Basic {auth_b64}',
            'Content-Type': 'application/x-www-form-urlencoded',
        }

        success, data, error = await self.safe_request(
            method='GET',
            url='https://api.stripe.com/v1/account',
            headers=headers,
        )

        return data if success else None

    async def _process_account_data(self, account_data: dict, key: str) -> VerificationResult:
        """
        Process Stripe account data.

        Args:
            account_data: Account data from API
            key: Stripe key

        Returns:
            Verification result
        """
        # Extract account information
        account_id = account_data.get('id', 'Unknown')
        business_name = account_data.get('business_profile', {}).get('name') or account_data.get('display_name', 'Unknown')
        email = account_data.get('email', 'Not provided')
        country = account_data.get('country', 'Unknown')
        charges_enabled = account_data.get('charges_enabled', False)
        payouts_enabled = account_data.get('payouts_enabled', False)

        # Determine environment
        is_live = key.startswith('sk_live_') or key.startswith('rk_live_')
        environment = 'production' if is_live else 'test'

        # Build identity
        identity = f'{business_name} ({account_id})'

        # Determine permissions based on key type
        permissions = []
        can_pivot_to = []

        if key.startswith('sk_'):
            # Full secret key - has all permissions
            permissions = [
                'Full API access',
                'Create charges',
                'Manage customers',
                'Access payment methods',
                'Manage subscriptions',
            ]

            can_pivot_to = [
                'Customer payment methods (credit cards)',
                'Transaction history',
                'Subscription data',
                'Payout information',
            ]

            if charges_enabled:
                can_pivot_to.append('Create unauthorized charges')

        elif key.startswith('rk_'):
            # Restricted key - limited permissions
            permissions = ['Restricted access (specific endpoints only)']
            can_pivot_to = ['Limited based on key restrictions']

        # Assess blast radius
        if is_live and charges_enabled:
            blast_radius = Severity.CRITICAL
        elif is_live:
            blast_radius = Severity.HIGH
        elif charges_enabled:
            blast_radius = Severity.MEDIUM
        else:
            blast_radius = Severity.LOW

        return VerificationResult(
            status=VerificationStatus.VERIFIED,
            method='stripe_account_api',
            identity=identity,
            permissions=permissions,
            can_pivot_to=can_pivot_to,
            blast_radius=blast_radius,
            environment=environment,
            metadata={
                'account_id': account_id,
                'business_name': business_name,
                'email': email,
                'country': country,
                'charges_enabled': charges_enabled,
                'payouts_enabled': payouts_enabled,
                'live_mode': is_live,
            },
        )
