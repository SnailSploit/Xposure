"""Twilio credential verifier for X-POSURE."""

import base64

from .base import BaseVerifier, VerificationResult
from ..core.models import Finding, VerificationStatus, Severity


class TwilioVerifier(BaseVerifier):
    """Verifier for Twilio credentials using the Accounts API."""

    SUPPORTED_TYPES = [
        'twilio_api_key',
        'twilio_account_sid',
        'twilio_auth_token',
    ]

    def can_verify(self, finding: Finding) -> bool:
        """Check if this is a Twilio credential."""
        return finding.credential_type in self.SUPPORTED_TYPES

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify Twilio credentials using the Accounts API.

        Expects finding.value to be the auth token and
        finding.paired_credentials to contain 'account_sid'.

        Args:
            finding: Finding with Twilio credentials

        Returns:
            Verification result with account info
        """
        auth_token = finding.value
        account_sid = finding.paired_credentials.get('account_sid', '')

        # If the value itself looks like an account SID, swap
        if finding.value.startswith('AC') and len(finding.value) == 34:
            account_sid = finding.value
            auth_token = finding.paired_credentials.get('auth_token', '')

        if not account_sid or not auth_token:
            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                method='twilio_accounts_api',
                error='Both Account SID and Auth Token are required',
            )

        # Build Basic auth header
        credentials = base64.b64encode(
            f'{account_sid}:{auth_token}'.encode()
        ).decode()

        headers = {
            'Authorization': f'Basic {credentials}',
        }

        success, data, error = await self.safe_request(
            method='GET',
            url=f'https://api.twilio.com/2010-04-01/Accounts/{account_sid}.json',
            headers=headers,
        )

        if not success:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='twilio_accounts_api',
                error=error or 'Credentials are invalid or expired',
            )

        # Extract account information
        friendly_name = data.get('friendly_name', 'Unknown')
        account_status = data.get('status', 'unknown')
        account_type = data.get('type', 'unknown')
        owner_account_sid = data.get('owner_account_sid', '')
        date_created = data.get('date_created', '')

        # Build identity
        identity = f'{friendly_name} ({account_sid})'

        # Determine permissions
        permissions = [
            f'account_status:{account_status}',
            f'account_type:{account_type}',
        ]

        # Check if this is a master account or subaccount
        is_master = owner_account_sid == account_sid
        if is_master:
            permissions.append('master_account')
        else:
            permissions.append('subaccount')

        # Assess blast radius
        is_admin = is_master
        is_production = account_status == 'active'
        blast_radius = self._assess_blast_radius(
            permissions=permissions,
            is_admin=is_admin,
            is_production=is_production,
        )

        # Pivot opportunities
        can_pivot_to = []
        if is_master:
            can_pivot_to.append('All subaccounts and resources')
        can_pivot_to.append('Send SMS/MMS messages')
        can_pivot_to.append('Make phone calls')
        can_pivot_to.append('Access call recordings and logs')
        if is_master:
            can_pivot_to.append('Create/manage subaccounts')
            can_pivot_to.append('Billing and usage information')

        return VerificationResult(
            status=VerificationStatus.VERIFIED,
            method='twilio_accounts_api',
            identity=identity,
            permissions=permissions,
            can_pivot_to=can_pivot_to,
            blast_radius=blast_radius,
            environment='production' if is_production else 'test',
            metadata={
                'account_sid': account_sid,
                'friendly_name': friendly_name,
                'status': account_status,
                'type': account_type,
                'is_master': is_master,
                'owner_account_sid': owner_account_sid,
                'date_created': date_created,
            },
        )
