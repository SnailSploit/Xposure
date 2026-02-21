"""SendGrid API key verifier for X-POSURE."""

from .base import BaseVerifier, VerificationResult
from ..core.models import Finding, VerificationStatus, Severity


class SendGridVerifier(BaseVerifier):
    """Verifier for SendGrid API keys using the scopes endpoint."""

    SUPPORTED_TYPES = [
        'sendgrid_api_key',
        'sendgrid_key',
    ]

    def can_verify(self, finding: Finding) -> bool:
        """Check if this is a SendGrid credential."""
        return finding.credential_type in self.SUPPORTED_TYPES

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify SendGrid API key using the scopes endpoint.

        Args:
            finding: Finding with SendGrid API key

        Returns:
            Verification result with scopes and permissions
        """
        api_key = finding.value

        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
        }

        success, data, error = await self.safe_request(
            method='GET',
            url='https://api.sendgrid.com/v3/scopes',
            headers=headers,
        )

        if not success:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='sendgrid_scopes_api',
                error=error or 'API key is invalid or expired',
            )

        # Extract scopes
        scopes = data.get('scopes', [])

        # Build identity
        identity = 'SendGrid API Key'

        # Determine permissions
        permissions = scopes if scopes else ['authenticated (no scopes returned)']

        # Check for admin/write access
        has_admin = any('admin' in s for s in scopes)
        has_mail_send = 'mail.send' in scopes
        has_write = any('.create' in s or '.update' in s or '.delete' in s for s in scopes)
        has_read_only = all('.read' in s for s in scopes) if scopes else False

        # Assess blast radius
        is_production = has_mail_send  # Can send emails = production impact
        blast_radius = self._assess_blast_radius(
            permissions=permissions,
            is_admin=has_admin,
            is_production=is_production,
        )

        # Pivot opportunities
        can_pivot_to = []
        if has_mail_send:
            can_pivot_to.append('Send emails as the account (phishing potential)')
        if has_admin:
            can_pivot_to.append('Full account administration')
        if any('api_keys' in s for s in scopes):
            can_pivot_to.append('Create/manage API keys')
        if any('templates' in s for s in scopes):
            can_pivot_to.append('Email templates access')
        if any('stats' in s for s in scopes):
            can_pivot_to.append('Email statistics and analytics')

        return VerificationResult(
            status=VerificationStatus.VERIFIED,
            method='sendgrid_scopes_api',
            identity=identity,
            permissions=permissions,
            can_pivot_to=can_pivot_to,
            blast_radius=blast_radius,
            environment='production' if has_mail_send else 'unknown',
            metadata={
                'scopes_count': len(scopes),
                'has_mail_send': has_mail_send,
                'has_admin': has_admin,
                'has_write': has_write,
                'read_only': has_read_only,
            },
        )
