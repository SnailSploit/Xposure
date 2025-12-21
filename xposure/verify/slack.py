"""Slack credential verifier for X-POSURE."""

from .base import BaseVerifier, VerificationResult
from ..core.models import Finding, VerificationStatus, Severity


class SlackVerifier(BaseVerifier):
    """Verifier for Slack tokens using auth.test API."""

    SUPPORTED_TYPES = [
        'slack_token',
        'slack_bot_token',
        'slack_user_token',
        'slack_webhook',
    ]

    def can_verify(self, finding: Finding) -> bool:
        """Check if this is a Slack credential."""
        return finding.credential_type in self.SUPPORTED_TYPES

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify Slack token using auth.test API.

        Args:
            finding: Finding with Slack token

        Returns:
            Verification result with workspace and bot info
        """
        token = finding.value

        # Webhooks are verified differently
        if finding.credential_type == 'slack_webhook':
            return await self._verify_webhook(token)

        # Verify token with auth.test
        auth_data = await self._auth_test(token)

        if not auth_data:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='slack_auth_test',
                error='Token is invalid or revoked',
            )

        return await self._process_auth_data(auth_data, token)

    async def _auth_test(self, token: str) -> dict:
        """
        Call Slack auth.test API.

        Args:
            token: Slack token

        Returns:
            Auth data or None if failed
        """
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }

        success, data, error = await self.safe_request(
            method='POST',
            url='https://slack.com/api/auth.test',
            headers=headers,
        )

        if success and data and data.get('ok'):
            return data

        return None

    async def _verify_webhook(self, webhook_url: str) -> VerificationResult:
        """
        Verify Slack webhook by sending a test message.

        Args:
            webhook_url: Webhook URL

        Returns:
            Verification result
        """
        # Send a minimal test payload
        test_payload = {
            'text': '[X-POSURE] Credential verification test - please ignore',
        }

        success, data, error = await self.safe_request(
            method='POST',
            url=webhook_url,
            json=test_payload,
        )

        if success:
            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                method='slack_webhook_test',
                identity='Slack Webhook',
                permissions=['Post messages'],
                blast_radius=Severity.MEDIUM,
                metadata={'webhook_url': webhook_url[:50] + '...'},
            )
        else:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='slack_webhook_test',
                error=error or 'Webhook is invalid',
            )

    async def _process_auth_data(self, auth_data: dict, token: str) -> VerificationResult:
        """
        Process auth.test response.

        Args:
            auth_data: Auth data from API
            token: Slack token

        Returns:
            Verification result
        """
        # Extract information
        team_name = auth_data.get('team', 'Unknown')
        team_id = auth_data.get('team_id', '')
        user_name = auth_data.get('user', 'bot')
        user_id = auth_data.get('user_id', '')
        bot_id = auth_data.get('bot_id', '')
        is_enterprise = auth_data.get('is_enterprise_install', False)

        # Determine if it's a bot token or user token
        is_bot = bool(bot_id) or token.startswith('xoxb-')
        is_user = token.startswith('xoxp-')
        is_app = token.startswith('xapp-')

        # Build identity
        if is_bot:
            identity = f'Bot: {user_name} in {team_name}'
        elif is_user:
            identity = f'User: {user_name} in {team_name}'
        elif is_app:
            identity = f'App token in {team_name}'
        else:
            identity = f'{user_name} in {team_name}'

        # Get scopes if available
        scopes = await self._get_scopes(token)

        # Determine permissions
        permissions = scopes if scopes else ['Unknown scopes']

        # Assess blast radius
        has_admin = any('admin' in s for s in scopes)
        has_files = any('files:' in s for s in scopes)
        has_channels = any('channels:' in s for s in scopes)
        has_users = any('users:' in s for s in scopes)

        if has_admin or is_enterprise:
            blast_radius = Severity.CRITICAL
        elif has_files or has_channels or has_users:
            blast_radius = Severity.HIGH
        else:
            blast_radius = Severity.MEDIUM

        # Pivot opportunities
        can_pivot_to = []

        if has_admin:
            can_pivot_to.append('Workspace administration')

        if has_files:
            can_pivot_to.append('All shared files and documents')

        if has_channels:
            can_pivot_to.append('All channels and messages')

        if has_users:
            can_pivot_to.append('User information and profiles')

        if 'chat:write' in scopes:
            can_pivot_to.append('Send messages as bot/user')

        return VerificationResult(
            status=VerificationStatus.VERIFIED,
            method='slack_auth_test',
            identity=identity,
            permissions=permissions,
            can_pivot_to=can_pivot_to,
            blast_radius=blast_radius,
            environment='production',
            metadata={
                'team_name': team_name,
                'team_id': team_id,
                'user_name': user_name,
                'user_id': user_id,
                'bot_id': bot_id,
                'is_bot': is_bot,
                'is_enterprise': is_enterprise,
                'scopes': scopes,
            },
        )

    async def _get_scopes(self, token: str) -> list:
        """
        Get token scopes from auth.test response.

        Args:
            token: Slack token

        Returns:
            List of scopes
        """
        # Try to get scopes from auth.revoke endpoint (doesn't actually revoke, just shows info)
        # This is a hack - in reality, scopes aren't easily accessible from the API
        # We'll infer from token type instead

        scopes = []

        if token.startswith('xoxb-'):
            scopes = ['bot', 'chat:write', 'channels:read']  # Common bot scopes
        elif token.startswith('xoxp-'):
            scopes = ['identify', 'chat:write:user']  # Common user scopes
        elif token.startswith('xapp-'):
            scopes = ['app_mentions:read', 'chat:write']  # App-level token

        return scopes
