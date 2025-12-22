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

    async def _get_scopes(self, token: str) -> tuple[list, bool]:
        """
        Attempt to get token scopes from Slack API.

        Note: Slack API doesn't expose scopes directly for most token types.
        We attempt to infer from auth.test response and API behavior.

        Args:
            token: Slack token

        Returns:
            Tuple of (list of scopes, bool indicating if scopes are confirmed)
        """
        # Try to get scopes from apps.permissions.info (only works for some token types)
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }

        try:
            success, data, error = await self.safe_request(
                method='GET',
                url='https://slack.com/api/apps.permissions.info',
                headers=headers,
            )

            if success and data and data.get('ok'):
                # If we got permissions info, extract scopes
                scopes = data.get('info', {}).get('app_home', {}).get('scopes', [])
                if scopes:
                    return scopes, True
        except Exception:
            pass

        # Scopes not available via API - return empty with flag indicating uncertainty
        # DO NOT fabricate scopes as that misleads the user
        return [], False

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
        scopes, scopes_confirmed = await self._get_scopes(token)

        # Determine permissions - be honest about uncertainty
        if scopes_confirmed and scopes:
            permissions = scopes
        else:
            # Cannot determine scopes - indicate uncertainty
            token_type = 'bot' if is_bot else ('user' if is_user else ('app' if is_app else 'unknown'))
            permissions = [f'Unable to enumerate scopes (token type: {token_type})']

        # Assess blast radius - be conservative when scopes are unknown
        if scopes_confirmed:
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
        else:
            # Unknown scopes - assume high risk to be safe
            if is_enterprise:
                blast_radius = Severity.CRITICAL
            else:
                blast_radius = Severity.HIGH  # Conservative when uncertain

        # Pivot opportunities
        can_pivot_to = []

        if scopes_confirmed:
            if any('admin' in s for s in scopes):
                can_pivot_to.append('Workspace administration')
            if any('files:' in s for s in scopes):
                can_pivot_to.append('All shared files and documents')
            if any('channels:' in s for s in scopes):
                can_pivot_to.append('All channels and messages')
            if any('users:' in s for s in scopes):
                can_pivot_to.append('User information and profiles')
            if 'chat:write' in scopes:
                can_pivot_to.append('Send messages as bot/user')
        else:
            can_pivot_to.append('Scope-dependent access (unable to enumerate)')

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
                'scopes_confirmed': scopes_confirmed,
            },
        )
