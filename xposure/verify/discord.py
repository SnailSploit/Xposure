"""Discord bot token verifier for X-POSURE."""

from .base import BaseVerifier, VerificationResult
from ..core.models import Finding, VerificationStatus, Severity


class DiscordVerifier(BaseVerifier):
    """Verifier for Discord bot tokens using the users/@me endpoint."""

    SUPPORTED_TYPES = [
        'discord_bot_token',
        'discord_token',
        'discord_webhook',
    ]

    def can_verify(self, finding: Finding) -> bool:
        """Check if this is a Discord credential."""
        return finding.credential_type in self.SUPPORTED_TYPES

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify Discord bot token using the users/@me endpoint.

        Args:
            finding: Finding with Discord bot token

        Returns:
            Verification result with bot info
        """
        token = finding.value

        # Webhooks are verified differently
        if finding.credential_type == 'discord_webhook':
            return await self._verify_webhook(token)

        headers = {
            'Authorization': f'Bot {token}',
            'Content-Type': 'application/json',
        }

        success, data, error = await self.safe_request(
            method='GET',
            url='https://discord.com/api/v10/users/@me',
            headers=headers,
        )

        if not success:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='discord_users_api',
                error=error or 'Bot token is invalid or expired',
            )

        # Extract bot information
        username = data.get('username', 'Unknown')
        discriminator = data.get('discriminator', '0000')
        bot_id = data.get('id', '')
        is_bot = data.get('bot', False)
        is_verified = data.get('verified', False)
        mfa_enabled = data.get('mfa_enabled', False)
        flags = data.get('flags', 0)
        public_flags = data.get('public_flags', 0)

        # Build identity
        if discriminator and discriminator != '0':
            identity = f'{username}#{discriminator} (ID: {bot_id})'
        else:
            identity = f'{username} (ID: {bot_id})'

        # Determine permissions
        permissions = []
        if is_bot:
            permissions.append('bot_account')
        if is_verified:
            permissions.append('verified')
        if mfa_enabled:
            permissions.append('mfa_enabled')

        # Try to get bot application info for more permissions
        app_data = await self._get_application_info(token)
        if app_data:
            if app_data.get('bot_public', False):
                permissions.append('public_bot')
            if app_data.get('bot_require_code_grant', False):
                permissions.append('requires_code_grant')
            install_params = app_data.get('install_params', {})
            if install_params:
                bot_permissions = install_params.get('permissions', '0')
                permissions.append(f'install_permissions:{bot_permissions}')

        # Assess blast radius
        blast_radius = self._assess_blast_radius(
            permissions=permissions,
            is_admin=False,
            is_production=True,
        )

        # Pivot opportunities
        can_pivot_to = [
            'Access guilds (servers) the bot is in',
            'Read messages in accessible channels',
        ]
        if is_bot:
            can_pivot_to.append('Send messages as the bot')
            can_pivot_to.append('Manage server resources (permission-dependent)')

        return VerificationResult(
            status=VerificationStatus.VERIFIED,
            method='discord_users_api',
            identity=identity,
            permissions=permissions,
            can_pivot_to=can_pivot_to,
            blast_radius=blast_radius,
            environment='production',
            metadata={
                'username': username,
                'discriminator': discriminator,
                'bot_id': bot_id,
                'is_bot': is_bot,
                'is_verified': is_verified,
                'mfa_enabled': mfa_enabled,
                'flags': flags,
                'public_flags': public_flags,
            },
        )

    async def _get_application_info(self, token: str) -> dict:
        """
        Get bot application information.

        Args:
            token: Discord bot token

        Returns:
            Application data or None
        """
        headers = {
            'Authorization': f'Bot {token}',
            'Content-Type': 'application/json',
        }

        success, data, error = await self.safe_request(
            method='GET',
            url='https://discord.com/api/v10/oauth2/applications/@me',
            headers=headers,
        )

        return data if success else None

    async def _verify_webhook(self, webhook_url: str) -> VerificationResult:
        """
        Verify Discord webhook by fetching its info.

        Args:
            webhook_url: Discord webhook URL

        Returns:
            Verification result
        """
        success, data, error = await self.safe_request(
            method='GET',
            url=webhook_url,
        )

        if success and data:
            name = data.get('name', 'Unknown')
            guild_id = data.get('guild_id', '')
            channel_id = data.get('channel_id', '')

            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                method='discord_webhook_info',
                identity=f'Webhook: {name}',
                permissions=['send_messages'],
                can_pivot_to=['Post messages to channel'],
                blast_radius=Severity.MEDIUM,
                environment='production',
                metadata={
                    'name': name,
                    'guild_id': guild_id,
                    'channel_id': channel_id,
                },
            )

        return VerificationResult(
            status=VerificationStatus.INVALID,
            method='discord_webhook_info',
            error=error or 'Webhook is invalid',
        )
