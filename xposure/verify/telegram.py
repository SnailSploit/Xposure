"""Telegram bot token verifier for X-POSURE."""

from .base import BaseVerifier, VerificationResult
from ..core.models import Finding, VerificationStatus, Severity


class TelegramVerifier(BaseVerifier):
    """Verifier for Telegram bot tokens using the getMe endpoint."""

    SUPPORTED_TYPES = [
        'telegram_bot_token',
        'telegram_token',
    ]

    def can_verify(self, finding: Finding) -> bool:
        """Check if this is a Telegram credential."""
        return finding.credential_type in self.SUPPORTED_TYPES

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify Telegram bot token using the getMe endpoint.

        Args:
            finding: Finding with Telegram bot token

        Returns:
            Verification result with bot info
        """
        token = finding.value

        success, data, error = await self.safe_request(
            method='GET',
            url=f'https://api.telegram.org/bot{token}/getMe',
        )

        if not success:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='telegram_getme_api',
                error=error or 'Bot token is invalid or expired',
            )

        # Telegram wraps the response in a 'result' field
        result_data = data.get('result', data)

        if not data.get('ok', False) and 'result' in data:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='telegram_getme_api',
                error='API returned error status',
            )

        # Extract bot information
        bot_id = result_data.get('id', '')
        is_bot = result_data.get('is_bot', False)
        first_name = result_data.get('first_name', 'Unknown')
        username = result_data.get('username', '')
        can_join_groups = result_data.get('can_join_groups', False)
        can_read_all_group_messages = result_data.get('can_read_all_group_messages', False)
        supports_inline_queries = result_data.get('supports_inline_queries', False)
        can_connect_to_business = result_data.get('can_connect_to_business', False)

        # Build identity
        identity = f'{first_name}'
        if username:
            identity += f' (@{username})'

        # Determine permissions
        permissions = []
        if is_bot:
            permissions.append('bot_account')
        if can_join_groups:
            permissions.append('can_join_groups')
        if can_read_all_group_messages:
            permissions.append('can_read_all_group_messages')
        if supports_inline_queries:
            permissions.append('supports_inline_queries')
        if can_connect_to_business:
            permissions.append('can_connect_to_business')

        # Assess blast radius
        blast_radius = self._assess_blast_radius(
            permissions=permissions,
            is_admin=can_read_all_group_messages,
            is_production=True,
        )

        # Pivot opportunities
        can_pivot_to = ['Send messages via the bot']
        if can_join_groups:
            can_pivot_to.append('Join and interact in groups')
        if can_read_all_group_messages:
            can_pivot_to.append('Read all group messages (privacy mode disabled)')
        if supports_inline_queries:
            can_pivot_to.append('Handle inline queries from users')

        return VerificationResult(
            status=VerificationStatus.VERIFIED,
            method='telegram_getme_api',
            identity=identity,
            permissions=permissions,
            can_pivot_to=can_pivot_to,
            blast_radius=blast_radius,
            environment='production',
            metadata={
                'bot_id': bot_id,
                'is_bot': is_bot,
                'first_name': first_name,
                'username': username,
                'can_join_groups': can_join_groups,
                'can_read_all_group_messages': can_read_all_group_messages,
                'supports_inline_queries': supports_inline_queries,
                'can_connect_to_business': can_connect_to_business,
            },
        )
