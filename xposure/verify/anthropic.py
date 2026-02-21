"""Anthropic API key verifier for X-POSURE."""

from .base import BaseVerifier, VerificationResult
from ..core.models import Finding, VerificationStatus, Severity


class AnthropicVerifier(BaseVerifier):
    """Verifier for Anthropic API keys using the models endpoint."""

    SUPPORTED_TYPES = [
        'anthropic_api_key',
        'anthropic_key',
        'claude_api_key',
    ]

    def can_verify(self, finding: Finding) -> bool:
        """Check if this is an Anthropic credential."""
        return finding.credential_type in self.SUPPORTED_TYPES

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify Anthropic API key using the models endpoint.

        Args:
            finding: Finding with Anthropic API key

        Returns:
            Verification result with available models info
        """
        api_key = finding.value

        headers = {
            'x-api-key': api_key,
            'anthropic-version': '2023-06-01',
            'Content-Type': 'application/json',
        }

        success, data, error = await self.safe_request(
            method='GET',
            url='https://api.anthropic.com/v1/models',
            headers=headers,
        )

        if not success:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='anthropic_models_api',
                error=error or 'API key is invalid or expired',
            )

        # Extract model information
        models = []
        if isinstance(data, dict):
            model_list = data.get('data', [])
            if isinstance(model_list, list):
                models = [m.get('id', '') for m in model_list if isinstance(m, dict)]

        # Build identity
        identity = 'Anthropic API Key'
        if models:
            identity += f' ({len(models)} models available)'

        # Determine permissions
        permissions = ['api_access']
        if models:
            permissions.append(f'models_available:{len(models)}')
            for model in models[:5]:
                permissions.append(f'model:{model}')

        # Assess blast radius
        blast_radius = self._assess_blast_radius(
            permissions=permissions,
            is_admin=False,
            is_production=True,
        )

        # Pivot opportunities
        can_pivot_to = [
            'Use Claude AI models for inference',
            'Consume API credits/billing',
        ]
        if any('opus' in m for m in models):
            can_pivot_to.append('Access to highest-tier models')

        return VerificationResult(
            status=VerificationStatus.VERIFIED,
            method='anthropic_models_api',
            identity=identity,
            permissions=permissions,
            can_pivot_to=can_pivot_to,
            blast_radius=blast_radius,
            environment='production',
            metadata={
                'models': models,
                'model_count': len(models),
            },
        )
