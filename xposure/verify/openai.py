"""OpenAI credential verifier for X-POSURE."""

from .base import BaseVerifier, VerificationResult
from ..core.models import Finding, VerificationStatus, Severity


class OpenAIVerifier(BaseVerifier):
    """Verifier for OpenAI API keys using the models API."""

    SUPPORTED_TYPES = [
        'openai_key',
        'openai_api_key',
    ]

    def can_verify(self, finding: Finding) -> bool:
        """Check if this is an OpenAI credential."""
        return finding.credential_type in self.SUPPORTED_TYPES

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify OpenAI API key using the models API.

        Args:
            finding: Finding with OpenAI key

        Returns:
            Verification result with organization info
        """
        api_key = finding.value

        # Get models list (lightweight check)
        models_data = await self._list_models(api_key)

        if not models_data:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='openai_models_api',
                error='API key is invalid or revoked',
            )

        # Try to get organization info
        org_data = await self._get_organization_info(api_key)

        return await self._process_verification(models_data, org_data, api_key)

    async def _list_models(self, api_key: str) -> dict:
        """
        List available models.

        Args:
            api_key: OpenAI API key

        Returns:
            Models data or None if failed
        """
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
        }

        success, data, error = await self.safe_request(
            method='GET',
            url='https://api.openai.com/v1/models',
            headers=headers,
        )

        return data if success else None

    async def _get_organization_info(self, api_key: str) -> dict:
        """
        Try to get organization information (if available).

        Args:
            api_key: OpenAI API key

        Returns:
            Organization data or empty dict
        """
        # Note: OpenAI doesn't have a direct org info endpoint
        # We'll extract what we can from other endpoints

        # Try getting usage/billing info (may require specific permissions)
        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
        }

        success, data, error = await self.safe_request(
            method='GET',
            url='https://api.openai.com/v1/usage',
            headers=headers,
        )

        return data if success else {}

    async def _process_verification(
        self,
        models_data: dict,
        org_data: dict,
        api_key: str,
    ) -> VerificationResult:
        """
        Process verification results.

        Args:
            models_data: Models list data
            org_data: Organization data
            api_key: OpenAI API key

        Returns:
            Verification result
        """
        # Extract available models
        models = models_data.get('data', [])
        model_ids = [m.get('id', '') for m in models[:10]]  # First 10

        # Determine key type
        is_project_key = api_key.startswith('sk-proj-')
        key_type = 'Project Key' if is_project_key else 'User/Service Key'

        # Build identity
        identity = f'OpenAI {key_type}'

        # Permissions based on available models
        permissions = [
            'API access',
            f'Access to {len(models)} models',
        ]

        # Check for specific model access
        has_gpt4 = any('gpt-4' in m for m in model_ids)
        has_gpt35 = any('gpt-3.5' in m for m in model_ids)
        has_embedding = any('embedding' in m for m in model_ids)
        has_whisper = any('whisper' in m for m in model_ids)
        has_dalle = any('dall-e' in m for m in model_ids)

        if has_gpt4:
            permissions.append('GPT-4 access')
        if has_gpt35:
            permissions.append('GPT-3.5 access')
        if has_embedding:
            permissions.append('Embeddings access')
        if has_whisper:
            permissions.append('Whisper (speech-to-text) access')
        if has_dalle:
            permissions.append('DALL-E (image generation) access')

        # Pivot opportunities
        can_pivot_to = [
            'API usage and billing information',
        ]

        if has_gpt4 or has_gpt35:
            can_pivot_to.append('Consume API credits for expensive models')

        if has_dalle:
            can_pivot_to.append('Generate images (cost accumulation)')

        # Assess blast radius
        # OpenAI keys can be expensive if abused
        if has_gpt4 or has_dalle:
            blast_radius = Severity.HIGH
        elif has_gpt35:
            blast_radius = Severity.MEDIUM
        else:
            blast_radius = Severity.LOW

        return VerificationResult(
            status=VerificationStatus.VERIFIED,
            method='openai_models_api',
            identity=identity,
            permissions=permissions,
            can_pivot_to=can_pivot_to,
            blast_radius=blast_radius,
            environment='production',
            metadata={
                'key_type': key_type,
                'total_models': len(models),
                'sample_models': model_ids,
                'has_gpt4': has_gpt4,
                'has_gpt35': has_gpt35,
                'has_dalle': has_dalle,
            },
        )
