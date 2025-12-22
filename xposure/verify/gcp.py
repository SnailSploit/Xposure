"""GCP credential verifier for X-POSURE."""

import json
from .base import BaseVerifier, VerificationResult
from ..core.models import Finding, VerificationStatus, Severity


class GCPVerifier(BaseVerifier):
    """Verifier for GCP credentials using Google APIs."""

    SUPPORTED_TYPES = [
        'gcp_api_key',
        'gcp_service_account',
        'gcp_oauth',
    ]

    def can_verify(self, finding: Finding) -> bool:
        """Check if this is a GCP credential."""
        return finding.credential_type in self.SUPPORTED_TYPES

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify GCP credential.

        Args:
            finding: Finding with GCP credential

        Returns:
            Verification result with project and permissions info
        """
        if finding.credential_type == 'gcp_api_key':
            return await self._verify_api_key(finding.value)
        elif finding.credential_type == 'gcp_service_account':
            return await self._verify_service_account(finding.value)
        elif finding.credential_type == 'gcp_oauth':
            return await self._verify_oauth_token(finding.value)
        else:
            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                method='gcp_unknown',
                error=f'Unknown GCP credential type: {finding.credential_type}',
            )

    async def _verify_api_key(self, api_key: str) -> VerificationResult:
        """
        Verify GCP API key by testing against a public API.

        Args:
            api_key: GCP API key

        Returns:
            Verification result
        """
        # Test against Google Custom Search API (doesn't require project setup)
        # This only checks if the key is valid, not what APIs it can access
        test_url = f'https://www.googleapis.com/customsearch/v1?key={api_key}&q=test'

        headers = {
            'Accept': 'application/json',
            'User-Agent': 'X-POSURE/4.0',
        }

        success, data, error = await self.safe_request(
            method='GET',
            url=test_url,
            headers=headers,
        )

        if success and data:
            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                method='gcp_api_test',
                identity='GCP API Key',
                permissions=['API key is valid (specific APIs unknown)'],
                can_pivot_to=['Google Cloud APIs enabled for this key'],
                blast_radius=Severity.MEDIUM,
                environment='production',
                metadata={
                    'key_prefix': api_key[:10] + '...',
                    'note': 'API key verified via test request. Actual API access depends on project configuration.',
                },
            )
        elif error and 'API key not valid' in str(error):
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='gcp_api_test',
                error='API key is invalid or revoked',
            )
        elif error and 'quota' in str(error).lower():
            # Key is valid but quota exceeded
            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                method='gcp_api_test',
                identity='GCP API Key',
                permissions=['API key is valid (quota exceeded)'],
                blast_radius=Severity.MEDIUM,
                environment='production',
                metadata={'note': 'Key validated via quota error - key is active'},
            )
        else:
            return VerificationResult(
                status=VerificationStatus.LIKELY_VALID,
                method='gcp_api_test',
                identity='GCP API Key (unconfirmed)',
                permissions=['Unable to verify - API response unclear'],
                blast_radius=Severity.MEDIUM,
                error=error,
            )

    async def _verify_service_account(self, json_key: str) -> VerificationResult:
        """
        Verify GCP service account JSON key.

        Args:
            json_key: Service account JSON key content

        Returns:
            Verification result
        """
        try:
            # Parse the JSON key
            key_data = json.loads(json_key)
        except json.JSONDecodeError:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='gcp_service_account_parse',
                error='Invalid JSON format for service account key',
            )

        # Extract key information
        project_id = key_data.get('project_id', 'Unknown')
        client_email = key_data.get('client_email', 'Unknown')
        key_type = key_data.get('type', 'Unknown')
        private_key_id = key_data.get('private_key_id', '')

        if key_type != 'service_account':
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='gcp_service_account_parse',
                error=f'Invalid key type: {key_type}',
            )

        # Note: Full verification would require creating a signed JWT and
        # testing against Google APIs, which is complex. For now, we validate
        # the structure and extract useful information.

        # Check if key has required fields
        has_private_key = 'private_key' in key_data and key_data['private_key']
        has_client_email = 'client_email' in key_data and '@' in str(key_data.get('client_email', ''))

        if not has_private_key or not has_client_email:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='gcp_service_account_parse',
                error='Missing required fields (private_key or client_email)',
            )

        # Determine service account type and blast radius
        identity = client_email
        permissions = ['Service account credentials (scope unknown)']
        blast_radius = Severity.HIGH  # Service accounts typically have significant access

        # Check for dangerous service account patterns
        can_pivot_to = []
        if 'compute@developer' in client_email:
            can_pivot_to.append('Compute Engine instances')
            blast_radius = Severity.CRITICAL
        if 'storage@' in client_email or 'gcs@' in client_email:
            can_pivot_to.append('Cloud Storage buckets')
        if 'bigquery@' in client_email:
            can_pivot_to.append('BigQuery datasets')
        if 'firebase@' in client_email:
            can_pivot_to.append('Firebase services')
        if 'owner' in client_email.lower() or 'admin' in client_email.lower():
            can_pivot_to.append('Project-wide resources')
            blast_radius = Severity.CRITICAL

        if not can_pivot_to:
            can_pivot_to.append('GCP resources (scope depends on IAM roles)')

        return VerificationResult(
            status=VerificationStatus.LIKELY_VALID,
            method='gcp_service_account_parse',
            identity=identity,
            permissions=permissions,
            can_pivot_to=can_pivot_to,
            blast_radius=blast_radius,
            environment='production',
            metadata={
                'project_id': project_id,
                'client_email': client_email,
                'key_id': private_key_id[:8] + '...' if private_key_id else 'N/A',
                'note': 'Key structure validated. Active verification requires API calls with signed JWT.',
            },
        )

    async def _verify_oauth_token(self, token: str) -> VerificationResult:
        """
        Verify GCP OAuth token.

        Args:
            token: OAuth access token (ya29.*)

        Returns:
            Verification result
        """
        # Verify OAuth token using Google's tokeninfo endpoint
        tokeninfo_url = f'https://oauth2.googleapis.com/tokeninfo?access_token={token}'

        headers = {
            'Accept': 'application/json',
            'User-Agent': 'X-POSURE/4.0',
        }

        success, data, error = await self.safe_request(
            method='GET',
            url=tokeninfo_url,
            headers=headers,
        )

        if success and data:
            # Token is valid
            email = data.get('email', 'Unknown')
            scope = data.get('scope', '').split()
            expires_in = data.get('expires_in', 0)

            # Assess blast radius based on scopes
            has_sensitive = any(
                s in ' '.join(scope).lower()
                for s in ['admin', 'full', 'write', 'manage', 'owner']
            )

            if has_sensitive:
                blast_radius = Severity.CRITICAL
            elif scope:
                blast_radius = Severity.HIGH
            else:
                blast_radius = Severity.MEDIUM

            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                method='gcp_oauth_tokeninfo',
                identity=email,
                permissions=scope if scope else ['Unknown scopes'],
                can_pivot_to=['GCP APIs authorized by token scopes'],
                blast_radius=blast_radius,
                environment='production',
                metadata={
                    'email': email,
                    'expires_in': expires_in,
                    'scope_count': len(scope),
                    'audience': data.get('audience', 'Unknown'),
                },
            )
        else:
            # Token is invalid or expired
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='gcp_oauth_tokeninfo',
                error=error or 'Token is invalid or expired',
            )
