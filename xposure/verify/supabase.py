"""Supabase key verifier for X-POSURE."""

import json
import base64

from .base import BaseVerifier, VerificationResult
from ..core.models import Finding, VerificationStatus, Severity


class SupabaseVerifier(BaseVerifier):
    """Verifier for Supabase keys by decoding JWT and testing against the API."""

    SUPPORTED_TYPES = [
        'supabase_key',
        'supabase_anon_key',
        'supabase_service_role_key',
        'supabase_jwt',
    ]

    def can_verify(self, finding: Finding) -> bool:
        """Check if this is a Supabase credential."""
        return finding.credential_type in self.SUPPORTED_TYPES

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify Supabase key by decoding the JWT and testing the API.

        Args:
            finding: Finding with Supabase key

        Returns:
            Verification result with role and project info
        """
        token = finding.value

        # Decode the JWT to extract claims
        claims = self._decode_jwt(token)

        if not claims:
            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                method='supabase_jwt_decode',
                error='Unable to decode JWT - may not be a valid Supabase key',
            )

        # Extract role from claims
        role = claims.get('role', 'unknown')
        issuer = claims.get('iss', '')
        exp = claims.get('exp', 0)
        iat = claims.get('iat', 0)
        ref = claims.get('ref', '')

        # Determine Supabase URL
        supabase_url = (
            finding.paired_credentials.get('supabase_url', '')
            or finding.metadata.get('supabase_url', '')
        )

        # Try to extract project ref from issuer
        project_ref = ''
        if issuer and 'supabase' in issuer:
            # issuer format is typically "https://<ref>.supabase.co/auth/v1"
            parts = issuer.split('.')
            if len(parts) > 0:
                project_ref = parts[0].replace('https://', '').replace('http://', '')

        if not supabase_url and project_ref:
            supabase_url = f'https://{project_ref}.supabase.co'

        # Build identity
        is_service_role = role == 'service_role'
        is_anon = role == 'anon'
        identity = f'Supabase {role} key'
        if project_ref:
            identity += f' (project: {project_ref})'

        # Determine permissions based on role
        permissions = [f'role:{role}']
        if is_service_role:
            permissions.extend([
                'bypass_rls',
                'full_database_access',
                'auth_admin',
                'storage_admin',
            ])
        elif is_anon:
            permissions.extend([
                'rls_enforced',
                'public_access_only',
            ])
        else:
            permissions.append(f'custom_role:{role}')

        if issuer:
            permissions.append(f'issuer:{issuer}')

        # Test the key against Supabase API if we have the URL
        api_accessible = False
        if supabase_url:
            api_result = await self._test_supabase_api(supabase_url, token, role)
            if api_result:
                api_accessible = True
                permissions.append('api_accessible')

        # Assess blast radius
        blast_radius = self._assess_blast_radius(
            permissions=permissions,
            is_admin=is_service_role,
            is_production=True,
        )

        # Pivot opportunities
        can_pivot_to = []
        if is_service_role:
            can_pivot_to.extend([
                'Full database access bypassing RLS',
                'User management and authentication',
                'Storage bucket management',
                'Edge function invocation',
                'Read all user data and sessions',
            ])
        elif is_anon:
            can_pivot_to.extend([
                'Public API access',
                'Authentication endpoints',
                'Public storage buckets',
            ])
        if project_ref:
            can_pivot_to.append(f'Supabase project: {project_ref}')

        # Determine status
        if api_accessible:
            status = VerificationStatus.VERIFIED
        elif claims:
            status = VerificationStatus.LIKELY_VALID
        else:
            status = VerificationStatus.UNVERIFIED

        return VerificationResult(
            status=status,
            method='supabase_jwt_decode',
            identity=identity,
            permissions=permissions,
            can_pivot_to=can_pivot_to,
            blast_radius=blast_radius,
            environment='production',
            metadata={
                'role': role,
                'issuer': issuer,
                'project_ref': project_ref,
                'supabase_url': supabase_url,
                'exp': exp,
                'iat': iat,
                'is_service_role': is_service_role,
                'is_anon': is_anon,
                'api_accessible': api_accessible,
            },
        )

    def _decode_jwt(self, token: str) -> dict:
        """
        Decode JWT payload without verification.

        Args:
            token: JWT string

        Returns:
            Decoded claims dict or None
        """
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None

            # Decode the payload (second part)
            payload = parts[1]

            # Add padding if necessary
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += '=' * padding

            decoded = base64.urlsafe_b64decode(payload)
            return json.loads(decoded)

        except Exception:
            return None

    async def _test_supabase_api(self, supabase_url: str, token: str, role: str) -> bool:
        """
        Test the Supabase key against the REST API.

        Args:
            supabase_url: Supabase project URL
            token: Supabase API key
            role: JWT role claim

        Returns:
            True if API is accessible
        """
        supabase_url = supabase_url.rstrip('/')

        headers = {
            'apikey': token,
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
        }

        # Test the REST API endpoint
        success, data, error = await self.safe_request(
            method='GET',
            url=f'{supabase_url}/rest/v1/',
            headers=headers,
        )

        return success
