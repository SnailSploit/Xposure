"""PyPI API token verifier for X-POSURE."""

from .base import BaseVerifier, VerificationResult
from ..core.models import Finding, VerificationStatus, Severity


class PyPIVerifier(BaseVerifier):
    """Verifier for PyPI API tokens by testing upload endpoint authentication."""

    SUPPORTED_TYPES = [
        'pypi_token',
        'pypi_api_token',
        'pypi_key',
    ]

    def can_verify(self, finding: Finding) -> bool:
        """Check if this is a PyPI credential."""
        return finding.credential_type in self.SUPPORTED_TYPES

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify PyPI API token by checking authentication against the upload endpoint.

        PyPI tokens start with 'pypi-' and are used for package uploads.
        We test with a minimal POST to the upload endpoint to check auth
        without actually uploading anything.

        Args:
            finding: Finding with PyPI token

        Returns:
            Verification result
        """
        token = finding.value

        # PyPI uses __token__ as username and the token as password
        # Test authentication with a GET to the upload endpoint
        headers = {
            'Authorization': f'Basic {self._encode_credentials(token)}',
        }

        success, data, error = await self.safe_request(
            method='GET',
            url='https://upload.pypi.org/legacy/',
            headers=headers,
        )

        # PyPI upload endpoint behavior:
        # - 405 Method Not Allowed = auth succeeded but GET not supported (valid token)
        # - 401 = invalid credentials
        # - 403 = forbidden

        if success:
            # Unlikely for GET on upload endpoint, but handle it
            return self._build_verified_result(token)

        if error and 'HTTP 405' in error:
            # Method Not Allowed means auth succeeded
            return self._build_verified_result(token)

        if error and ('HTTP 401' in error or 'HTTP 403' in error):
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='pypi_upload_auth',
                error='Token is invalid or expired',
            )

        # Ambiguous result
        return VerificationResult(
            status=VerificationStatus.UNVERIFIED,
            method='pypi_upload_auth',
            error=error or 'Unable to determine token validity',
        )

    def _encode_credentials(self, token: str) -> str:
        """
        Encode PyPI credentials as base64 for Basic auth.

        Args:
            token: PyPI API token

        Returns:
            Base64-encoded credentials string
        """
        import base64
        credentials = f'__token__:{token}'
        return base64.b64encode(credentials.encode()).decode()

    def _build_verified_result(self, token: str) -> VerificationResult:
        """
        Build a verified result for a valid PyPI token.

        Args:
            token: PyPI API token

        Returns:
            Verification result
        """
        # Determine token scope from prefix
        is_project_scoped = False
        project_name = None

        # PyPI tokens that are project-scoped have different characteristics
        # but we can't easily determine the project from the token alone
        if token.startswith('pypi-'):
            identity = 'PyPI API Token'
        else:
            identity = 'PyPI Credentials'

        permissions = ['package_upload']

        # Assess blast radius - PyPI publish tokens are high risk (supply chain)
        blast_radius = self._assess_blast_radius(
            permissions=permissions,
            is_admin=not is_project_scoped,  # Global tokens are admin-like
            is_production=True,  # PyPI is always production
        )

        # Pivot opportunities
        can_pivot_to = [
            'Upload/overwrite Python packages (supply chain attack)',
            'Access to package download statistics',
        ]
        if not is_project_scoped:
            can_pivot_to.append('Upload to any project owned by the account')

        return VerificationResult(
            status=VerificationStatus.VERIFIED,
            method='pypi_upload_auth',
            identity=identity,
            permissions=permissions,
            can_pivot_to=can_pivot_to,
            blast_radius=blast_radius,
            environment='production',
            metadata={
                'token_prefix': token[:10] + '...' if len(token) > 10 else token,
                'is_project_scoped': is_project_scoped,
            },
        )
