"""GitHub credential verifier for X-POSURE."""

from .base import BaseVerifier, VerificationResult
from ..core.models import Finding, VerificationStatus, Severity


class GitHubVerifier(BaseVerifier):
    """Verifier for GitHub tokens using the user API."""

    SUPPORTED_TYPES = [
        'github_token',
        'github_pat',
        'github_oauth',
        'github_app_token',
    ]

    def can_verify(self, finding: Finding) -> bool:
        """Check if this is a GitHub credential."""
        return finding.credential_type in self.SUPPORTED_TYPES

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify GitHub token using the user API.

        Args:
            finding: Finding with GitHub token

        Returns:
            Verification result with user info and permissions
        """
        token = finding.value

        # Get user information
        user_data = await self._get_user_info(token)

        if not user_data:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='github_user_api',
                error='Token is invalid or expired',
            )

        # Get token scopes
        scopes = await self._get_token_scopes(token)

        # Process the results
        return await self._process_user_data(user_data, scopes, token)

    async def _get_user_info(self, token: str) -> dict:
        """
        Get authenticated user information.

        Args:
            token: GitHub token

        Returns:
            User data or None if failed
        """
        headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'X-POSURE/4.0',
        }

        success, data, error = await self.safe_request(
            method='GET',
            url='https://api.github.com/user',
            headers=headers,
        )

        return data if success else None

    async def _get_token_scopes(self, token: str) -> list:
        """
        Get token scopes from response headers.

        Args:
            token: GitHub token

        Returns:
            List of scopes
        """
        if not self.session:
            return []

        try:
            headers = {
                'Authorization': f'Bearer {token}',
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'X-POSURE/4.0',
            }

            # Make a lightweight request to get headers
            async with self.session.get('https://api.github.com/user', headers=headers) as response:
                # GitHub returns scopes in X-OAuth-Scopes header
                scopes_header = response.headers.get('X-OAuth-Scopes', '')

                if scopes_header:
                    return [s.strip() for s in scopes_header.split(',') if s.strip()]

        except Exception:
            pass

        return []

    async def _process_user_data(self, user_data: dict, scopes: list, token: str) -> VerificationResult:
        """
        Process user data and scopes into verification result.

        Args:
            user_data: User data from API
            scopes: Token scopes
            token: GitHub token

        Returns:
            Verification result
        """
        # Extract user information
        username = user_data.get('login', 'Unknown')
        name = user_data.get('name', username)
        email = user_data.get('email', 'Not public')
        user_type = user_data.get('type', 'User')
        is_site_admin = user_data.get('site_admin', False)

        # Build identity string
        identity = f'{username}'
        if name and name != username:
            identity += f' ({name})'

        # Determine permissions from scopes
        permissions = scopes if scopes else ['Unknown scopes']

        # Assess blast radius based on scopes and user type
        is_admin = is_site_admin
        has_write = any('write' in s or 'delete' in s or 'admin' in s for s in scopes)
        has_repo_access = any('repo' in s for s in scopes)

        if is_site_admin:
            blast_radius = Severity.CRITICAL
        elif has_repo_access and has_write:
            blast_radius = Severity.HIGH
        elif has_repo_access:
            blast_radius = Severity.MEDIUM
        elif scopes:
            blast_radius = Severity.LOW
        else:
            blast_radius = Severity.INFO

        # Determine pivot opportunities
        can_pivot_to = []

        if is_site_admin:
            can_pivot_to.append('All GitHub organizations and repositories')

        if has_repo_access:
            can_pivot_to.append('Private repositories')

        if 'workflow' in scopes:
            can_pivot_to.append('GitHub Actions secrets')

        if 'admin:org' in scopes:
            can_pivot_to.append('Organization settings and members')

        if 'admin:repo_hook' in scopes:
            can_pivot_to.append('Repository webhooks (potential RCE)')

        # Determine environment
        environment = 'production' if user_type in ['User', 'Organization'] else 'unknown'

        return VerificationResult(
            status=VerificationStatus.VERIFIED,
            method='github_user_api',
            identity=identity,
            permissions=permissions,
            can_pivot_to=can_pivot_to,
            blast_radius=blast_radius,
            environment=environment,
            metadata={
                'username': username,
                'email': email,
                'user_type': user_type,
                'site_admin': is_site_admin,
                'public_repos': user_data.get('public_repos', 0),
                'followers': user_data.get('followers', 0),
                'scopes': scopes,
            },
        )
