"""HashiCorp Vault token verifier for X-POSURE."""

from .base import BaseVerifier, VerificationResult
from ..core.models import Finding, VerificationStatus, Severity


class VaultVerifier(BaseVerifier):
    """Verifier for HashiCorp Vault tokens using the lookup-self endpoint."""

    SUPPORTED_TYPES = [
        'vault_token',
        'hashicorp_vault_token',
    ]

    def can_verify(self, finding: Finding) -> bool:
        """Check if this is a Vault credential."""
        return finding.credential_type in self.SUPPORTED_TYPES

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify Vault token using the lookup-self endpoint.

        Expects finding.paired_credentials or finding.metadata to contain
        'vault_addr' for the Vault server address.

        Args:
            finding: Finding with Vault token

        Returns:
            Verification result with token info
        """
        token = finding.value

        # Determine Vault address
        vault_addr = (
            finding.paired_credentials.get('vault_addr', '')
            or finding.metadata.get('vault_addr', '')
            or 'https://vault.example.com:8200'
        )

        # Strip trailing slash
        vault_addr = vault_addr.rstrip('/')

        headers = {
            'X-Vault-Token': token,
            'Content-Type': 'application/json',
        }

        success, data, error = await self.safe_request(
            method='GET',
            url=f'{vault_addr}/v1/auth/token/lookup-self',
            headers=headers,
        )

        if not success:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='vault_token_lookup',
                error=error or 'Token is invalid or Vault is unreachable',
            )

        # Extract token information
        token_data = data.get('data', data)

        display_name = token_data.get('display_name', 'Unknown')
        token_id = token_data.get('id', '')
        accessor = token_data.get('accessor', '')
        policies = token_data.get('policies', [])
        token_type = token_data.get('type', 'unknown')
        orphan = token_data.get('orphan', False)
        renewable = token_data.get('renewable', False)
        ttl = token_data.get('ttl', 0)
        explicit_max_ttl = token_data.get('explicit_max_ttl', 0)
        creation_time = token_data.get('creation_time', 0)
        entity_id = token_data.get('entity_id', '')
        path = token_data.get('path', '')
        meta = token_data.get('meta', {})
        num_uses = token_data.get('num_uses', 0)

        # Build identity
        identity = f'{display_name}'
        if entity_id:
            identity += f' (entity: {entity_id})'

        # Determine permissions from policies
        permissions = list(policies) if policies else ['no policies']
        if orphan:
            permissions.append('orphan_token')
        if renewable:
            permissions.append('renewable')
        permissions.append(f'type:{token_type}')

        # Check for root/admin access
        is_root = 'root' in policies
        is_admin = is_root or any('admin' in p for p in policies)

        # Detect environment
        is_production = self._detect_production(vault_addr, policies)

        # Assess blast radius
        blast_radius = self._assess_blast_radius(
            permissions=permissions,
            is_admin=is_admin,
            is_production=is_production,
        )

        # Pivot opportunities
        can_pivot_to = []
        if is_root:
            can_pivot_to.append('Full root access to all Vault secrets')
            can_pivot_to.append('Create/revoke tokens and policies')
            can_pivot_to.append('Access all secret engines')
        else:
            can_pivot_to.append('Access secrets allowed by policies')
        if 'default' in policies:
            can_pivot_to.append('Token self-management (lookup, renew)')

        # Try to list accessible secret mounts
        mounts = await self._get_mounts(vault_addr, token)
        if mounts:
            mount_names = list(mounts.keys())[:10]
            can_pivot_to.append(f'Secret engines: {", ".join(mount_names)}')

        return VerificationResult(
            status=VerificationStatus.VERIFIED,
            method='vault_token_lookup',
            identity=identity,
            permissions=permissions,
            can_pivot_to=can_pivot_to,
            blast_radius=blast_radius,
            environment='production' if is_production else 'unknown',
            metadata={
                'display_name': display_name,
                'accessor': accessor,
                'policies': policies,
                'token_type': token_type,
                'orphan': orphan,
                'renewable': renewable,
                'ttl': ttl,
                'explicit_max_ttl': explicit_max_ttl,
                'creation_time': creation_time,
                'entity_id': entity_id,
                'path': path,
                'meta': meta,
                'num_uses': num_uses,
                'vault_addr': vault_addr,
            },
        )

    async def _get_mounts(self, vault_addr: str, token: str) -> dict:
        """
        List accessible secret engine mounts.

        Args:
            vault_addr: Vault server address
            token: Vault token

        Returns:
            Mounts data or None
        """
        headers = {
            'X-Vault-Token': token,
            'Content-Type': 'application/json',
        }

        success, data, error = await self.safe_request(
            method='GET',
            url=f'{vault_addr}/v1/sys/mounts',
            headers=headers,
        )

        if success and data:
            return data.get('data', data)

        return None

    def _detect_production(self, vault_addr: str, policies: list) -> bool:
        """
        Detect if the Vault instance is production.

        Args:
            vault_addr: Vault server address
            policies: Token policies

        Returns:
            True if likely production
        """
        combined = f'{vault_addr} {" ".join(policies)}'.lower()

        non_prod_indicators = ['dev', 'test', 'staging', 'local', 'localhost', '127.0.0.1']
        prod_indicators = ['prod', 'production', 'live']

        for indicator in non_prod_indicators:
            if indicator in combined:
                return False

        for indicator in prod_indicators:
            if indicator in combined:
                return True

        # Root tokens in any environment are production-critical
        if 'root' in policies:
            return True

        return False
