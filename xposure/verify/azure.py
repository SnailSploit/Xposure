"""Azure credential verifier for X-POSURE."""

from .base import BaseVerifier, VerificationResult
from ..core.models import Finding, VerificationStatus, Severity


class AzureVerifier(BaseVerifier):
    """Verifier for Azure credentials using Azure APIs."""

    SUPPORTED_TYPES = [
        'azure_client_secret',
        'azure_sas',
        'azure_connection_string',
    ]

    def can_verify(self, finding: Finding) -> bool:
        """Check if this is an Azure credential."""
        return finding.credential_type in self.SUPPORTED_TYPES

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify Azure credential.

        Args:
            finding: Finding with Azure credential

        Returns:
            Verification result
        """
        if finding.credential_type == 'azure_client_secret':
            return await self._verify_client_secret(finding)
        elif finding.credential_type == 'azure_sas':
            return await self._verify_sas_token(finding.value)
        elif finding.credential_type == 'azure_connection_string':
            return await self._verify_connection_string(finding.value)
        else:
            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                method='azure_unknown',
                error=f'Unknown Azure credential type: {finding.credential_type}',
            )

    async def _verify_client_secret(self, finding: Finding) -> VerificationResult:
        """
        Verify Azure AD client secret by attempting OAuth token request.

        Note: Requires paired client_id and tenant_id for full verification.

        Args:
            finding: Finding with client secret and potentially paired credentials

        Returns:
            Verification result
        """
        client_secret = finding.value

        # Check for paired credentials
        paired = finding.paired_credentials
        client_id = paired.get('azure_client_id')
        tenant_id = paired.get('azure_tenant_id')

        if not client_id or not tenant_id:
            # Without client_id and tenant_id, we can only validate format
            return VerificationResult(
                status=VerificationStatus.LIKELY_VALID,
                method='azure_client_secret_format',
                identity='Azure Client Secret',
                permissions=['Unable to verify without client_id and tenant_id'],
                can_pivot_to=['Azure resources (requires client_id and tenant_id to verify)'],
                blast_radius=Severity.HIGH,
                metadata={
                    'note': 'Client secret format appears valid. Full verification requires client_id and tenant_id.',
                    'has_client_id': bool(client_id),
                    'has_tenant_id': bool(tenant_id),
                },
            )

        # Attempt OAuth token request
        token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'

        data = {
            'client_id': client_id,
            'client_secret': client_secret,
            'scope': 'https://graph.microsoft.com/.default',
            'grant_type': 'client_credentials',
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'X-POSURE/4.0',
        }

        success, response_data, error = await self.safe_request(
            method='POST',
            url=token_url,
            headers=headers,
            data=data,
        )

        if success and response_data and 'access_token' in response_data:
            # Successfully obtained token - credentials are valid
            token_type = response_data.get('token_type', 'Bearer')
            expires_in = response_data.get('expires_in', 0)

            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                method='azure_oauth_token',
                identity=f'Service Principal: {client_id}',
                permissions=['Microsoft Graph API access (other permissions may exist)'],
                can_pivot_to=[
                    'Azure AD directory data',
                    'Azure resources authorized for this service principal',
                ],
                blast_radius=Severity.CRITICAL,
                environment='production',
                metadata={
                    'client_id': client_id,
                    'tenant_id': tenant_id,
                    'token_type': token_type,
                    'expires_in': expires_in,
                },
            )
        elif error and 'invalid_client' in str(error).lower():
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='azure_oauth_token',
                error='Invalid client secret or client_id',
            )
        elif error and 'tenant' in str(error).lower():
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='azure_oauth_token',
                error='Invalid or unknown tenant_id',
            )
        else:
            return VerificationResult(
                status=VerificationStatus.LIKELY_VALID,
                method='azure_oauth_token',
                identity=f'Service Principal: {client_id}',
                permissions=['Unable to verify permissions'],
                blast_radius=Severity.HIGH,
                error=error or 'Unexpected response from Azure AD',
            )

    async def _verify_sas_token(self, sas_token: str) -> VerificationResult:
        """
        Verify Azure SAS token by parsing and checking expiration.

        Note: Full verification would require testing against the actual
        Azure Storage resource, which we don't have.

        Args:
            sas_token: SAS token string

        Returns:
            Verification result
        """
        import urllib.parse
        from datetime import datetime

        try:
            # Parse SAS token parameters
            params = urllib.parse.parse_qs(sas_token)
        except Exception:
            params = {}

        # Extract key parameters
        sv = params.get('sv', ['unknown'])[0]  # API version
        se = params.get('se', [None])[0]  # Expiry time
        sp = params.get('sp', [''])[0]  # Permissions
        sr = params.get('sr', [''])[0]  # Resource type
        sig = params.get('sig', [None])[0]  # Signature

        # Check if signature exists
        if not sig:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='azure_sas_parse',
                error='No signature found in SAS token',
            )

        # Check expiration
        is_expired = False
        expiry_str = 'Unknown'
        if se:
            try:
                # Parse ISO format date
                expiry = datetime.fromisoformat(se.replace('Z', '+00:00'))
                expiry_str = expiry.isoformat()
                is_expired = expiry < datetime.now(expiry.tzinfo)
            except Exception:
                pass

        if is_expired:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='azure_sas_parse',
                error=f'SAS token expired on {expiry_str}',
            )

        # Parse permissions
        permission_map = {
            'r': 'Read',
            'w': 'Write',
            'd': 'Delete',
            'l': 'List',
            'a': 'Add',
            'c': 'Create',
            'u': 'Update',
            'p': 'Process',
        }
        permissions = [permission_map.get(c, c) for c in sp]

        # Parse resource type
        resource_map = {
            'b': 'Blob',
            'c': 'Container',
            'f': 'File',
            's': 'Share',
            'd': 'Directory',
        }
        resource_type = resource_map.get(sr, sr or 'Unknown')

        # Assess blast radius based on permissions
        has_write = any(p in ['Write', 'Delete', 'Update', 'Create'] for p in permissions)

        if has_write:
            blast_radius = Severity.HIGH
        else:
            blast_radius = Severity.MEDIUM

        return VerificationResult(
            status=VerificationStatus.LIKELY_VALID,
            method='azure_sas_parse',
            identity=f'Azure SAS Token ({resource_type})',
            permissions=permissions if permissions else ['Unknown permissions'],
            can_pivot_to=[f'Azure Storage {resource_type} resources'],
            blast_radius=blast_radius,
            environment='production',
            metadata={
                'api_version': sv,
                'expiry': expiry_str,
                'resource_type': resource_type,
                'permissions': sp,
                'note': 'Token parsed but not verified against actual resource',
            },
        )

    async def _verify_connection_string(self, connection_string: str) -> VerificationResult:
        """
        Parse and verify Azure connection string.

        Args:
            connection_string: Azure service connection string

        Returns:
            Verification result
        """
        # Parse connection string key=value pairs
        params = {}
        try:
            for part in connection_string.split(';'):
                if '=' in part:
                    key, value = part.split('=', 1)
                    params[key.lower()] = value
        except Exception:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='azure_connection_parse',
                error='Unable to parse connection string',
            )

        # Identify service type
        if 'accountname' in params:
            service_type = 'Storage'
            account_name = params.get('accountname', 'Unknown')
            identity = f'Azure Storage: {account_name}'
        elif 'hostname' in params:
            service_type = 'Service Bus'
            identity = f'Azure Service Bus: {params.get("hostname", "Unknown")}'
        elif 'server' in params:
            service_type = 'SQL Database'
            identity = f'Azure SQL: {params.get("server", "Unknown")}'
        else:
            service_type = 'Unknown Azure Service'
            identity = 'Azure Connection String'

        # Check for key/credentials
        has_key = 'accountkey' in params or 'sharedaccesskey' in params
        has_password = 'password' in params

        if not has_key and not has_password:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='azure_connection_parse',
                error='No credentials found in connection string',
            )

        # Determine permissions and blast radius
        permissions = [f'{service_type} access']

        if service_type == 'Storage':
            can_pivot_to = ['Storage blobs, queues, tables, and files']
            blast_radius = Severity.HIGH
        elif service_type == 'SQL Database':
            can_pivot_to = ['Database tables and data']
            blast_radius = Severity.CRITICAL
        elif service_type == 'Service Bus':
            can_pivot_to = ['Message queues and topics']
            blast_radius = Severity.HIGH
        else:
            can_pivot_to = ['Azure resources']
            blast_radius = Severity.HIGH

        return VerificationResult(
            status=VerificationStatus.LIKELY_VALID,
            method='azure_connection_parse',
            identity=identity,
            permissions=permissions,
            can_pivot_to=can_pivot_to,
            blast_radius=blast_radius,
            environment='production',
            metadata={
                'service_type': service_type,
                'has_key': has_key,
                'has_password': has_password,
                'note': 'Connection string parsed. Full verification requires connecting to the service.',
            },
        )
