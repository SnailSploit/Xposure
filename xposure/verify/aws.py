"""AWS credential verifier for X-POSURE."""

import hashlib
import hmac
from datetime import datetime
from urllib.parse import quote

from .base import BaseVerifier, VerificationResult
from ..core.models import Finding, VerificationStatus, Severity


class AWSVerifier(BaseVerifier):
    """Verifier for AWS credentials using STS GetCallerIdentity."""

    SUPPORTED_TYPES = ['aws_access_key', 'aws_secret_key']

    def can_verify(self, finding: Finding) -> bool:
        """Check if this is an AWS credential."""
        return finding.credential_type in self.SUPPORTED_TYPES

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify AWS credentials using STS GetCallerIdentity.

        Args:
            finding: Finding with AWS credentials

        Returns:
            Verification result with identity and permissions
        """
        # Need both access key and secret key
        access_key = None
        secret_key = None

        if finding.credential_type == 'aws_access_key':
            access_key = finding.value

            # Try to find paired secret key
            if finding.paired_credentials and 'aws_secret_key' in finding.paired_credentials:
                secret_key = finding.paired_credentials['aws_secret_key']
        elif finding.credential_type == 'aws_secret_key':
            secret_key = finding.value

            # Try to find paired access key
            if finding.paired_credentials and 'aws_access_key' in finding.paired_credentials:
                access_key = finding.paired_credentials['aws_access_key']

        # Need both keys to verify
        if not access_key or not secret_key:
            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                method='aws_sts',
                error='Missing paired credential (need both access key and secret key)',
            )

        # Call STS GetCallerIdentity
        try:
            identity_data = await self._get_caller_identity(access_key, secret_key)

            if identity_data:
                return await self._process_identity(identity_data, access_key)
            else:
                return VerificationResult(
                    status=VerificationStatus.INVALID,
                    method='aws_sts',
                    error='GetCallerIdentity failed - likely invalid credentials',
                )

        except Exception as e:
            return VerificationResult(
                status=VerificationStatus.ERROR,
                method='aws_sts',
                error=f'Verification error: {str(e)}',
            )

    async def _get_caller_identity(self, access_key: str, secret_key: str) -> dict:
        """
        Call AWS STS GetCallerIdentity API.

        Args:
            access_key: AWS access key
            secret_key: AWS secret key

        Returns:
            Response data or None if failed
        """
        # AWS STS endpoint
        region = 'us-east-1'
        service = 'sts'
        host = f'sts.{region}.amazonaws.com'
        endpoint = f'https://{host}/'

        # Request parameters
        method = 'POST'
        params = {
            'Action': 'GetCallerIdentity',
            'Version': '2011-06-15',
        }

        # Generate signed request
        headers = self._sign_request(
            method=method,
            host=host,
            uri='/',
            params=params,
            access_key=access_key,
            secret_key=secret_key,
            region=region,
            service=service,
        )

        # Make request
        success, data, error = await self.safe_request(
            method=method,
            url=endpoint,
            headers=headers,
            data=params,
        )

        if success and data:
            # Parse XML response (simple extraction)
            response_text = data.get('response', '')

            if 'UserId' in response_text and 'Account' in response_text and 'Arn' in response_text:
                # Extract values using simple string parsing
                user_id = self._extract_xml_value(response_text, 'UserId')
                account = self._extract_xml_value(response_text, 'Account')
                arn = self._extract_xml_value(response_text, 'Arn')

                return {
                    'UserId': user_id,
                    'Account': account,
                    'Arn': arn,
                }

        return None

    def _sign_request(
        self,
        method: str,
        host: str,
        uri: str,
        params: dict,
        access_key: str,
        secret_key: str,
        region: str,
        service: str,
    ) -> dict:
        """
        Generate AWS Signature V4 headers.

        Args:
            method: HTTP method
            host: API host
            uri: Request URI
            params: Query parameters
            access_key: AWS access key
            secret_key: AWS secret key
            region: AWS region
            service: AWS service name

        Returns:
            Headers dictionary
        """
        # Get current timestamp
        t = datetime.utcnow()
        amz_date = t.strftime('%Y%m%dT%H%M%SZ')
        date_stamp = t.strftime('%Y%m%d')

        # Create canonical request
        canonical_uri = uri
        canonical_querystring = ''
        canonical_headers = f'host:{host}\nx-amz-date:{amz_date}\n'
        signed_headers = 'host;x-amz-date'
        payload_hash = hashlib.sha256(''.encode('utf-8')).hexdigest()

        canonical_request = '\n'.join([
            method,
            canonical_uri,
            canonical_querystring,
            canonical_headers,
            signed_headers,
            payload_hash,
        ])

        # Create string to sign
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = f'{date_stamp}/{region}/{service}/aws4_request'
        string_to_sign = '\n'.join([
            algorithm,
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode('utf-8')).hexdigest(),
        ])

        # Calculate signature
        signing_key = self._get_signature_key(secret_key, date_stamp, region, service)
        signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

        # Create authorization header
        authorization_header = (
            f'{algorithm} '
            f'Credential={access_key}/{credential_scope}, '
            f'SignedHeaders={signed_headers}, '
            f'Signature={signature}'
        )

        # Return headers
        return {
            'Host': host,
            'X-Amz-Date': amz_date,
            'Authorization': authorization_header,
            'Content-Type': 'application/x-www-form-urlencoded',
        }

    def _get_signature_key(self, key: str, date_stamp: str, region: str, service: str) -> bytes:
        """Generate AWS signing key."""
        k_date = hmac.new(f'AWS4{key}'.encode('utf-8'), date_stamp.encode('utf-8'), hashlib.sha256).digest()
        k_region = hmac.new(k_date, region.encode('utf-8'), hashlib.sha256).digest()
        k_service = hmac.new(k_region, service.encode('utf-8'), hashlib.sha256).digest()
        k_signing = hmac.new(k_service, 'aws4_request'.encode('utf-8'), hashlib.sha256).digest()
        return k_signing

    def _extract_xml_value(self, xml: str, tag: str) -> str:
        """Extract value from XML tag."""
        start_tag = f'<{tag}>'
        end_tag = f'</{tag}>'

        start_idx = xml.find(start_tag)
        end_idx = xml.find(end_tag)

        if start_idx != -1 and end_idx != -1:
            return xml[start_idx + len(start_tag):end_idx].strip()

        return ''

    async def _process_identity(self, identity_data: dict, access_key: str) -> VerificationResult:
        """
        Process GetCallerIdentity response.

        Args:
            identity_data: Identity data from API
            access_key: Access key ID

        Returns:
            Verification result
        """
        arn = identity_data.get('Arn', '')
        account_id = identity_data.get('Account', '')
        user_id = identity_data.get('UserId', '')

        # Determine identity type
        identity_type = 'Unknown'
        identity_name = ''

        if ':user/' in arn:
            identity_type = 'IAM User'
            identity_name = arn.split(':user/')[-1]
        elif ':role/' in arn:
            identity_type = 'IAM Role'
            identity_name = arn.split(':role/')[-1]
        elif ':root' in arn:
            identity_type = 'Root Account'
            identity_name = 'root'
        elif ':assumed-role/' in arn:
            identity_type = 'Assumed Role'
            identity_name = arn.split(':assumed-role/')[-1]

        # Assess blast radius
        is_root = identity_type == 'Root Account'
        is_admin = 'admin' in identity_name.lower() or is_root

        blast_radius = self._assess_blast_radius(
            permissions=[],  # We don't enumerate permissions yet
            is_admin=is_admin,
            is_production=True,  # Assume production unless proven otherwise
        )

        # Build permissions list (basic inference)
        permissions = []
        if is_root:
            permissions = ['ALL_PERMISSIONS']
        elif is_admin:
            permissions = ['LIKELY_ADMIN']
        else:
            permissions = ['AUTHENTICATED']

        # Pivot opportunities
        can_pivot_to = []
        if is_root or is_admin:
            can_pivot_to = [
                'All AWS services',
                'EC2 instances',
                'S3 buckets',
                'RDS databases',
                'Lambda functions',
            ]
        elif identity_type == 'IAM Role':
            can_pivot_to = ['Services using this role']

        return VerificationResult(
            status=VerificationStatus.VERIFIED,
            method='aws_sts_get_caller_identity',
            identity=f'{identity_type}: {identity_name}',
            permissions=permissions,
            can_pivot_to=can_pivot_to,
            blast_radius=blast_radius,
            environment='production',
            metadata={
                'arn': arn,
                'account_id': account_id,
                'user_id': user_id,
                'access_key': access_key,
                'identity_type': identity_type,
            },
        )
