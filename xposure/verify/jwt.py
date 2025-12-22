"""JWT token verifier for X-POSURE."""

import base64
import json
from datetime import datetime, timezone
from typing import Optional

from .base import BaseVerifier, VerificationResult
from ..core.models import Finding, VerificationStatus, Severity


class JWTVerifier(BaseVerifier):
    """Verifier for JWT tokens - decodes and checks validity."""

    SUPPORTED_TYPES = [
        'jwt_token',
        'bearer_token',
        'supabase_key',
        'supabase_service_key',
        'auth0_token',
    ]

    def can_verify(self, finding: Finding) -> bool:
        """Check if this is a JWT token."""
        # Check type or if value looks like a JWT
        if finding.credential_type in self.SUPPORTED_TYPES:
            return True

        # Check if value looks like a JWT (three base64 parts)
        value = finding.value
        if value and value.count('.') == 2:
            parts = value.split('.')
            if all(self._is_base64(p) for p in parts):
                return True

        return False

    def _is_base64(self, s: str) -> bool:
        """Check if string is valid base64url."""
        try:
            # Pad the string if needed
            padded = s + '=' * (4 - len(s) % 4)
            base64.urlsafe_b64decode(padded)
            return len(s) > 10  # Minimum length check
        except Exception:
            return False

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify JWT token by decoding and checking claims.

        Args:
            finding: Finding with JWT token

        Returns:
            Verification result with decoded claims
        """
        token = finding.value

        # Decode the JWT
        decoded = self._decode_jwt(token)

        if decoded is None:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='jwt_decode',
                error='Invalid JWT format - could not decode',
            )

        header, payload, signature_valid = decoded

        # Check expiration
        exp = payload.get('exp')
        iat = payload.get('iat')
        nbf = payload.get('nbf')

        now = datetime.now(timezone.utc).timestamp()
        is_expired = False
        expiry_info = None

        if exp:
            is_expired = exp < now
            try:
                expiry_dt = datetime.fromtimestamp(exp, timezone.utc)
                expiry_info = expiry_dt.isoformat()
            except Exception:
                expiry_info = str(exp)

        if is_expired:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='jwt_decode',
                error=f'JWT expired on {expiry_info}',
                metadata={
                    'header': header,
                    'claims': self._sanitize_payload(payload),
                    'expired_at': expiry_info,
                },
            )

        # Check not-before
        if nbf and nbf > now:
            try:
                nbf_dt = datetime.fromtimestamp(nbf, timezone.utc)
                nbf_info = nbf_dt.isoformat()
            except Exception:
                nbf_info = str(nbf)
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='jwt_decode',
                error=f'JWT not valid until {nbf_info}',
                metadata={
                    'header': header,
                    'claims': self._sanitize_payload(payload),
                    'not_before': nbf_info,
                },
            )

        # Extract identity information
        identity = self._extract_identity(payload)
        permissions = self._extract_permissions(payload)
        blast_radius = self._assess_blast_radius(payload, header)

        # Determine token type
        token_type = self._identify_token_type(header, payload)

        # Build metadata
        metadata = {
            'algorithm': header.get('alg', 'unknown'),
            'token_type': token_type,
            'issuer': payload.get('iss'),
            'audience': payload.get('aud'),
            'subject': payload.get('sub'),
            'issued_at': iat,
            'expires_at': exp,
            'expiry_info': expiry_info,
            'claims': self._sanitize_payload(payload),
        }

        # Determine status
        if signature_valid is False:
            status = VerificationStatus.LIKELY_VALID
            metadata['note'] = 'JWT decoded but signature not verified (no secret available)'
        else:
            status = VerificationStatus.LIKELY_VALID

        return VerificationResult(
            status=status,
            method='jwt_decode',
            identity=identity,
            permissions=permissions,
            can_pivot_to=self._determine_pivot_targets(payload, token_type),
            blast_radius=blast_radius,
            environment='production' if self._is_production(payload) else 'unknown',
            metadata=metadata,
        )

    def _decode_jwt(self, token: str) -> Optional[tuple[dict, dict, bool]]:
        """
        Decode a JWT token.

        Args:
            token: JWT token string

        Returns:
            Tuple of (header, payload, signature_valid) or None
        """
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None

            header_b64, payload_b64, signature = parts

            # Decode header
            header = self._decode_base64_json(header_b64)
            if header is None:
                return None

            # Decode payload
            payload = self._decode_base64_json(payload_b64)
            if payload is None:
                return None

            # We can't verify signature without the secret
            # but we can confirm the token structure is valid
            signature_valid = None  # Unknown - would need secret to verify

            return header, payload, signature_valid

        except Exception:
            return None

    def _decode_base64_json(self, s: str) -> Optional[dict]:
        """Decode base64url-encoded JSON."""
        try:
            # Add padding if needed
            padded = s + '=' * (4 - len(s) % 4)
            decoded = base64.urlsafe_b64decode(padded)
            return json.loads(decoded)
        except Exception:
            return None

    def _extract_identity(self, payload: dict) -> str:
        """Extract identity from JWT payload."""
        # Try common identity fields
        if 'email' in payload:
            return payload['email']
        if 'sub' in payload:
            sub = payload['sub']
            # Check if sub looks like an email
            if '@' in str(sub):
                return str(sub)
            return f"Subject: {sub}"
        if 'user_id' in payload:
            return f"User ID: {payload['user_id']}"
        if 'username' in payload:
            return payload['username']
        if 'name' in payload:
            return payload['name']
        if 'client_id' in payload:
            return f"Client: {payload['client_id']}"
        if 'azp' in payload:  # Authorized party (OAuth)
            return f"App: {payload['azp']}"

        return 'Unknown identity'

    def _extract_permissions(self, payload: dict) -> list:
        """Extract permissions/scopes from JWT payload."""
        permissions = []

        # Check scope claim (OAuth)
        if 'scope' in payload:
            scope = payload['scope']
            if isinstance(scope, str):
                permissions.extend(scope.split())
            elif isinstance(scope, list):
                permissions.extend(scope)

        # Check scopes claim
        if 'scopes' in payload:
            scopes = payload['scopes']
            if isinstance(scopes, list):
                permissions.extend(scopes)

        # Check permissions claim
        if 'permissions' in payload:
            perms = payload['permissions']
            if isinstance(perms, list):
                permissions.extend(perms)

        # Check roles claim
        if 'roles' in payload:
            roles = payload['roles']
            if isinstance(roles, list):
                permissions.extend([f"role:{r}" for r in roles])

        # Check role claim (singular)
        if 'role' in payload:
            permissions.append(f"role:{payload['role']}")

        # Check groups claim
        if 'groups' in payload:
            groups = payload['groups']
            if isinstance(groups, list):
                permissions.extend([f"group:{g}" for g in groups])

        # Check Supabase-specific claims
        if 'app_metadata' in payload:
            app_meta = payload['app_metadata']
            if isinstance(app_meta, dict):
                if 'role' in app_meta:
                    permissions.append(f"supabase_role:{app_meta['role']}")

        if not permissions:
            permissions.append('No explicit permissions found')

        return permissions

    def _assess_blast_radius(self, payload: dict, header: dict) -> Severity:
        """Assess blast radius based on JWT claims."""
        # Check for admin/service indicators
        role = payload.get('role', '')
        roles = payload.get('roles', [])
        permissions = payload.get('permissions', [])
        scope = payload.get('scope', '')

        high_priv_indicators = [
            'admin', 'superuser', 'root', 'owner', 'service_role',
            'write', 'delete', 'manage', 'full_access'
        ]

        # Check role
        if any(ind in str(role).lower() for ind in high_priv_indicators):
            return Severity.CRITICAL

        # Check roles list
        if isinstance(roles, list):
            for r in roles:
                if any(ind in str(r).lower() for ind in high_priv_indicators):
                    return Severity.CRITICAL

        # Check permissions
        if isinstance(permissions, list):
            for p in permissions:
                if any(ind in str(p).lower() for ind in high_priv_indicators):
                    return Severity.HIGH

        # Check scope
        if any(ind in str(scope).lower() for ind in high_priv_indicators):
            return Severity.HIGH

        # Check for service account / machine token
        if payload.get('gty') == 'client-credentials':
            return Severity.HIGH

        # Check audience for sensitive services
        aud = payload.get('aud', '')
        if isinstance(aud, str):
            if any(s in aud for s in ['admin', 'api', 'internal']):
                return Severity.HIGH

        return Severity.MEDIUM

    def _identify_token_type(self, header: dict, payload: dict) -> str:
        """Identify the type of JWT token."""
        iss = payload.get('iss', '')
        aud = payload.get('aud', '')

        # Supabase
        if 'supabase' in str(iss).lower():
            if payload.get('role') == 'service_role':
                return 'Supabase Service Role'
            return 'Supabase'

        # Auth0
        if 'auth0' in str(iss).lower():
            return 'Auth0'

        # Firebase
        if 'firebase' in str(iss).lower() or 'securetoken.google.com' in str(iss):
            return 'Firebase Auth'

        # AWS Cognito
        if 'cognito' in str(iss).lower():
            return 'AWS Cognito'

        # Azure AD
        if 'login.microsoftonline.com' in str(iss) or 'sts.windows.net' in str(iss):
            return 'Azure AD'

        # Google
        if 'accounts.google.com' in str(iss):
            return 'Google OAuth'

        # Okta
        if 'okta' in str(iss).lower():
            return 'Okta'

        # Generic OAuth
        if 'scope' in payload or 'client_id' in payload:
            return 'OAuth Token'

        return 'JWT Token'

    def _determine_pivot_targets(self, payload: dict, token_type: str) -> list:
        """Determine potential pivot targets."""
        targets = []

        if 'supabase' in token_type.lower():
            if 'service' in token_type.lower():
                targets.append('Full Supabase database access')
                targets.append('Supabase Storage buckets')
                targets.append('Supabase Edge Functions')
            else:
                targets.append('Supabase user data')

        elif 'auth0' in token_type.lower():
            targets.append('Auth0 protected APIs')

        elif 'firebase' in token_type.lower():
            targets.append('Firebase services')
            targets.append('Firestore database')

        elif 'cognito' in token_type.lower():
            targets.append('AWS Cognito user pools')
            targets.append('AWS API Gateway endpoints')

        elif 'azure' in token_type.lower():
            targets.append('Azure AD protected resources')
            targets.append('Microsoft Graph API')

        # Check audience for specific services
        aud = payload.get('aud', '')
        if isinstance(aud, str) and aud:
            targets.append(f'Services at: {aud[:50]}')
        elif isinstance(aud, list):
            for a in aud[:3]:
                targets.append(f'Service: {str(a)[:50]}')

        if not targets:
            targets.append('API endpoints accepting this token')

        return targets

    def _is_production(self, payload: dict) -> bool:
        """Check if token appears to be production."""
        iss = str(payload.get('iss', '')).lower()
        aud = str(payload.get('aud', '')).lower()

        dev_indicators = ['dev', 'test', 'staging', 'local', 'sandbox']

        for indicator in dev_indicators:
            if indicator in iss or indicator in aud:
                return False

        return True

    def _sanitize_payload(self, payload: dict) -> dict:
        """Sanitize payload for safe display (remove sensitive values)."""
        sanitized = {}

        # Fields to include as-is
        safe_fields = [
            'iss', 'sub', 'aud', 'exp', 'iat', 'nbf', 'jti',
            'scope', 'scopes', 'roles', 'role', 'permissions',
            'email', 'name', 'azp', 'gty', 'client_id'
        ]

        for key in safe_fields:
            if key in payload:
                value = payload[key]
                # Truncate long strings
                if isinstance(value, str) and len(value) > 100:
                    value = value[:100] + '...'
                sanitized[key] = value

        # Add count of other claims
        other_count = len(payload) - len(sanitized)
        if other_count > 0:
            sanitized['_other_claims'] = other_count

        return sanitized
