"""Redis connection string verifier for X-POSURE."""

from .base import BaseVerifier, VerificationResult
from ..core.models import Finding, VerificationStatus, Severity

try:
    import redis as redis_lib
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class RedisVerifier(BaseVerifier):
    """Verifier for Redis connection strings using redis-py."""

    SUPPORTED_TYPES = [
        'redis_uri',
        'redis_url',
        'redis_connection_string',
    ]

    def can_verify(self, finding: Finding) -> bool:
        """Check if this is a Redis credential."""
        return finding.credential_type in self.SUPPORTED_TYPES

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify Redis connection string by attempting a PING.

        Args:
            finding: Finding with Redis URI

        Returns:
            Verification result with server info
        """
        if not REDIS_AVAILABLE:
            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                method='redis_connection',
                error='redis is not installed. Install with: pip install redis',
            )

        uri = finding.value

        try:
            # Attempt connection with timeout
            client = redis_lib.Redis.from_url(
                uri,
                socket_timeout=self.timeout,
                socket_connect_timeout=self.timeout,
            )

            # Test connectivity with PING
            pong = client.ping()

            if not pong:
                return VerificationResult(
                    status=VerificationStatus.INVALID,
                    method='redis_connection',
                    error='PING did not return PONG',
                )

            # Get server info
            permissions = []
            server_info = {}
            try:
                info = client.info()
                server_info = {
                    'redis_version': info.get('redis_version', 'unknown'),
                    'os': info.get('os', 'unknown'),
                    'connected_clients': info.get('connected_clients', 0),
                    'used_memory_human': info.get('used_memory_human', 'unknown'),
                    'role': info.get('role', 'unknown'),
                    'db_count': sum(1 for k in info if k.startswith('db')),
                }
                permissions.append(f"redis_version:{info.get('redis_version', 'unknown')}")
                permissions.append(f"role:{info.get('role', 'unknown')}")
                permissions.append('info:accessible')

                # Count total keys across all databases
                total_keys = 0
                for key, value in info.items():
                    if key.startswith('db') and isinstance(value, dict):
                        total_keys += value.get('keys', 0)
                if total_keys > 0:
                    permissions.append(f'total_keys:{total_keys}')
                    server_info['total_keys'] = total_keys

            except redis_lib.exceptions.ResponseError:
                permissions.append('info:denied')

            # Check if CONFIG is accessible
            try:
                client.config_get('maxmemory')
                permissions.append('config:accessible')
            except (redis_lib.exceptions.ResponseError, redis_lib.exceptions.AuthenticationError):
                permissions.append('config:denied')

            # Try to list keys (limited)
            try:
                key_count = client.dbsize()
                permissions.append(f'dbsize:{key_count}')
                server_info['current_db_keys'] = key_count
            except redis_lib.exceptions.ResponseError:
                pass

            # Build identity
            redis_version = server_info.get('redis_version', 'unknown')
            role = server_info.get('role', 'unknown')
            identity = f'Redis {redis_version} ({role})'

            # Detect environment
            is_production = self._detect_production(uri)

            # Assess blast radius
            has_config = 'config:accessible' in permissions
            blast_radius = self._assess_blast_radius(
                permissions=permissions,
                is_admin=has_config,
                is_production=is_production,
            )

            # Pivot opportunities
            can_pivot_to = ['Read/write cached data']
            if has_config:
                can_pivot_to.append('Server configuration (potential RCE via CONFIG SET)')
            if role == 'master':
                can_pivot_to.append('Master node - full read/write access')
            total_keys = server_info.get('total_keys', 0)
            if total_keys > 0:
                can_pivot_to.append(f'Access to {total_keys} keys')

            # Clean up
            client.close()

            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                method='redis_connection',
                identity=identity,
                permissions=permissions,
                can_pivot_to=can_pivot_to,
                blast_radius=blast_radius,
                environment='production' if is_production else 'unknown',
                metadata=server_info,
            )

        except redis_lib.exceptions.AuthenticationError as e:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='redis_connection',
                error=f'Authentication failed: {str(e)}',
            )
        except redis_lib.exceptions.ConnectionError as e:
            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                method='redis_connection',
                error=f'Connection error: {str(e)}',
            )
        except redis_lib.exceptions.TimeoutError:
            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                method='redis_connection',
                error='Connection timeout - server unreachable',
            )
        except Exception as e:
            return VerificationResult(
                status=VerificationStatus.ERROR,
                method='redis_connection',
                error=f'Unexpected error: {str(e)}',
            )

    def _detect_production(self, uri: str) -> bool:
        """
        Detect if the URI points to a production environment.

        Args:
            uri: Redis connection string

        Returns:
            True if likely production
        """
        uri_lower = uri.lower()

        non_prod_indicators = ['dev', 'test', 'staging', 'local', 'localhost', '127.0.0.1']
        prod_indicators = ['prod', 'production', 'live', 'main', 'primary']

        for indicator in non_prod_indicators:
            if indicator in uri_lower:
                return False

        for indicator in prod_indicators:
            if indicator in uri_lower:
                return True

        # Cloud-hosted Redis is typically production
        cloud_indicators = ['redis.cache.windows.net', 'cache.amazonaws.com', 'upstash.io', 'redislabs.com']
        for indicator in cloud_indicators:
            if indicator in uri_lower:
                return True

        return False
