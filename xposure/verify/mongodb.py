"""MongoDB connection string verifier for X-POSURE."""

from .base import BaseVerifier, VerificationResult
from ..core.models import Finding, VerificationStatus, Severity

try:
    import pymongo
    PYMONGO_AVAILABLE = True
except ImportError:
    PYMONGO_AVAILABLE = False


class MongoDBVerifier(BaseVerifier):
    """Verifier for MongoDB connection strings using pymongo."""

    SUPPORTED_TYPES = [
        'mongodb_uri',
        'mongodb_connection_string',
        'mongo_uri',
    ]

    def can_verify(self, finding: Finding) -> bool:
        """Check if this is a MongoDB credential."""
        return finding.credential_type in self.SUPPORTED_TYPES

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify MongoDB connection string by attempting a connection.

        Args:
            finding: Finding with MongoDB URI

        Returns:
            Verification result with server info
        """
        if not PYMONGO_AVAILABLE:
            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                method='mongodb_connection',
                error='pymongo is not installed. Install with: pip install pymongo',
            )

        uri = finding.value

        try:
            # Attempt connection with a short timeout
            client = pymongo.MongoClient(
                uri,
                serverSelectionTimeoutMS=self.timeout * 1000,
                connectTimeoutMS=self.timeout * 1000,
                socketTimeoutMS=self.timeout * 1000,
            )

            # Test connection by getting server info
            server_info = client.server_info()

            # Extract server information
            version = server_info.get('version', 'unknown')
            git_version = server_info.get('gitVersion', '')

            # Try to list databases to check permissions
            databases = []
            permissions = []
            try:
                db_list = client.list_database_names()
                databases = db_list
                permissions.append(f'list_databases ({len(db_list)} databases)')
                for db_name in db_list[:10]:  # Limit to first 10
                    permissions.append(f'access:{db_name}')
            except Exception:
                permissions.append('list_databases:denied')

            # Parse URI for environment hints
            is_production = self._detect_production(uri)
            is_atlas = 'mongodb.net' in uri or 'mongodb+srv' in uri

            # Build identity
            identity = f'MongoDB {version}'
            if is_atlas:
                identity += ' (Atlas)'

            # Assess blast radius
            has_admin = 'admin' in databases
            blast_radius = self._assess_blast_radius(
                permissions=permissions,
                is_admin=has_admin,
                is_production=is_production,
            )

            # Pivot opportunities
            can_pivot_to = ['Read/write database collections']
            if has_admin:
                can_pivot_to.append('Database administration')
                can_pivot_to.append('User management')
            if len(databases) > 0:
                can_pivot_to.append(f'Access to {len(databases)} databases')

            # Clean up
            client.close()

            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                method='mongodb_connection',
                identity=identity,
                permissions=permissions,
                can_pivot_to=can_pivot_to,
                blast_radius=blast_radius,
                environment='production' if is_production else 'unknown',
                metadata={
                    'version': version,
                    'git_version': git_version,
                    'databases': databases[:10],
                    'database_count': len(databases),
                    'is_atlas': is_atlas,
                },
            )

        except pymongo.errors.OperationFailure as e:
            # Authentication failure
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='mongodb_connection',
                error=f'Authentication failed: {str(e)}',
            )
        except pymongo.errors.ServerSelectionTimeoutError:
            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                method='mongodb_connection',
                error='Connection timeout - server unreachable',
            )
        except pymongo.errors.ConfigurationError as e:
            return VerificationResult(
                status=VerificationStatus.INVALID,
                method='mongodb_connection',
                error=f'Invalid connection string: {str(e)}',
            )
        except Exception as e:
            return VerificationResult(
                status=VerificationStatus.ERROR,
                method='mongodb_connection',
                error=f'Connection error: {str(e)}',
            )

    def _detect_production(self, uri: str) -> bool:
        """
        Detect if the URI points to a production environment.

        Args:
            uri: MongoDB connection string

        Returns:
            True if likely production
        """
        prod_indicators = ['prod', 'production', 'live', 'main', 'primary']
        non_prod_indicators = ['dev', 'test', 'staging', 'local', 'localhost', '127.0.0.1']

        uri_lower = uri.lower()

        for indicator in non_prod_indicators:
            if indicator in uri_lower:
                return False

        for indicator in prod_indicators:
            if indicator in uri_lower:
                return True

        # Atlas clusters are typically production
        if 'mongodb.net' in uri_lower:
            return True

        return False
