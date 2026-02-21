"""PostgreSQL connection string verifier for X-POSURE."""

from .base import BaseVerifier, VerificationResult
from ..core.models import Finding, VerificationStatus, Severity

try:
    import psycopg2
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False


class PostgresVerifier(BaseVerifier):
    """Verifier for PostgreSQL connection strings using psycopg2."""

    SUPPORTED_TYPES = [
        'postgres_uri',
        'postgresql_uri',
        'postgres_connection_string',
        'database_url',
    ]

    def can_verify(self, finding: Finding) -> bool:
        """Check if this is a PostgreSQL credential."""
        return finding.credential_type in self.SUPPORTED_TYPES

    async def verify(self, finding: Finding) -> VerificationResult:
        """
        Verify PostgreSQL connection string by attempting a connection.

        Args:
            finding: Finding with PostgreSQL URI

        Returns:
            Verification result with server info
        """
        if not PSYCOPG2_AVAILABLE:
            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                method='postgres_connection',
                error='psycopg2 is not installed. Install with: pip install psycopg2-binary',
            )

        uri = finding.value
        conn = None

        try:
            # Attempt connection with timeout
            conn = psycopg2.connect(uri, connect_timeout=self.timeout)
            cursor = conn.cursor()

            # Test basic connectivity
            cursor.execute('SELECT 1')

            # Get server version
            cursor.execute('SELECT version()')
            version_row = cursor.fetchone()
            version = version_row[0] if version_row else 'unknown'

            # Get current user and database
            cursor.execute('SELECT current_user, current_database()')
            user_row = cursor.fetchone()
            current_user = user_row[0] if user_row else 'unknown'
            current_db = user_row[1] if user_row else 'unknown'

            # Check if superuser
            cursor.execute("SELECT usesuper FROM pg_user WHERE usename = current_user")
            super_row = cursor.fetchone()
            is_superuser = super_row[0] if super_row else False

            # List accessible databases
            databases = []
            permissions = []
            try:
                cursor.execute(
                    "SELECT datname FROM pg_database WHERE datallowconn = true ORDER BY datname"
                )
                databases = [row[0] for row in cursor.fetchall()]
                permissions.append(f'databases_visible:{len(databases)}')
            except Exception:
                permissions.append('list_databases:denied')

            # Check table access in current database
            table_count = 0
            try:
                cursor.execute(
                    "SELECT count(*) FROM information_schema.tables "
                    "WHERE table_schema NOT IN ('pg_catalog', 'information_schema')"
                )
                count_row = cursor.fetchone()
                table_count = count_row[0] if count_row else 0
                permissions.append(f'tables_accessible:{table_count}')
            except Exception:
                permissions.append('list_tables:denied')

            # Build permissions list
            permissions.insert(0, f'user:{current_user}')
            permissions.insert(1, f'database:{current_db}')
            if is_superuser:
                permissions.append('superuser')

            # Build identity
            identity = f'{current_user}@{current_db}'

            # Detect environment
            is_production = self._detect_production(uri, current_db)

            # Assess blast radius
            blast_radius = self._assess_blast_radius(
                permissions=permissions,
                is_admin=is_superuser,
                is_production=is_production,
            )

            # Pivot opportunities
            can_pivot_to = [f'Read/write access to {current_db}']
            if is_superuser:
                can_pivot_to.append('Full superuser access to all databases')
                can_pivot_to.append('Create/drop databases and roles')
                can_pivot_to.append('Read pg_shadow (password hashes)')
            if table_count > 0:
                can_pivot_to.append(f'Access to {table_count} tables')
            if len(databases) > 1:
                can_pivot_to.append(f'{len(databases)} databases visible')

            cursor.close()

            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                method='postgres_connection',
                identity=identity,
                permissions=permissions,
                can_pivot_to=can_pivot_to,
                blast_radius=blast_radius,
                environment='production' if is_production else 'unknown',
                metadata={
                    'version': version,
                    'current_user': current_user,
                    'current_database': current_db,
                    'is_superuser': is_superuser,
                    'databases': databases[:10],
                    'table_count': table_count,
                },
            )

        except psycopg2.OperationalError as e:
            error_msg = str(e).strip()
            if 'authentication failed' in error_msg.lower():
                return VerificationResult(
                    status=VerificationStatus.INVALID,
                    method='postgres_connection',
                    error=f'Authentication failed: {error_msg}',
                )
            return VerificationResult(
                status=VerificationStatus.UNVERIFIED,
                method='postgres_connection',
                error=f'Connection error: {error_msg}',
            )
        except Exception as e:
            return VerificationResult(
                status=VerificationStatus.ERROR,
                method='postgres_connection',
                error=f'Unexpected error: {str(e)}',
            )
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def _detect_production(self, uri: str, db_name: str) -> bool:
        """
        Detect if the connection points to a production environment.

        Args:
            uri: PostgreSQL connection string
            db_name: Database name

        Returns:
            True if likely production
        """
        combined = f'{uri} {db_name}'.lower()

        non_prod_indicators = ['dev', 'test', 'staging', 'local', 'localhost', '127.0.0.1']
        prod_indicators = ['prod', 'production', 'live', 'main', 'primary']

        for indicator in non_prod_indicators:
            if indicator in combined:
                return False

        for indicator in prod_indicators:
            if indicator in combined:
                return True

        # Cloud-hosted databases are typically production
        cloud_indicators = ['rds.amazonaws.com', 'supabase.co', 'neon.tech', 'bit.io']
        for indicator in cloud_indicators:
            if indicator in combined:
                return True

        return False
