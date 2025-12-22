"""SQLite database layer for X-POSURE persistence."""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any
from dataclasses import asdict

from ..core.models import Finding, Source, Severity, VerificationStatus


class Database:
    """SQLite database for persistent storage."""

    SCHEMA_VERSION = 1

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize database connection.

        Args:
            db_path: Path to SQLite database file. Uses default if not specified.
        """
        if db_path is None:
            db_path = str(Path.home() / '.xposure' / 'xposure.db')

        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        self._init_schema()

    @contextmanager
    def _connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self):
        """Initialize database schema."""
        with self._connection() as conn:
            cursor = conn.cursor()

            # Schema version tracking
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY
                )
            ''')

            # Scans table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT DEFAULT 'running',
                    config_json TEXT,
                    stats_json TEXT,
                    findings_count INTEGER DEFAULT 0,
                    verified_count INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Findings table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT,
                    credential_type TEXT NOT NULL,
                    value_hash TEXT NOT NULL,
                    value_preview TEXT,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    sources_json TEXT,
                    verification_status TEXT,
                    verification_json TEXT,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    is_suppressed INTEGER DEFAULT 0,
                    suppression_reason TEXT,
                    suppressed_by TEXT,
                    suppressed_at TEXT,
                    notes TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            ''')

            # Suppression rules table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS suppression_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_type TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    reason TEXT,
                    created_by TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    expires_at TEXT,
                    is_active INTEGER DEFAULT 1
                )
            ''')

            # Assets table (for tracking discovered assets)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_type TEXT NOT NULL,
                    value TEXT NOT NULL UNIQUE,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    metadata_json TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Audit log table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    entity_type TEXT,
                    entity_id TEXT,
                    user_id TEXT,
                    details_json TEXT,
                    ip_address TEXT
                )
            ''')

            # Webhooks table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS webhooks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    events TEXT NOT NULL,
                    secret TEXT,
                    is_active INTEGER DEFAULT 1,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_triggered_at TEXT,
                    failure_count INTEGER DEFAULT 0
                )
            ''')

            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(credential_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_findings_hash ON findings(value_hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)')

            # Set schema version
            cursor.execute('INSERT OR REPLACE INTO schema_version (version) VALUES (?)',
                          (self.SCHEMA_VERSION,))

    # ==================== Scan Operations ====================

    def create_scan(
        self,
        scan_id: str,
        target: str,
        config: Optional[dict] = None,
    ) -> str:
        """
        Create a new scan record.

        Args:
            scan_id: Unique scan identifier
            target: Scan target (URL or path)
            config: Scan configuration

        Returns:
            Scan ID
        """
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scans (id, target, started_at, config_json)
                VALUES (?, ?, ?, ?)
            ''', (
                scan_id,
                target,
                datetime.now(timezone.utc).isoformat(),
                json.dumps(config) if config else None,
            ))

            self._audit_log(conn, 'scan.created', 'scan', scan_id, {
                'target': target,
            })

        return scan_id

    def complete_scan(
        self,
        scan_id: str,
        status: str = 'completed',
        stats: Optional[dict] = None,
        findings_count: int = 0,
        verified_count: int = 0,
    ):
        """
        Mark a scan as completed.

        Args:
            scan_id: Scan identifier
            status: Final status (completed, failed, cancelled)
            stats: Scan statistics
            findings_count: Number of findings
            verified_count: Number of verified findings
        """
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE scans
                SET completed_at = ?, status = ?, stats_json = ?,
                    findings_count = ?, verified_count = ?
                WHERE id = ?
            ''', (
                datetime.now(timezone.utc).isoformat(),
                status,
                json.dumps(stats) if stats else None,
                findings_count,
                verified_count,
                scan_id,
            ))

            self._audit_log(conn, 'scan.completed', 'scan', scan_id, {
                'status': status,
                'findings_count': findings_count,
            })

    def get_scan(self, scan_id: str) -> Optional[dict]:
        """Get scan by ID."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def list_scans(
        self,
        target: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[dict]:
        """List scans with optional filtering."""
        with self._connection() as conn:
            cursor = conn.cursor()
            if target:
                cursor.execute('''
                    SELECT * FROM scans WHERE target = ?
                    ORDER BY started_at DESC LIMIT ? OFFSET ?
                ''', (target, limit, offset))
            else:
                cursor.execute('''
                    SELECT * FROM scans
                    ORDER BY started_at DESC LIMIT ? OFFSET ?
                ''', (limit, offset))
            return [dict(row) for row in cursor.fetchall()]

    # ==================== Finding Operations ====================

    def save_finding(
        self,
        finding: Finding,
        scan_id: Optional[str] = None,
        verification: Optional[dict] = None,
    ) -> str:
        """
        Save or update a finding.

        Args:
            finding: Finding to save
            scan_id: Associated scan ID
            verification: Verification result

        Returns:
            Finding ID
        """
        import hashlib
        value_hash = hashlib.sha256(finding.value.encode()).hexdigest()
        value_preview = finding.value[:8] + '...' if len(finding.value) > 12 else finding.value

        # Serialize sources
        sources_json = json.dumps([
            {
                'type': s.type,
                'url': s.url,
                'path': s.path,
                'line': s.line,
            } for s in finding.sources
        ])

        now = datetime.now(timezone.utc).isoformat()

        with self._connection() as conn:
            cursor = conn.cursor()

            # Check if finding already exists (by value hash)
            cursor.execute('''
                SELECT id, first_seen_at FROM findings WHERE value_hash = ?
            ''', (value_hash,))
            existing = cursor.fetchone()

            if existing:
                # Update existing finding
                cursor.execute('''
                    UPDATE findings
                    SET last_seen_at = ?, scan_id = ?, sources_json = ?,
                        verification_status = ?, verification_json = ?,
                        confidence = ?
                    WHERE id = ?
                ''', (
                    now,
                    scan_id,
                    sources_json,
                    verification.get('status') if verification else None,
                    json.dumps(verification) if verification else None,
                    finding.confidence,
                    existing['id'],
                ))
                return existing['id']
            else:
                # Insert new finding
                cursor.execute('''
                    INSERT INTO findings (
                        id, scan_id, credential_type, value_hash, value_preview,
                        severity, confidence, sources_json, verification_status,
                        verification_json, first_seen_at, last_seen_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    finding.id,
                    scan_id,
                    finding.credential_type,
                    value_hash,
                    value_preview,
                    finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                    finding.confidence,
                    sources_json,
                    verification.get('status') if verification else None,
                    json.dumps(verification) if verification else None,
                    now,
                    now,
                ))

                self._audit_log(conn, 'finding.created', 'finding', finding.id, {
                    'type': finding.credential_type,
                    'severity': str(finding.severity),
                })

                return finding.id

    def get_finding(self, finding_id: str) -> Optional[dict]:
        """Get finding by ID."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM findings WHERE id = ?', (finding_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def list_findings(
        self,
        scan_id: Optional[str] = None,
        credential_type: Optional[str] = None,
        severity: Optional[str] = None,
        verified_only: bool = False,
        include_suppressed: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> List[dict]:
        """List findings with filtering."""
        conditions = []
        params = []

        if scan_id:
            conditions.append('scan_id = ?')
            params.append(scan_id)
        if credential_type:
            conditions.append('credential_type = ?')
            params.append(credential_type)
        if severity:
            conditions.append('severity = ?')
            params.append(severity)
        if verified_only:
            conditions.append("verification_status = 'verified'")
        if not include_suppressed:
            conditions.append('is_suppressed = 0')

        where_clause = ' AND '.join(conditions) if conditions else '1=1'

        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f'''
                SELECT * FROM findings
                WHERE {where_clause}
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        ELSE 5
                    END,
                    last_seen_at DESC
                LIMIT ? OFFSET ?
            ''', params + [limit, offset])
            return [dict(row) for row in cursor.fetchall()]

    def get_finding_by_hash(self, value_hash: str) -> Optional[dict]:
        """Get finding by value hash."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM findings WHERE value_hash = ?', (value_hash,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def is_duplicate(self, value: str) -> bool:
        """Check if a credential value has been seen before."""
        import hashlib
        value_hash = hashlib.sha256(value.encode()).hexdigest()
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT 1 FROM findings WHERE value_hash = ?', (value_hash,))
            return cursor.fetchone() is not None

    # ==================== Suppression Operations ====================

    def suppress_finding(
        self,
        finding_id: str,
        reason: str,
        suppressed_by: Optional[str] = None,
    ):
        """
        Suppress a finding (mark as false positive).

        Args:
            finding_id: Finding to suppress
            reason: Reason for suppression
            suppressed_by: User who suppressed
        """
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE findings
                SET is_suppressed = 1, suppression_reason = ?,
                    suppressed_by = ?, suppressed_at = ?
                WHERE id = ?
            ''', (
                reason,
                suppressed_by,
                datetime.now(timezone.utc).isoformat(),
                finding_id,
            ))

            self._audit_log(conn, 'finding.suppressed', 'finding', finding_id, {
                'reason': reason,
                'by': suppressed_by,
            })

    def unsuppress_finding(self, finding_id: str):
        """Remove suppression from a finding."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE findings
                SET is_suppressed = 0, suppression_reason = NULL,
                    suppressed_by = NULL, suppressed_at = NULL
                WHERE id = ?
            ''', (finding_id,))

            self._audit_log(conn, 'finding.unsuppressed', 'finding', finding_id, {})

    def add_suppression_rule(
        self,
        rule_type: str,
        pattern: str,
        reason: str,
        created_by: Optional[str] = None,
        expires_at: Optional[str] = None,
    ) -> int:
        """
        Add a suppression rule.

        Args:
            rule_type: Type of rule (value_pattern, path_pattern, credential_type)
            pattern: Pattern to match
            reason: Reason for rule
            created_by: User who created the rule
            expires_at: Optional expiration date

        Returns:
            Rule ID
        """
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO suppression_rules (rule_type, pattern, reason, created_by, expires_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (rule_type, pattern, reason, created_by, expires_at))

            rule_id = cursor.lastrowid

            self._audit_log(conn, 'suppression_rule.created', 'suppression_rule', str(rule_id), {
                'type': rule_type,
                'pattern': pattern,
            })

            return rule_id

    def get_suppression_rules(self, active_only: bool = True) -> List[dict]:
        """Get all suppression rules."""
        with self._connection() as conn:
            cursor = conn.cursor()
            if active_only:
                cursor.execute('''
                    SELECT * FROM suppression_rules
                    WHERE is_active = 1
                    AND (expires_at IS NULL OR expires_at > datetime('now'))
                ''')
            else:
                cursor.execute('SELECT * FROM suppression_rules')
            return [dict(row) for row in cursor.fetchall()]

    def should_suppress(self, finding: Finding) -> tuple[bool, Optional[str]]:
        """
        Check if a finding should be suppressed based on rules.

        Args:
            finding: Finding to check

        Returns:
            Tuple of (should_suppress, reason)
        """
        import re
        rules = self.get_suppression_rules()

        for rule in rules:
            rule_type = rule['rule_type']
            pattern = rule['pattern']

            try:
                if rule_type == 'credential_type':
                    if finding.credential_type == pattern:
                        return True, rule['reason']
                elif rule_type == 'value_pattern':
                    if re.search(pattern, finding.value):
                        return True, rule['reason']
                elif rule_type == 'path_pattern':
                    for source in finding.sources:
                        if source.path and re.search(pattern, source.path):
                            return True, rule['reason']
            except re.error:
                # Invalid regex, skip rule
                continue

        return False, None

    # ==================== Webhook Operations ====================

    def add_webhook(
        self,
        name: str,
        url: str,
        events: List[str],
        secret: Optional[str] = None,
    ) -> int:
        """Add a webhook configuration."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO webhooks (name, url, events, secret)
                VALUES (?, ?, ?, ?)
            ''', (name, url, ','.join(events), secret))

            webhook_id = cursor.lastrowid

            self._audit_log(conn, 'webhook.created', 'webhook', str(webhook_id), {
                'name': name,
                'url': url[:50],
                'events': events,
            })

            return webhook_id

    def get_webhooks(self, event: Optional[str] = None) -> List[dict]:
        """Get webhooks, optionally filtered by event."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM webhooks WHERE is_active = 1')
            webhooks = [dict(row) for row in cursor.fetchall()]

            if event:
                webhooks = [w for w in webhooks if event in w['events'].split(',')]

            return webhooks

    def update_webhook_status(self, webhook_id: int, success: bool):
        """Update webhook status after trigger."""
        with self._connection() as conn:
            cursor = conn.cursor()
            if success:
                cursor.execute('''
                    UPDATE webhooks
                    SET last_triggered_at = ?, failure_count = 0
                    WHERE id = ?
                ''', (datetime.now(timezone.utc).isoformat(), webhook_id))
            else:
                cursor.execute('''
                    UPDATE webhooks
                    SET failure_count = failure_count + 1
                    WHERE id = ?
                ''', (webhook_id,))

    # ==================== Statistics ====================

    def get_stats(self) -> dict:
        """Get overall statistics."""
        with self._connection() as conn:
            cursor = conn.cursor()

            # Total findings
            cursor.execute('SELECT COUNT(*) FROM findings WHERE is_suppressed = 0')
            total_findings = cursor.fetchone()[0]

            # By severity
            cursor.execute('''
                SELECT severity, COUNT(*) as count
                FROM findings WHERE is_suppressed = 0
                GROUP BY severity
            ''')
            by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}

            # By type
            cursor.execute('''
                SELECT credential_type, COUNT(*) as count
                FROM findings WHERE is_suppressed = 0
                GROUP BY credential_type
                ORDER BY count DESC
                LIMIT 10
            ''')
            by_type = {row['credential_type']: row['count'] for row in cursor.fetchall()}

            # Verified count
            cursor.execute('''
                SELECT COUNT(*) FROM findings
                WHERE is_suppressed = 0 AND verification_status = 'verified'
            ''')
            verified_count = cursor.fetchone()[0]

            # Recent scans
            cursor.execute('''
                SELECT COUNT(*) FROM scans
                WHERE started_at > datetime('now', '-7 days')
            ''')
            recent_scans = cursor.fetchone()[0]

            # Suppressed count
            cursor.execute('SELECT COUNT(*) FROM findings WHERE is_suppressed = 1')
            suppressed_count = cursor.fetchone()[0]

            return {
                'total_findings': total_findings,
                'by_severity': by_severity,
                'by_type': by_type,
                'verified_count': verified_count,
                'suppressed_count': suppressed_count,
                'recent_scans_7d': recent_scans,
            }

    # ==================== Audit Logging ====================

    def _audit_log(
        self,
        conn: sqlite3.Connection,
        action: str,
        entity_type: str,
        entity_id: str,
        details: dict,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ):
        """Internal method to add audit log entry."""
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO audit_log (timestamp, action, entity_type, entity_id, user_id, details_json, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now(timezone.utc).isoformat(),
            action,
            entity_type,
            entity_id,
            user_id,
            json.dumps(details),
            ip_address,
        ))

    def get_audit_log(
        self,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 100,
    ) -> List[dict]:
        """Get audit log entries."""
        conditions = []
        params = []

        if entity_type:
            conditions.append('entity_type = ?')
            params.append(entity_type)
        if entity_id:
            conditions.append('entity_id = ?')
            params.append(entity_id)
        if action:
            conditions.append('action LIKE ?')
            params.append(f'{action}%')

        where_clause = ' AND '.join(conditions) if conditions else '1=1'

        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f'''
                SELECT * FROM audit_log
                WHERE {where_clause}
                ORDER BY timestamp DESC
                LIMIT ?
            ''', params + [limit])
            return [dict(row) for row in cursor.fetchall()]


# Global database instance
_db: Optional[Database] = None


def get_database(db_path: Optional[str] = None) -> Database:
    """Get or create database instance."""
    global _db
    if _db is None:
        _db = Database(db_path)
    return _db
