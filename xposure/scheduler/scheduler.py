"""Scan scheduler for X-POSURE."""

import asyncio
import json
import re
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any, Callable, Awaitable
import uuid


@dataclass
class CronExpression:
    """Simple cron expression parser."""

    minute: str = '*'
    hour: str = '*'
    day_of_month: str = '*'
    month: str = '*'
    day_of_week: str = '*'

    @classmethod
    def parse(cls, expression: str) -> 'CronExpression':
        """
        Parse cron expression string.

        Args:
            expression: Cron expression (e.g., "0 */6 * * *")

        Returns:
            CronExpression instance
        """
        parts = expression.strip().split()
        if len(parts) != 5:
            raise ValueError(f"Invalid cron expression: {expression}")

        return cls(
            minute=parts[0],
            hour=parts[1],
            day_of_month=parts[2],
            month=parts[3],
            day_of_week=parts[4],
        )

    def matches(self, dt: datetime) -> bool:
        """Check if datetime matches cron expression."""
        return (
            self._matches_field(self.minute, dt.minute, 0, 59) and
            self._matches_field(self.hour, dt.hour, 0, 23) and
            self._matches_field(self.day_of_month, dt.day, 1, 31) and
            self._matches_field(self.month, dt.month, 1, 12) and
            self._matches_field(self.day_of_week, dt.weekday(), 0, 6)
        )

    def _matches_field(self, field: str, value: int, min_val: int, max_val: int) -> bool:
        """Check if value matches cron field."""
        if field == '*':
            return True

        # Handle */n (every n)
        if field.startswith('*/'):
            step = int(field[2:])
            return value % step == 0

        # Handle ranges (e.g., 1-5)
        if '-' in field:
            start, end = map(int, field.split('-'))
            return start <= value <= end

        # Handle lists (e.g., 1,3,5)
        if ',' in field:
            values = [int(v) for v in field.split(',')]
            return value in values

        # Handle single value
        return value == int(field)

    def next_run(self, after: datetime) -> datetime:
        """Calculate next run time after given datetime."""
        # Start from next minute
        dt = after.replace(second=0, microsecond=0) + timedelta(minutes=1)

        # Search for next matching time (up to 1 year)
        max_iterations = 525600  # minutes in a year
        for _ in range(max_iterations):
            if self.matches(dt):
                return dt
            dt += timedelta(minutes=1)

        raise ValueError("Could not find next run time within a year")

    def __str__(self) -> str:
        return f"{self.minute} {self.hour} {self.day_of_month} {self.month} {self.day_of_week}"


@dataclass
class ScheduledScan:
    """Represents a scheduled scan."""

    id: str
    name: str
    target: str
    cron: CronExpression
    options: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def calculate_next_run(self) -> datetime:
        """Calculate next run time."""
        after = self.last_run or datetime.now(timezone.utc)
        self.next_run = self.cron.next_run(after)
        return self.next_run


class Scheduler:
    """Scan scheduler with persistence."""

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize scheduler.

        Args:
            db_path: Path to scheduler database
        """
        if db_path is None:
            db_path = str(Path.home() / '.xposure' / 'scheduler.db')

        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._scan_callback: Optional[Callable[[ScheduledScan], Awaitable[None]]] = None

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

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scheduled_scans (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    cron_expression TEXT NOT NULL,
                    options_json TEXT,
                    enabled INTEGER DEFAULT 1,
                    last_run TEXT,
                    next_run TEXT,
                    created_at TEXT NOT NULL
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    schedule_id TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT,
                    findings_count INTEGER DEFAULT 0,
                    error TEXT,
                    FOREIGN KEY (schedule_id) REFERENCES scheduled_scans(id)
                )
            ''')

            cursor.execute('CREATE INDEX IF NOT EXISTS idx_history_schedule ON scan_history(schedule_id)')

    def add_schedule(
        self,
        name: str,
        target: str,
        cron_expression: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> ScheduledScan:
        """
        Add a new scheduled scan.

        Args:
            name: Schedule name
            target: Scan target
            cron_expression: Cron expression for scheduling
            options: Scan options

        Returns:
            Created ScheduledScan
        """
        schedule = ScheduledScan(
            id=str(uuid.uuid4()),
            name=name,
            target=target,
            cron=CronExpression.parse(cron_expression),
            options=options or {},
        )
        schedule.calculate_next_run()

        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scheduled_scans
                (id, name, target, cron_expression, options_json, enabled, next_run, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                schedule.id,
                schedule.name,
                schedule.target,
                str(schedule.cron),
                json.dumps(schedule.options),
                1 if schedule.enabled else 0,
                schedule.next_run.isoformat() if schedule.next_run else None,
                schedule.created_at.isoformat(),
            ))

        return schedule

    def get_schedule(self, schedule_id: str) -> Optional[ScheduledScan]:
        """Get schedule by ID."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM scheduled_scans WHERE id = ?', (schedule_id,))
            row = cursor.fetchone()

            if not row:
                return None

            return self._row_to_schedule(row)

    def list_schedules(self, enabled_only: bool = False) -> List[ScheduledScan]:
        """List all schedules."""
        with self._connection() as conn:
            cursor = conn.cursor()
            if enabled_only:
                cursor.execute('SELECT * FROM scheduled_scans WHERE enabled = 1 ORDER BY next_run')
            else:
                cursor.execute('SELECT * FROM scheduled_scans ORDER BY next_run')

            return [self._row_to_schedule(row) for row in cursor.fetchall()]

    def update_schedule(
        self,
        schedule_id: str,
        name: Optional[str] = None,
        cron_expression: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
        enabled: Optional[bool] = None,
    ):
        """Update a schedule."""
        updates = []
        params = []

        if name is not None:
            updates.append('name = ?')
            params.append(name)

        if cron_expression is not None:
            updates.append('cron_expression = ?')
            params.append(cron_expression)
            # Recalculate next run
            cron = CronExpression.parse(cron_expression)
            next_run = cron.next_run(datetime.now(timezone.utc))
            updates.append('next_run = ?')
            params.append(next_run.isoformat())

        if options is not None:
            updates.append('options_json = ?')
            params.append(json.dumps(options))

        if enabled is not None:
            updates.append('enabled = ?')
            params.append(1 if enabled else 0)

        if updates:
            params.append(schedule_id)
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    f'UPDATE scheduled_scans SET {", ".join(updates)} WHERE id = ?',
                    params
                )

    def delete_schedule(self, schedule_id: str):
        """Delete a schedule."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM scheduled_scans WHERE id = ?', (schedule_id,))

    def record_run(
        self,
        schedule_id: str,
        status: str,
        findings_count: int = 0,
        error: Optional[str] = None,
    ):
        """Record a scan run."""
        now = datetime.now(timezone.utc)

        with self._connection() as conn:
            cursor = conn.cursor()

            # Record in history
            cursor.execute('''
                INSERT INTO scan_history (schedule_id, started_at, completed_at, status, findings_count, error)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                schedule_id,
                now.isoformat(),
                now.isoformat(),
                status,
                findings_count,
                error,
            ))

            # Update schedule
            schedule = self.get_schedule(schedule_id)
            if schedule:
                schedule.last_run = now
                schedule.calculate_next_run()
                cursor.execute('''
                    UPDATE scheduled_scans SET last_run = ?, next_run = ? WHERE id = ?
                ''', (
                    now.isoformat(),
                    schedule.next_run.isoformat() if schedule.next_run else None,
                    schedule_id,
                ))

    def get_run_history(self, schedule_id: str, limit: int = 10) -> List[dict]:
        """Get run history for a schedule."""
        with self._connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM scan_history
                WHERE schedule_id = ?
                ORDER BY started_at DESC
                LIMIT ?
            ''', (schedule_id, limit))

            return [dict(row) for row in cursor.fetchall()]

    def get_due_scans(self) -> List[ScheduledScan]:
        """Get all scans that are due to run."""
        now = datetime.now(timezone.utc)
        schedules = self.list_schedules(enabled_only=True)

        due = []
        for schedule in schedules:
            if schedule.next_run and schedule.next_run <= now:
                due.append(schedule)

        return due

    def _row_to_schedule(self, row: sqlite3.Row) -> ScheduledScan:
        """Convert database row to ScheduledScan."""
        return ScheduledScan(
            id=row['id'],
            name=row['name'],
            target=row['target'],
            cron=CronExpression.parse(row['cron_expression']),
            options=json.loads(row['options_json']) if row['options_json'] else {},
            enabled=bool(row['enabled']),
            last_run=datetime.fromisoformat(row['last_run']) if row['last_run'] else None,
            next_run=datetime.fromisoformat(row['next_run']) if row['next_run'] else None,
            created_at=datetime.fromisoformat(row['created_at']),
        )

    # ==================== Scheduler Loop ====================

    def set_scan_callback(self, callback: Callable[[ScheduledScan], Awaitable[None]]):
        """Set callback to run when a scan is due."""
        self._scan_callback = callback

    async def start(self):
        """Start the scheduler loop."""
        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        print("[scheduler] Started")

    async def stop(self):
        """Stop the scheduler loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        print("[scheduler] Stopped")

    async def _run_loop(self):
        """Main scheduler loop."""
        while self._running:
            try:
                # Check for due scans
                due_scans = self.get_due_scans()

                for schedule in due_scans:
                    if self._scan_callback:
                        try:
                            print(f"[scheduler] Running scheduled scan: {schedule.name}")
                            await self._scan_callback(schedule)
                            self.record_run(schedule.id, 'completed')
                        except Exception as e:
                            print(f"[scheduler] Error running {schedule.name}: {e}")
                            self.record_run(schedule.id, 'failed', error=str(e))
                    else:
                        # No callback, just update next_run
                        self.record_run(schedule.id, 'skipped', error='No scan callback configured')

                # Sleep for 1 minute
                await asyncio.sleep(60)

            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[scheduler] Loop error: {e}")
                await asyncio.sleep(60)


# Common cron expressions
CRON_HOURLY = "0 * * * *"
CRON_DAILY = "0 0 * * *"
CRON_WEEKLY = "0 0 * * 0"
CRON_MONTHLY = "0 0 1 * *"
CRON_EVERY_6_HOURS = "0 */6 * * *"
CRON_EVERY_12_HOURS = "0 */12 * * *"
