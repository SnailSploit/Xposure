"""REST API server for X-POSURE."""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Optional, Callable, Any
from functools import wraps

from aiohttp import web

from ..storage import get_database
from ..config import Config


class APIServer:
    """REST API server for X-POSURE."""

    def __init__(
        self,
        host: str = '0.0.0.0',
        port: int = 8080,
        api_key: Optional[str] = None,
        db_path: Optional[str] = None,
    ):
        """
        Initialize API server.

        Args:
            host: Host to bind to
            port: Port to listen on
            api_key: Optional API key for authentication
            db_path: Optional database path
        """
        self.host = host
        self.port = port
        self.api_key = api_key
        self.db = get_database(db_path)
        self.app = web.Application(middlewares=[self._error_middleware])
        self._setup_routes()

        # Track running scans
        self._running_scans: dict[str, asyncio.Task] = {}

    def _setup_routes(self):
        """Setup API routes."""
        self.app.router.add_get('/health', self.health_check)
        self.app.router.add_get('/api/v1/stats', self.get_stats)

        # Scans
        self.app.router.add_post('/api/v1/scans', self.create_scan)
        self.app.router.add_get('/api/v1/scans', self.list_scans)
        self.app.router.add_get('/api/v1/scans/{scan_id}', self.get_scan)
        self.app.router.add_delete('/api/v1/scans/{scan_id}', self.cancel_scan)

        # Findings
        self.app.router.add_get('/api/v1/findings', self.list_findings)
        self.app.router.add_get('/api/v1/findings/{finding_id}', self.get_finding)
        self.app.router.add_post('/api/v1/findings/{finding_id}/suppress', self.suppress_finding)
        self.app.router.add_delete('/api/v1/findings/{finding_id}/suppress', self.unsuppress_finding)

        # Suppression rules
        self.app.router.add_get('/api/v1/suppressions', self.list_suppression_rules)
        self.app.router.add_post('/api/v1/suppressions', self.create_suppression_rule)
        self.app.router.add_delete('/api/v1/suppressions/{rule_id}', self.delete_suppression_rule)

        # Webhooks
        self.app.router.add_get('/api/v1/webhooks', self.list_webhooks)
        self.app.router.add_post('/api/v1/webhooks', self.create_webhook)
        self.app.router.add_delete('/api/v1/webhooks/{webhook_id}', self.delete_webhook)

        # Audit log
        self.app.router.add_get('/api/v1/audit', self.get_audit_log)

    @web.middleware
    async def _error_middleware(self, request: web.Request, handler: Callable) -> web.Response:
        """Error handling middleware."""
        try:
            # Check API key if configured
            if self.api_key:
                auth_header = request.headers.get('Authorization', '')
                if not auth_header.startswith('Bearer '):
                    return web.json_response(
                        {'error': 'Missing or invalid Authorization header'},
                        status=401
                    )
                token = auth_header[7:]
                if token != self.api_key:
                    return web.json_response(
                        {'error': 'Invalid API key'},
                        status=403
                    )

            response = await handler(request)
            return response

        except web.HTTPException:
            raise
        except json.JSONDecodeError:
            return web.json_response(
                {'error': 'Invalid JSON in request body'},
                status=400
            )
        except Exception as e:
            return web.json_response(
                {'error': str(e)},
                status=500
            )

    # ==================== Health ====================

    async def health_check(self, request: web.Request) -> web.Response:
        """Health check endpoint."""
        return web.json_response({
            'status': 'healthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'version': '4.0.0',
        })

    async def get_stats(self, request: web.Request) -> web.Response:
        """Get overall statistics."""
        stats = self.db.get_stats()
        stats['running_scans'] = len(self._running_scans)
        return web.json_response(stats)

    # ==================== Scans ====================

    async def create_scan(self, request: web.Request) -> web.Response:
        """
        Create and start a new scan.

        Request body:
            {
                "target": "https://example.com",
                "options": {
                    "verify": true,
                    "discover_subdomains": true,
                    ...
                }
            }
        """
        data = await request.json()

        target = data.get('target')
        if not target:
            return web.json_response(
                {'error': 'Missing required field: target'},
                status=400
            )

        options = data.get('options', {})

        # Generate scan ID
        scan_id = str(uuid.uuid4())

        # Create scan record
        self.db.create_scan(scan_id, target, options)

        # Start scan in background (placeholder - would integrate with actual scanner)
        # self._running_scans[scan_id] = asyncio.create_task(self._run_scan(scan_id, target, options))

        return web.json_response({
            'id': scan_id,
            'target': target,
            'status': 'queued',
            'created_at': datetime.now(timezone.utc).isoformat(),
        }, status=201)

    async def list_scans(self, request: web.Request) -> web.Response:
        """List all scans."""
        target = request.query.get('target')
        limit = int(request.query.get('limit', 100))
        offset = int(request.query.get('offset', 0))

        scans = self.db.list_scans(target=target, limit=limit, offset=offset)

        # Add running status
        for scan in scans:
            if scan['id'] in self._running_scans:
                scan['status'] = 'running'

        return web.json_response({
            'scans': scans,
            'limit': limit,
            'offset': offset,
        })

    async def get_scan(self, request: web.Request) -> web.Response:
        """Get scan by ID."""
        scan_id = request.match_info['scan_id']
        scan = self.db.get_scan(scan_id)

        if not scan:
            return web.json_response(
                {'error': 'Scan not found'},
                status=404
            )

        # Check if running
        if scan_id in self._running_scans:
            scan['status'] = 'running'

        return web.json_response(scan)

    async def cancel_scan(self, request: web.Request) -> web.Response:
        """Cancel a running scan."""
        scan_id = request.match_info['scan_id']

        if scan_id in self._running_scans:
            self._running_scans[scan_id].cancel()
            del self._running_scans[scan_id]
            self.db.complete_scan(scan_id, status='cancelled')
            return web.json_response({'status': 'cancelled'})

        return web.json_response(
            {'error': 'Scan not found or not running'},
            status=404
        )

    # ==================== Findings ====================

    async def list_findings(self, request: web.Request) -> web.Response:
        """List findings with filtering."""
        scan_id = request.query.get('scan_id')
        credential_type = request.query.get('type')
        severity = request.query.get('severity')
        verified_only = request.query.get('verified', '').lower() == 'true'
        include_suppressed = request.query.get('include_suppressed', '').lower() == 'true'
        limit = int(request.query.get('limit', 100))
        offset = int(request.query.get('offset', 0))

        findings = self.db.list_findings(
            scan_id=scan_id,
            credential_type=credential_type,
            severity=severity,
            verified_only=verified_only,
            include_suppressed=include_suppressed,
            limit=limit,
            offset=offset,
        )

        return web.json_response({
            'findings': findings,
            'limit': limit,
            'offset': offset,
        })

    async def get_finding(self, request: web.Request) -> web.Response:
        """Get finding by ID."""
        finding_id = request.match_info['finding_id']
        finding = self.db.get_finding(finding_id)

        if not finding:
            return web.json_response(
                {'error': 'Finding not found'},
                status=404
            )

        return web.json_response(finding)

    async def suppress_finding(self, request: web.Request) -> web.Response:
        """Suppress a finding (mark as false positive)."""
        finding_id = request.match_info['finding_id']
        data = await request.json()

        reason = data.get('reason', 'No reason provided')
        suppressed_by = data.get('user')

        # Verify finding exists
        finding = self.db.get_finding(finding_id)
        if not finding:
            return web.json_response(
                {'error': 'Finding not found'},
                status=404
            )

        self.db.suppress_finding(finding_id, reason, suppressed_by)

        return web.json_response({
            'id': finding_id,
            'is_suppressed': True,
            'reason': reason,
        })

    async def unsuppress_finding(self, request: web.Request) -> web.Response:
        """Remove suppression from a finding."""
        finding_id = request.match_info['finding_id']

        finding = self.db.get_finding(finding_id)
        if not finding:
            return web.json_response(
                {'error': 'Finding not found'},
                status=404
            )

        self.db.unsuppress_finding(finding_id)

        return web.json_response({
            'id': finding_id,
            'is_suppressed': False,
        })

    # ==================== Suppression Rules ====================

    async def list_suppression_rules(self, request: web.Request) -> web.Response:
        """List suppression rules."""
        active_only = request.query.get('active_only', 'true').lower() == 'true'
        rules = self.db.get_suppression_rules(active_only=active_only)
        return web.json_response({'rules': rules})

    async def create_suppression_rule(self, request: web.Request) -> web.Response:
        """
        Create a suppression rule.

        Request body:
            {
                "rule_type": "credential_type|value_pattern|path_pattern",
                "pattern": "...",
                "reason": "...",
                "expires_at": "2024-12-31T23:59:59Z"  // optional
            }
        """
        data = await request.json()

        rule_type = data.get('rule_type')
        pattern = data.get('pattern')
        reason = data.get('reason', '')

        if not rule_type or not pattern:
            return web.json_response(
                {'error': 'Missing required fields: rule_type, pattern'},
                status=400
            )

        if rule_type not in ('credential_type', 'value_pattern', 'path_pattern'):
            return web.json_response(
                {'error': 'Invalid rule_type. Must be: credential_type, value_pattern, or path_pattern'},
                status=400
            )

        rule_id = self.db.add_suppression_rule(
            rule_type=rule_type,
            pattern=pattern,
            reason=reason,
            created_by=data.get('user'),
            expires_at=data.get('expires_at'),
        )

        return web.json_response({
            'id': rule_id,
            'rule_type': rule_type,
            'pattern': pattern,
        }, status=201)

    async def delete_suppression_rule(self, request: web.Request) -> web.Response:
        """Delete (deactivate) a suppression rule."""
        rule_id = request.match_info['rule_id']

        # Deactivate instead of delete for audit trail
        with self.db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE suppression_rules SET is_active = 0 WHERE id = ?', (rule_id,))

        return web.json_response({'status': 'deleted'})

    # ==================== Webhooks ====================

    async def list_webhooks(self, request: web.Request) -> web.Response:
        """List webhooks."""
        webhooks = self.db.get_webhooks()
        # Mask secrets
        for wh in webhooks:
            if wh.get('secret'):
                wh['secret'] = '***'
        return web.json_response({'webhooks': webhooks})

    async def create_webhook(self, request: web.Request) -> web.Response:
        """
        Create a webhook.

        Request body:
            {
                "name": "Slack Alerts",
                "url": "https://hooks.slack.com/...",
                "events": ["finding.critical", "finding.verified"],
                "secret": "optional-hmac-secret"
            }
        """
        data = await request.json()

        name = data.get('name')
        url = data.get('url')
        events = data.get('events', [])

        if not name or not url:
            return web.json_response(
                {'error': 'Missing required fields: name, url'},
                status=400
            )

        valid_events = [
            'finding.new', 'finding.critical', 'finding.verified',
            'scan.started', 'scan.completed', 'scan.failed'
        ]
        for event in events:
            if event not in valid_events:
                return web.json_response(
                    {'error': f'Invalid event: {event}. Valid events: {valid_events}'},
                    status=400
                )

        webhook_id = self.db.add_webhook(
            name=name,
            url=url,
            events=events if events else valid_events,
            secret=data.get('secret'),
        )

        return web.json_response({
            'id': webhook_id,
            'name': name,
            'url': url,
            'events': events,
        }, status=201)

    async def delete_webhook(self, request: web.Request) -> web.Response:
        """Delete a webhook."""
        webhook_id = request.match_info['webhook_id']

        with self.db._connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE webhooks SET is_active = 0 WHERE id = ?', (webhook_id,))

        return web.json_response({'status': 'deleted'})

    # ==================== Audit ====================

    async def get_audit_log(self, request: web.Request) -> web.Response:
        """Get audit log entries."""
        entity_type = request.query.get('entity_type')
        entity_id = request.query.get('entity_id')
        action = request.query.get('action')
        limit = int(request.query.get('limit', 100))

        entries = self.db.get_audit_log(
            entity_type=entity_type,
            entity_id=entity_id,
            action=action,
            limit=limit,
        )

        return web.json_response({'entries': entries})

    # ==================== Server Control ====================

    def run(self):
        """Run the API server."""
        web.run_app(self.app, host=self.host, port=self.port)

    async def start(self) -> web.AppRunner:
        """Start the API server (async)."""
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        await site.start()
        return runner


def run_server(
    host: str = '0.0.0.0',
    port: int = 8080,
    api_key: Optional[str] = None,
    db_path: Optional[str] = None,
):
    """Convenience function to run API server."""
    server = APIServer(host=host, port=port, api_key=api_key, db_path=db_path)
    server.run()
