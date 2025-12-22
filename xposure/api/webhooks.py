"""Webhook notification system for X-POSURE."""

import asyncio
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

import aiohttp

from ..storage import get_database
from ..core.models import Finding, Severity


class WebhookNotifier:
    """Send notifications via webhooks."""

    def __init__(self, db_path: Optional[str] = None, timeout: int = 10):
        """
        Initialize webhook notifier.

        Args:
            db_path: Optional database path
            timeout: Request timeout in seconds
        """
        self.db = get_database(db_path)
        self.timeout = timeout
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        """Context manager entry."""
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self._session:
            await self._session.close()

    async def notify_finding(
        self,
        finding: Finding,
        verification: Optional[dict] = None,
        scan_id: Optional[str] = None,
    ):
        """
        Send webhook notifications for a new finding.

        Args:
            finding: The finding to notify about
            verification: Optional verification result
            scan_id: Optional scan ID
        """
        # Determine events to trigger
        events = ['finding.new']

        if finding.severity == Severity.CRITICAL:
            events.append('finding.critical')
        elif finding.severity == Severity.HIGH:
            events.append('finding.high')

        if verification and verification.get('status') == 'verified':
            events.append('finding.verified')

        # Build payload
        payload = self._build_finding_payload(finding, verification, scan_id)

        # Send to matching webhooks
        await self._send_to_webhooks(events, payload)

    async def notify_scan_event(
        self,
        event: str,
        scan_id: str,
        target: str,
        details: Optional[dict] = None,
    ):
        """
        Send webhook notifications for scan events.

        Args:
            event: Event type (scan.started, scan.completed, scan.failed)
            scan_id: Scan identifier
            target: Scan target
            details: Additional details
        """
        payload = {
            'event': event,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'scan': {
                'id': scan_id,
                'target': target,
            }
        }

        if details:
            payload['scan'].update(details)

        await self._send_to_webhooks([event], payload)

    async def _send_to_webhooks(self, events: List[str], payload: dict):
        """Send payload to all matching webhooks."""
        if not self._session:
            raise RuntimeError("Session not initialized. Use async context manager.")

        for event in events:
            webhooks = self.db.get_webhooks(event=event)

            for webhook in webhooks:
                await self._send_webhook(webhook, event, payload)

    async def _send_webhook(self, webhook: dict, event: str, payload: dict):
        """Send payload to a single webhook."""
        url = webhook['url']
        secret = webhook.get('secret')
        webhook_id = webhook['id']

        # Add event to payload
        payload_with_event = {**payload, 'event': event}
        body = json.dumps(payload_with_event)

        headers = {
            'Content-Type': 'application/json',
            'X-XPOSURE-Event': event,
            'X-XPOSURE-Delivery': str(webhook_id),
        }

        # Add HMAC signature if secret is configured
        if secret:
            signature = hmac.new(
                secret.encode(),
                body.encode(),
                hashlib.sha256
            ).hexdigest()
            headers['X-XPOSURE-Signature'] = f'sha256={signature}'

        try:
            async with self._session.post(url, data=body, headers=headers) as response:
                success = 200 <= response.status < 300
                self.db.update_webhook_status(webhook_id, success)

                if not success:
                    # Log failure but don't raise
                    print(f"[webhook] Failed to deliver to {url}: {response.status}")

        except Exception as e:
            self.db.update_webhook_status(webhook_id, False)
            print(f"[webhook] Error delivering to {url}: {e}")

    def _build_finding_payload(
        self,
        finding: Finding,
        verification: Optional[dict],
        scan_id: Optional[str],
    ) -> dict:
        """Build webhook payload for a finding."""
        # Mask the actual secret value
        value = finding.value
        if len(value) > 12:
            masked_value = value[:4] + '*' * (len(value) - 8) + value[-4:]
        else:
            masked_value = '*' * len(value)

        payload = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'finding': {
                'id': finding.id,
                'credential_type': finding.credential_type,
                'value_preview': masked_value,
                'severity': finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                'confidence': finding.confidence,
                'sources': [
                    {
                        'type': s.type,
                        'url': s.url,
                        'path': s.path,
                        'line': s.line,
                    }
                    for s in finding.sources[:5]  # Limit sources
                ],
            }
        }

        if scan_id:
            payload['scan_id'] = scan_id

        if verification:
            payload['verification'] = {
                'status': verification.get('status'),
                'method': verification.get('method'),
                'identity': verification.get('identity'),
            }
            if verification.get('permissions'):
                payload['verification']['permissions'] = verification['permissions'][:5]

        return payload


class SlackNotifier:
    """Specialized notifier for Slack webhooks."""

    def __init__(self, webhook_url: str, timeout: int = 10):
        """
        Initialize Slack notifier.

        Args:
            webhook_url: Slack webhook URL
            timeout: Request timeout
        """
        self.webhook_url = webhook_url
        self.timeout = timeout

    async def notify_finding(
        self,
        finding: Finding,
        verification: Optional[dict] = None,
    ):
        """Send Slack notification for a finding."""
        # Determine color based on severity
        color_map = {
            Severity.CRITICAL: '#FF0000',  # Red
            Severity.HIGH: '#FF6600',      # Orange
            Severity.MEDIUM: '#FFCC00',    # Yellow
            Severity.LOW: '#00CC00',       # Green
            Severity.INFO: '#0066FF',      # Blue
        }
        color = color_map.get(finding.severity, '#808080')

        # Mask value
        value = finding.value
        if len(value) > 12:
            masked_value = value[:4] + '*' * 8 + value[-4:]
        else:
            masked_value = '*' * len(value)

        # Build Slack message
        blocks = [
            {
                'type': 'header',
                'text': {
                    'type': 'plain_text',
                    'text': f'🔑 New {finding.severity.value.upper()} Finding',
                    'emoji': True,
                }
            },
            {
                'type': 'section',
                'fields': [
                    {
                        'type': 'mrkdwn',
                        'text': f'*Type:*\n{finding.credential_type}',
                    },
                    {
                        'type': 'mrkdwn',
                        'text': f'*Severity:*\n{finding.severity.value}',
                    },
                    {
                        'type': 'mrkdwn',
                        'text': f'*Value:*\n`{masked_value}`',
                    },
                    {
                        'type': 'mrkdwn',
                        'text': f'*Confidence:*\n{finding.confidence:.0%}',
                    },
                ]
            }
        ]

        # Add verification info if available
        if verification:
            status = verification.get('status', 'unknown')
            status_emoji = {
                'verified': '✅',
                'invalid': '❌',
                'likely_valid': '⚠️',
            }.get(status, '❓')

            verification_text = f'{status_emoji} *Verification:* {status}'
            if verification.get('identity'):
                verification_text += f'\n*Identity:* {verification["identity"]}'

            blocks.append({
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': verification_text,
                }
            })

        # Add source info
        if finding.sources:
            source = finding.sources[0]
            source_text = f'*Source:* {source.url or source.path}'
            if source.line:
                source_text += f' (line {source.line})'

            blocks.append({
                'type': 'context',
                'elements': [
                    {
                        'type': 'mrkdwn',
                        'text': source_text,
                    }
                ]
            })

        payload = {
            'blocks': blocks,
            'attachments': [
                {
                    'color': color,
                    'fallback': f'New {finding.credential_type} finding ({finding.severity.value})',
                }
            ]
        }

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            try:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                ) as response:
                    return 200 <= response.status < 300
            except Exception as e:
                print(f"[slack] Error sending notification: {e}")
                return False

    async def notify_scan_complete(
        self,
        target: str,
        findings_count: int,
        critical_count: int,
        verified_count: int,
        duration_seconds: int,
    ):
        """Send Slack notification for scan completion."""
        emoji = '🎉' if findings_count == 0 else '⚠️' if critical_count == 0 else '🚨'

        blocks = [
            {
                'type': 'header',
                'text': {
                    'type': 'plain_text',
                    'text': f'{emoji} Scan Complete',
                    'emoji': True,
                }
            },
            {
                'type': 'section',
                'fields': [
                    {'type': 'mrkdwn', 'text': f'*Target:*\n{target}'},
                    {'type': 'mrkdwn', 'text': f'*Duration:*\n{duration_seconds}s'},
                    {'type': 'mrkdwn', 'text': f'*Findings:*\n{findings_count}'},
                    {'type': 'mrkdwn', 'text': f'*Critical:*\n{critical_count}'},
                    {'type': 'mrkdwn', 'text': f'*Verified:*\n{verified_count}'},
                ]
            }
        ]

        payload = {'blocks': blocks}

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            try:
                async with session.post(self.webhook_url, json=payload) as response:
                    return 200 <= response.status < 300
            except Exception as e:
                print(f"[slack] Error sending notification: {e}")
                return False
