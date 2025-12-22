"""SARIF output formatter for X-POSURE.

SARIF (Static Analysis Results Interchange Format) is a standard JSON format
for static analysis tools. It's widely supported by GitHub, GitLab, Azure DevOps,
and other CI/CD platforms.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import json
from datetime import datetime, timezone
from typing import List, Optional
from pathlib import Path

from ..core.models import Finding, VerificationStatus, Severity
from ..verify.base import VerificationResult


# SARIF severity mapping
SEVERITY_TO_SARIF = {
    Severity.CRITICAL: 'error',
    Severity.HIGH: 'error',
    Severity.MEDIUM: 'warning',
    Severity.LOW: 'note',
    Severity.INFO: 'note',
}

# SARIF security severity mapping (for GitHub Code Scanning)
SEVERITY_TO_SECURITY_SEVERITY = {
    Severity.CRITICAL: 'critical',
    Severity.HIGH: 'high',
    Severity.MEDIUM: 'medium',
    Severity.LOW: 'low',
    Severity.INFO: 'low',
}


class SARIFFormatter:
    """Format findings as SARIF for CI/CD integration."""

    TOOL_NAME = 'X-POSURE'
    TOOL_VERSION = '4.0.0'
    SARIF_VERSION = '2.1.0'
    SARIF_SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json'

    def __init__(
        self,
        target: str,
        include_verification: bool = True,
        base_path: Optional[Path] = None,
    ):
        """
        Initialize SARIF formatter.

        Args:
            target: Scan target (URL or path)
            include_verification: Include verification results in output
            base_path: Base path for relative file URIs
        """
        self.target = target
        self.include_verification = include_verification
        self.base_path = base_path or Path.cwd()
        self._rules = {}  # Track unique rules

    def format(
        self,
        findings: List[Finding],
        verifications: Optional[dict[str, VerificationResult]] = None,
    ) -> dict:
        """
        Format findings as SARIF.

        Args:
            findings: List of findings
            verifications: Optional dict mapping finding IDs to verification results

        Returns:
            SARIF document as dict
        """
        verifications = verifications or {}

        # Build results
        results = []
        for finding in findings:
            verification = verifications.get(finding.id)
            result = self._format_finding(finding, verification)
            results.append(result)

        # Build rules from collected rule IDs
        rules = self._build_rules()

        # Build SARIF document
        sarif = {
            '$schema': self.SARIF_SCHEMA,
            'version': self.SARIF_VERSION,
            'runs': [
                {
                    'tool': {
                        'driver': {
                            'name': self.TOOL_NAME,
                            'version': self.TOOL_VERSION,
                            'informationUri': 'https://github.com/SnailSploit/Xposure',
                            'rules': rules,
                        }
                    },
                    'results': results,
                    'invocations': [
                        {
                            'executionSuccessful': True,
                            'endTimeUtc': datetime.now(timezone.utc).isoformat(),
                        }
                    ],
                    'properties': {
                        'target': self.target,
                        'findingsCount': len(findings),
                        'verifiedCount': len([v for v in verifications.values() if v and v.status == VerificationStatus.VERIFIED]),
                    }
                }
            ]
        }

        return sarif

    def format_json(
        self,
        findings: List[Finding],
        verifications: Optional[dict[str, VerificationResult]] = None,
        indent: int = 2,
    ) -> str:
        """
        Format findings as SARIF JSON string.

        Args:
            findings: List of findings
            verifications: Optional verification results
            indent: JSON indentation

        Returns:
            SARIF JSON string
        """
        sarif = self.format(findings, verifications)
        return json.dumps(sarif, indent=indent, default=str)

    def _format_finding(
        self,
        finding: Finding,
        verification: Optional[VerificationResult],
    ) -> dict:
        """Format a single finding as SARIF result."""

        # Get or create rule ID
        rule_id = self._get_rule_id(finding)

        # Determine severity level
        severity = finding.severity
        if verification and verification.status == VerificationStatus.VERIFIED:
            # Bump severity if verified active
            if severity == Severity.MEDIUM:
                severity = Severity.HIGH
            elif severity == Severity.LOW:
                severity = Severity.MEDIUM

        level = SEVERITY_TO_SARIF.get(severity, 'warning')

        # Build message
        message_parts = [f'Exposed {finding.credential_type}']

        if verification:
            if verification.status == VerificationStatus.VERIFIED:
                message_parts.append('[VERIFIED ACTIVE]')
                if verification.identity:
                    message_parts.append(f'Identity: {verification.identity}')
            elif verification.status == VerificationStatus.INVALID:
                message_parts.append('[INVALID/EXPIRED]')
            elif verification.status == VerificationStatus.LIKELY_VALID:
                message_parts.append('[LIKELY VALID]')

        message = ' - '.join(message_parts)

        # Build locations
        locations = []
        for source in finding.sources:
            location = self._format_location(source, finding)
            if location:
                locations.append(location)

        # If no locations, add a logical location
        if not locations:
            locations.append({
                'logicalLocations': [
                    {
                        'name': finding.credential_type,
                        'kind': 'credential',
                    }
                ]
            })

        # Build result
        result = {
            'ruleId': rule_id,
            'level': level,
            'message': {
                'text': message,
            },
            'locations': locations,
            'fingerprints': {
                'primaryLocationLineHash': finding.id,
            },
            'properties': {
                'credentialType': finding.credential_type,
                'confidence': finding.confidence,
                'severity': severity.value if hasattr(severity, 'value') else str(severity),
            }
        }

        # Add verification properties
        if verification:
            result['properties']['verification'] = {
                'status': verification.status.value if hasattr(verification.status, 'value') else str(verification.status),
                'method': verification.method,
            }
            if verification.identity:
                result['properties']['verification']['identity'] = verification.identity
            if verification.permissions:
                result['properties']['verification']['permissions'] = verification.permissions
            if verification.can_pivot_to:
                result['properties']['verification']['pivotTargets'] = verification.can_pivot_to
            if verification.blast_radius:
                br = verification.blast_radius
                result['properties']['verification']['blastRadius'] = br.value if hasattr(br, 'value') else str(br)

        # Add security-severity for GitHub
        security_severity = SEVERITY_TO_SECURITY_SEVERITY.get(severity, 'medium')
        result['properties']['security-severity'] = {
            'critical': '9.0',
            'high': '7.0',
            'medium': '5.0',
            'low': '3.0',
        }.get(security_severity, '5.0')

        return result

    def _format_location(self, source, finding: Finding) -> Optional[dict]:
        """Format a source as SARIF location."""
        # Handle file-based sources
        if hasattr(source, 'path') and source.path:
            artifact_location = {
                'uri': source.path,
            }

            # Make relative if possible
            try:
                path = Path(source.path)
                if path.is_absolute() and self.base_path:
                    try:
                        rel_path = path.relative_to(self.base_path)
                        artifact_location['uri'] = str(rel_path)
                    except ValueError:
                        pass
            except Exception:
                pass

            region = {}

            # Add line number if available
            if hasattr(source, 'line') and source.line:
                region['startLine'] = source.line

            # Add context snippet if available
            if hasattr(source, 'raw_context') and source.raw_context:
                context = source.raw_context
                # Find the value in context
                if finding.value in context:
                    # Mask the actual secret value
                    masked_value = finding.value[:4] + '*' * (len(finding.value) - 8) + finding.value[-4:] if len(finding.value) > 8 else '****'
                    masked_context = context.replace(finding.value, masked_value)
                    region['snippet'] = {
                        'text': masked_context[:500],  # Limit snippet size
                    }

            location = {
                'physicalLocation': {
                    'artifactLocation': artifact_location,
                }
            }

            if region:
                location['physicalLocation']['region'] = region

            return location

        # Handle URL-based sources
        if hasattr(source, 'url') and source.url:
            return {
                'logicalLocations': [
                    {
                        'name': source.url,
                        'kind': 'url',
                    }
                ]
            }

        return None

    def _get_rule_id(self, finding: Finding) -> str:
        """Get or create rule ID for finding type."""
        rule_id = f'XPOSURE-{finding.credential_type.upper().replace("_", "-")}'

        if rule_id not in self._rules:
            self._rules[rule_id] = {
                'id': rule_id,
                'name': finding.credential_type.replace('_', ' ').title(),
                'shortDescription': {
                    'text': f'Exposed {finding.credential_type}',
                },
                'fullDescription': {
                    'text': f'Detection of exposed {finding.credential_type} credential that may allow unauthorized access.',
                },
                'helpUri': 'https://github.com/SnailSploit/Xposure',
                'properties': {
                    'tags': ['security', 'secrets', 'credentials'],
                }
            }

        return rule_id

    def _build_rules(self) -> list:
        """Build rules list from collected rule IDs."""
        return list(self._rules.values())


def write_sarif(
    findings: List[Finding],
    output_path: str,
    target: str,
    verifications: Optional[dict[str, VerificationResult]] = None,
):
    """
    Write findings to SARIF file.

    Args:
        findings: List of findings
        output_path: Output file path
        target: Scan target
        verifications: Optional verification results
    """
    formatter = SARIFFormatter(target=target)
    sarif_json = formatter.format_json(findings, verifications)

    with open(output_path, 'w') as f:
        f.write(sarif_json)


def format_sarif(
    findings: List[Finding],
    target: str,
    verifications: Optional[dict[str, VerificationResult]] = None,
) -> str:
    """
    Format findings as SARIF JSON string.

    Args:
        findings: List of findings
        target: Scan target
        verifications: Optional verification results

    Returns:
        SARIF JSON string
    """
    formatter = SARIFFormatter(target=target)
    return formatter.format_json(findings, verifications)
