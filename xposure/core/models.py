"""X-POSURE core data models."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VerificationStatus(Enum):
    """Verification status for credentials."""
    VERIFIED = "verified"
    LIKELY_VALID = "likely_valid"
    UNVERIFIED = "unverified"
    INVALID = "invalid"
    ERROR = "error"


@dataclass
class Source:
    """Where a credential was found."""
    type: str                    # js_bundle, github, s3, wayback, etc.
    url: str
    path: Optional[str] = None
    line: Optional[int] = None
    commit: Optional[str] = None
    author: Optional[str] = None
    timestamp: Optional[datetime] = None
    raw_context: Optional[str] = None  # surrounding code

    def __eq__(self, other) -> bool:
        """Compare sources by value, not identity."""
        if not isinstance(other, Source):
            return False
        return (
            self.type == other.type and
            self.url == other.url and
            self.path == other.path and
            self.line == other.line and
            self.commit == other.commit and
            self.author == other.author
            # Exclude timestamp from comparison (changes between runs)
        )

    def __hash__(self) -> int:
        """Make Source hashable for use in sets."""
        return hash((self.type, self.url, self.path, self.line,
                    self.commit, self.author))

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "type": self.type,
            "url": self.url,
            "path": self.path,
            "line": self.line,
            "commit": self.commit,
            "author": self.author,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "raw_context": self.raw_context,
        }


@dataclass
class Candidate:
    """A potential credential before verification."""
    type: str                    # aws_access_key, stripe_secret, etc.
    value: str
    source: Source
    entropy: float
    context: str                 # surrounding code
    confidence: float = 0.0
    paired_with: Optional['Candidate'] = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "type": self.type,
            "value": self.value,
            "source": self.source.to_dict(),
            "entropy": self.entropy,
            "context": self.context,
            "confidence": self.confidence,
            "paired_with": self.paired_with.type if self.paired_with else None,
        }


@dataclass
class Finding:
    """A verified (or attempted) credential."""
    id: str
    credential_type: str
    value: str
    masked_value: str            # for display

    # Pairing
    paired_credentials: dict = field(default_factory=dict)

    # Verification
    status: VerificationStatus = VerificationStatus.UNVERIFIED
    verification_method: Optional[str] = None
    identity: Optional[str] = None
    permissions: list[str] = field(default_factory=list)
    can_pivot_to: list[str] = field(default_factory=list)
    blast_radius: Severity = Severity.MEDIUM
    environment: Optional[str] = None  # production, staging, test

    # Confidence
    confidence: float = 0.0
    confidence_factors: list[str] = field(default_factory=list)

    # Sources (multi-evidence)
    sources: list[Source] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    exposure_days: int = 0

    # Evidence
    evidence: dict = field(default_factory=dict)
    entropy: float = 0.0
    metadata: dict = field(default_factory=dict)

    # Severity (from rule matching)
    severity: Optional[Severity] = None

    # Remediation
    remediation: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for export."""
        return {
            "id": self.id,
            "credential_type": self.credential_type,
            "value": self.value,
            "masked_value": self.masked_value,
            "paired_credentials": self.paired_credentials,
            "status": self.status.value if isinstance(self.status, VerificationStatus) else self.status,
            "verification_method": self.verification_method,
            "identity": self.identity,
            "permissions": self.permissions,
            "can_pivot_to": self.can_pivot_to,
            "blast_radius": self.blast_radius.value if isinstance(self.blast_radius, Severity) else self.blast_radius,
            "environment": self.environment,
            "confidence": self.confidence,
            "confidence_factors": self.confidence_factors,
            "sources": [s.to_dict() for s in self.sources],
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "exposure_days": self.exposure_days,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }

    def add_source(self, source: Source):
        """Add a source to this finding."""
        if source not in self.sources:
            self.sources.append(source)
            if not self.first_seen:
                self.first_seen = source.timestamp or datetime.now()

    def update_confidence(self, delta: float, reason: str):
        """Update confidence score with reason and bounds checking."""
        old_confidence = self.confidence
        self.confidence = max(0.0, min(1.0, self.confidence + delta))
        actual_delta = self.confidence - old_confidence
        if abs(actual_delta - delta) > 0.001:  # Was clamped
            self.confidence_factors.append(f"{actual_delta:+.2f} {reason} (clamped from {delta:+.2f})")
        else:
            self.confidence_factors.append(f"{delta:+.2f} {reason}")


@dataclass
class InfraMapping:
    """Infrastructure mapping from DNS resolution + Shodan."""
    domain_to_ips: dict = field(default_factory=dict)   # domain -> [ips]
    ip_to_shodan: dict = field(default_factory=dict)    # ip -> ShodanHostInfo dict
    dns_records: dict = field(default_factory=dict)     # domain -> ResolvedHost dict
    unique_ips: list[str] = field(default_factory=list)
    total_open_ports: int = 0
    total_vulns: int = 0

    def to_dict(self) -> dict:
        return {
            "domain_to_ips": self.domain_to_ips,
            "ip_to_shodan": self.ip_to_shodan,
            "dns_records": self.dns_records,
            "unique_ips": self.unique_ips,
            "total_open_ports": self.total_open_ports,
            "total_vulns": self.total_vulns,
        }


@dataclass
class ScanStats:
    """Statistics for a scan."""
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None

    # Discovery stats
    subdomains_found: int = 0
    js_files_found: int = 0
    github_repos_found: int = 0
    buckets_found: int = 0
    sourcemaps_found: int = 0
    wayback_urls_found: int = 0

    # Recursive crawl stats
    crawl_pages: int = 0
    crawl_urls_found: int = 0
    trufflehog_findings: int = 0

    # Extract stats
    decoded_blobs: int = 0
    ast_parsed: int = 0
    candidates_found: int = 0
    paired_credentials: int = 0

    # Verification stats
    verified_findings: int = 0
    unverified_findings: int = 0
    invalid_findings: int = 0
    error_findings: int = 0

    # Enrichment stats
    dns_resolved: int = 0
    shodan_queried: int = 0
    ai_analyzed: bool = False

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        result = {
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": (self.end_time - self.start_time).total_seconds() if self.end_time else None,
            "discovery": {
                "subdomains": self.subdomains_found,
                "js_files": self.js_files_found,
                "github_repos": self.github_repos_found,
                "buckets": self.buckets_found,
                "sourcemaps": self.sourcemaps_found,
                "wayback_urls": self.wayback_urls_found,
            },
            "extraction": {
                "decoded_blobs": self.decoded_blobs,
                "ast_parsed": self.ast_parsed,
                "candidates": self.candidates_found,
                "paired": self.paired_credentials,
            },
            "verification": {
                "verified": self.verified_findings,
                "unverified": self.unverified_findings,
                "invalid": self.invalid_findings,
                "errors": self.error_findings,
            },
        }
        if self.crawl_pages or self.crawl_urls_found or self.trufflehog_findings:
            result["recursive_crawl"] = {
                "pages_crawled": self.crawl_pages,
                "urls_found": self.crawl_urls_found,
                "trufflehog_findings": self.trufflehog_findings,
            }
        if self.dns_resolved or self.shodan_queried or self.ai_analyzed:
            result["enrichment"] = {
                "dns_resolved": self.dns_resolved,
                "shodan_queried": self.shodan_queried,
                "ai_analyzed": self.ai_analyzed,
            }
        return result
