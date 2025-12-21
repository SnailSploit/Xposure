"""X-POSURE state persistence and resume functionality."""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Set

from .core.models import Finding, ScanStats


class ScanState:
    """Manages scan state for resume functionality and deduplication."""

    def __init__(self, scan_id: str, state_file: Path):
        """Initialize scan state."""
        self.scan_id = scan_id
        self.state_file = state_file
        self.seen_urls: Set[str] = set()
        self.seen_hashes: Set[str] = set()  # For dedup
        self.findings: list[Finding] = []
        self.stats: Optional[ScanStats] = None

        # Load existing state if available
        self._load()

    def _load(self):
        """Load state from disk."""
        if not self.state_file.exists():
            return

        try:
            with open(self.state_file, 'r') as f:
                data = json.load(f)

            self.seen_urls = set(data.get('seen_urls', []))
            self.seen_hashes = set(data.get('seen_hashes', []))

            # Note: Findings are not loaded for simplicity
            # In production, you'd deserialize findings properly

        except Exception as e:
            print(f"Warning: Could not load state: {e}")

    def save(self):
        """Save state to disk."""
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)

            data = {
                'scan_id': self.scan_id,
                'saved_at': datetime.now().isoformat(),
                'seen_urls': list(self.seen_urls),
                'seen_hashes': list(self.seen_hashes),
                'findings_count': len(self.findings),
                'stats': self.stats.to_dict() if self.stats else None,
            }

            with open(self.state_file, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            print(f"Warning: Could not save state: {e}")

    def mark_seen_url(self, url: str) -> bool:
        """
        Mark a URL as seen.

        Returns:
            True if URL was not seen before, False if it was already seen
        """
        if url in self.seen_urls:
            return False
        self.seen_urls.add(url)
        return True

    def is_duplicate(self, value: str, source_type: str) -> bool:
        """
        Check if a credential value has been seen before.

        Args:
            value: The credential value
            source_type: Type of source (for scoping)

        Returns:
            True if duplicate, False if new
        """
        # Create hash of value + type for deduplication
        key = f"{source_type}:{value}"
        h = hashlib.sha256(key.encode()).hexdigest()

        if h in self.seen_hashes:
            return True

        self.seen_hashes.add(h)
        return False

    def add_finding(self, finding: Finding):
        """Add a finding to the state."""
        self.findings.append(finding)

    def get_findings(self) -> list[Finding]:
        """Get all findings."""
        return self.findings

    def update_stats(self, stats: ScanStats):
        """Update scan statistics."""
        self.stats = stats

    def export(self, output_file: Path):
        """
        Export findings to JSON file.

        Args:
            output_file: Path to output JSON file
        """
        try:
            output_file.parent.mkdir(parents=True, exist_ok=True)

            data = {
                'scan_id': self.scan_id,
                'exported_at': datetime.now().isoformat(),
                'stats': self.stats.to_dict() if self.stats else None,
                'findings': [f.to_dict() for f in self.findings],
            }

            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)

            print(f"Exported {len(self.findings)} findings to {output_file}")

        except Exception as e:
            print(f"Error exporting findings: {e}")


def generate_scan_id(target: str) -> str:
    """
    Generate a unique scan ID based on target and timestamp.

    Args:
        target: Target domain

    Returns:
        Scan ID string
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = "".join(c if c.isalnum() else "_" for c in target)
    return f"{safe_target}_{timestamp}"
