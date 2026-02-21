"""JWT pre-extraction for X-POSURE.

Pre-scans content for complete JWTs BEFORE the rule engine runs,
preventing a single JWT from being fragmented into hundreds of
base64-matching false positives.
"""

import re
import json
import base64
from dataclasses import dataclass, field


@dataclass
class ExtractedJWT:
    """A complete JWT extracted from content."""
    raw: str
    header: dict
    payload: dict
    start: int
    end: int


JWT_PATTERN = re.compile(
    r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
)


class JWTPreScanner:
    """Extract complete JWTs BEFORE rule engine runs, mask their byte ranges."""

    def prescan(self, content: str) -> tuple[str, list[ExtractedJWT]]:
        """
        Pre-scan content for complete JWTs.

        1. Find all complete JWTs via regex
        2. Decode header+payload (ignore signature)
        3. Replace matched ranges with null bytes (same length to preserve offsets)
        4. Return (masked_content, extracted_jwts)

        The masked content goes to the rule engine — no more fragment FPs.
        The extracted JWTs become findings directly with decoded metadata.

        Args:
            content: Raw content to scan

        Returns:
            Tuple of (masked_content, list of extracted JWTs)
        """
        jwts = []
        masked = list(content)

        for match in JWT_PATTERN.finditer(content):
            raw = match.group(0)
            try:
                parts = raw.split('.')
                header = json.loads(self._b64decode(parts[0]))
                payload = json.loads(self._b64decode(parts[1]))

                jwt = ExtractedJWT(
                    raw=raw,
                    header=header,
                    payload=payload,
                    start=match.start(),
                    end=match.end(),
                )
                jwts.append(jwt)

                # Mask the byte range so rule engine skips it
                for i in range(match.start(), match.end()):
                    masked[i] = '\x00'

            except Exception:
                pass  # Not a valid JWT, leave for rule engine

        return ''.join(masked), jwts

    @staticmethod
    def _b64decode(s: str) -> bytes:
        """Base64url decode with padding fix."""
        s += '=' * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(s)
