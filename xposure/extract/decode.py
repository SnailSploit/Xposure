"""Recursive decoding chain for obfuscated secrets."""

import base64
import binascii
import re
import urllib.parse
from typing import Generator, Set


class DecodeChain:
    """Recursively decode obfuscated content."""

    def __init__(self, max_depth: int = 5):
        """
        Initialize decode chain.

        Args:
            max_depth: Maximum recursion depth
        """
        self.max_depth = max_depth

    def decode_all(self, content: str) -> Generator[tuple[str, list[str]], None, None]:
        """
        Recursively decode content and yield all decoded variants.

        Args:
            content: Content to decode

        Yields:
            Tuple of (decoded_content, decode_path)
            where decode_path is list of decoding methods used
        """
        seen: Set[str] = set()
        queue = [(content, [])]

        while queue:
            current, path = queue.pop(0)

            # Skip if we've seen this already
            if current in seen:
                continue

            seen.add(current)

            # Yield this variant
            yield current, path

            # Stop if we've reached max depth
            if len(path) >= self.max_depth:
                continue

            # Try all decoding methods
            for decoder_name, decoder_func in self._get_decoders():
                try:
                    decoded = decoder_func(current)

                    # Only queue if actually different
                    if decoded and decoded != current and decoded not in seen:
                        queue.append((decoded, path + [decoder_name]))

                except Exception:
                    # Decoding failed, skip
                    continue

    def _get_decoders(self):
        """Get list of decoder functions."""
        return [
            ('base64', self._decode_base64),
            ('base64_url', self._decode_base64_url),
            ('hex', self._decode_hex),
            ('url', self._decode_url),
            ('unicode_escape', self._decode_unicode_escape),
            ('rot13', self._decode_rot13),
        ]

    def _decode_base64(self, content: str) -> str:
        """
        Decode base64 content.

        Args:
            content: Content to decode

        Returns:
            Decoded string or empty if failed
        """
        # Look for base64-like strings (at least 20 chars, mostly alphanumeric+/+=)
        if len(content) < 20:
            return ""

        # Must be mostly base64 chars
        base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        valid_ratio = sum(1 for c in content if c in base64_chars) / len(content)

        if valid_ratio < 0.8:
            return ""

        try:
            # Add padding if needed
            missing_padding = len(content) % 4
            if missing_padding:
                content += '=' * (4 - missing_padding)

            decoded_bytes = base64.b64decode(content, validate=True)
            decoded = decoded_bytes.decode('utf-8', errors='ignore')

            # Only return if decoded looks meaningful (not binary junk)
            if self._looks_meaningful(decoded):
                return decoded

        except Exception:
            pass

        return ""

    def _decode_base64_url(self, content: str) -> str:
        """
        Decode base64url content (URL-safe base64).

        Args:
            content: Content to decode

        Returns:
            Decoded string or empty if failed
        """
        try:
            # Add padding if needed
            missing_padding = len(content) % 4
            if missing_padding:
                content += '=' * (4 - missing_padding)

            decoded_bytes = base64.urlsafe_b64decode(content)
            decoded = decoded_bytes.decode('utf-8', errors='ignore')

            if self._looks_meaningful(decoded):
                return decoded

        except Exception:
            pass

        return ""

    def _decode_hex(self, content: str) -> str:
        """
        Decode hexadecimal content.

        Args:
            content: Content to decode

        Returns:
            Decoded string or empty if failed
        """
        # Must be even length and all hex chars
        if len(content) < 16 or len(content) % 2 != 0:
            return ""

        # Check if mostly hex chars
        hex_chars = set('0123456789abcdefABCDEF')
        if not all(c in hex_chars for c in content):
            return ""

        try:
            decoded_bytes = bytes.fromhex(content)
            decoded = decoded_bytes.decode('utf-8', errors='ignore')

            if self._looks_meaningful(decoded):
                return decoded

        except Exception:
            pass

        return ""

    def _decode_url(self, content: str) -> str:
        """
        Decode URL-encoded content.

        Args:
            content: Content to decode

        Returns:
            Decoded string or empty if failed
        """
        # Must contain URL encoding patterns
        if '%' not in content:
            return ""

        try:
            decoded = urllib.parse.unquote(content)

            # Only return if actually different
            if decoded != content:
                return decoded

        except Exception:
            pass

        return ""

    def _decode_unicode_escape(self, content: str) -> str:
        """
        Decode unicode escape sequences.

        Args:
            content: Content to decode

        Returns:
            Decoded string or empty if failed
        """
        # Must contain unicode escapes
        if '\\u' not in content and '\\x' not in content:
            return ""

        try:
            decoded = content.encode().decode('unicode_escape')

            if decoded != content:
                return decoded

        except Exception:
            pass

        return ""

    def _decode_rot13(self, content: str) -> str:
        """
        Decode ROT13 content.

        Args:
            content: Content to decode

        Returns:
            Decoded string or empty if failed
        """
        # Only try on mostly alphabetic strings
        if not content.isalpha():
            return ""

        try:
            import codecs
            decoded = codecs.decode(content, 'rot_13')

            if decoded != content:
                return decoded

        except Exception:
            pass

        return ""

    def _looks_meaningful(self, s: str) -> bool:
        """
        Check if decoded string looks meaningful (not binary junk).

        Args:
            s: String to check

        Returns:
            True if looks meaningful
        """
        if not s or len(s) < 4:
            return False

        # Must be mostly printable ASCII
        printable_count = sum(1 for c in s if 32 <= ord(c) < 127 or c in '\n\r\t')
        if printable_count / len(s) < 0.8:
            return False

        # Must contain some alphanumeric
        if not any(c.isalnum() for c in s):
            return False

        return True


def extract_encoded_strings(content: str) -> Generator[str, None, None]:
    """
    Extract potential encoded strings from content.

    Args:
        content: Content to search

    Yields:
        Potential encoded strings
    """
    # Base64-like patterns (at least 20 chars)
    base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'

    for match in re.finditer(base64_pattern, content):
        yield match.group(0)

    # Hex patterns (at least 32 chars, even length)
    hex_pattern = r'(?:0x)?[0-9a-fA-F]{32,}'

    for match in re.finditer(hex_pattern, content):
        hex_str = match.group(0).replace('0x', '')
        if len(hex_str) % 2 == 0:
            yield hex_str

    # URL-encoded patterns
    url_pattern = r'(?:%[0-9a-fA-F]{2}){4,}'

    for match in re.finditer(url_pattern, content):
        yield match.group(0)


def decode_content(content: str, max_depth: int = 5) -> list[tuple[str, list[str]]]:
    """
    Convenience function to decode content.

    Args:
        content: Content to decode
        max_depth: Maximum recursion depth

    Returns:
        List of (decoded_content, decode_path) tuples
    """
    decoder = DecodeChain(max_depth=max_depth)
    return list(decoder.decode_all(content))
