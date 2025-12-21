"""Object and config block extraction."""

import json
import re
from typing import Any, Generator, Optional


class ObjectExtractor:
    """Extract configuration objects and paired credentials."""

    def __init__(self):
        """Initialize object extractor."""
        pass

    def extract_json_objects(self, content: str) -> Generator[dict, None, None]:
        """
        Extract JSON objects from content.

        Args:
            content: Content to search

        Yields:
            Extracted objects with metadata
        """
        # Find JSON-like objects
        stack = []
        start = None

        for i, char in enumerate(content):
            if char == '{':
                if not stack:
                    start = i
                stack.append('{')
            elif char == '}':
                if stack and stack[-1] == '{':
                    stack.pop()
                    if not stack and start is not None:
                        # Complete object found
                        obj_text = content[start:i+1]

                        try:
                            obj = json.loads(obj_text)
                            if self._is_interesting_object(obj):
                                yield {
                                    'type': 'json_object',
                                    'value': obj,
                                    'raw': obj_text,
                                    'start': start,
                                    'end': i+1,
                                }
                        except json.JSONDecodeError:
                            pass

                        start = None

    def extract_key_value_pairs(self, content: str) -> Generator[dict, None, None]:
        """
        Extract key=value and key:value pairs.

        Args:
            content: Content to search

        Yields:
            Key-value pair dictionaries
        """
        # Pattern for key=value or key:value
        patterns = [
            # key="value" or key='value'
            r'([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["\']([^"\']+)["\']',
            # key: "value" or key: 'value'
            r'([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*["\']([^"\']+)["\']',
            # KEY=value (env var style)
            r'^([A-Z_][A-Z0-9_]*)\s*=\s*(.+)$',
        ]

        for pattern in patterns:
            flags = re.MULTILINE if pattern.startswith('^') else 0

            for match in re.finditer(pattern, content, flags):
                key = match.group(1)
                value = match.group(2).strip().strip('"\'')

                # Skip very short or empty values
                if not value or len(value) < 4:
                    continue

                yield {
                    'type': 'key_value',
                    'key': key,
                    'value': value,
                }

    def extract_connection_strings(self, content: str) -> Generator[dict, None, None]:
        """
        Extract database connection strings and URIs.

        Args:
            content: Content to search

        Yields:
            Connection string dictionaries
        """
        # Database URIs
        uri_patterns = {
            'mongodb': r'mongodb(?:\+srv)?://([^:]+):([^@]+)@([^\s"\']+)',
            'postgresql': r'postgres(?:ql)?://([^:]+):([^@]+)@([^\s"\']+)',
            'mysql': r'mysql://([^:]+):([^@]+)@([^\s"\']+)',
            'redis': r'redis://(?:[^:]*:)?([^@]+)@([^\s"\']+)',
        }

        for db_type, pattern in uri_patterns.items():
            for match in re.finditer(pattern, content):
                full_uri = match.group(0)

                # Extract components
                if db_type == 'redis':
                    password = match.group(1)
                    host = match.group(2)
                    username = None
                else:
                    username = match.group(1)
                    password = match.group(2)
                    host = match.group(3)

                yield {
                    'type': 'connection_string',
                    'db_type': db_type,
                    'uri': full_uri,
                    'username': username,
                    'password': password,
                    'host': host,
                }

    def extract_credential_pairs(self, content: str) -> Generator[dict, None, None]:
        """
        Extract paired credentials (key + secret, username + password).

        Args:
            content: Content to search

        Yields:
            Credential pair dictionaries
        """
        # Common pairing patterns
        pairs = [
            ('api_key', 'api_secret'),
            ('apikey', 'apisecret'),
            ('access_key', 'secret_key'),
            ('access_key_id', 'secret_access_key'),
            ('client_id', 'client_secret'),
            ('username', 'password'),
            ('user', 'pass'),
            ('aws_access_key_id', 'aws_secret_access_key'),
        ]

        # Try to find pairs within proximity
        for key_pattern, secret_pattern in pairs:
            # Build regex
            key_regex = rf'{key_pattern}["\']?\s*[:=]\s*["\']?([^"\'\s]+)["\']?'
            secret_regex = rf'{secret_pattern}["\']?\s*[:=]\s*["\']?([^"\'\s]+)["\']?'

            # Find all keys and secrets
            keys = list(re.finditer(key_regex, content, re.IGNORECASE))
            secrets = list(re.finditer(secret_regex, content, re.IGNORECASE))

            # Pair them if they're close to each other (within 500 chars)
            for key_match in keys:
                key_value = key_match.group(1)
                key_pos = key_match.start()

                for secret_match in secrets:
                    secret_value = secret_match.group(1)
                    secret_pos = secret_match.start()

                    # Check proximity (within 500 chars)
                    if abs(key_pos - secret_pos) < 500:
                        yield {
                            'type': 'credential_pair',
                            'key_name': key_pattern,
                            'key_value': key_value,
                            'secret_name': secret_pattern,
                            'secret_value': secret_value,
                            'proximity': abs(key_pos - secret_pos),
                        }
                        break  # Only pair with closest match

    def _is_interesting_object(self, obj: Any) -> bool:
        """
        Check if object is interesting (likely to contain secrets).

        Args:
            obj: Python object

        Returns:
            True if interesting
        """
        if not isinstance(obj, dict):
            return False

        # Must have at least one key
        if not obj:
            return False

        # Look for interesting key names
        interesting_keys = {
            'api_key', 'apikey', 'api_secret', 'apisecret',
            'access_key', 'secret_key', 'secret_access_key',
            'password', 'passwd', 'pwd',
            'token', 'auth_token', 'access_token',
            'client_id', 'client_secret',
            'credentials', 'auth', 'authorization',
            'aws_access_key_id', 'aws_secret_access_key',
            'database_url', 'db_url', 'connection_string',
        }

        # Check if any keys match
        obj_keys = set(str(k).lower() for k in obj.keys())

        return bool(obj_keys & interesting_keys)


def extract_all_objects(content: str) -> dict:
    """
    Extract all objects and structures from content.

    Args:
        content: Content to extract from

    Returns:
        Dict with categorized extractions
    """
    extractor = ObjectExtractor()

    return {
        'json_objects': list(extractor.extract_json_objects(content)),
        'key_value_pairs': list(extractor.extract_key_value_pairs(content)),
        'connection_strings': list(extractor.extract_connection_strings(content)),
        'credential_pairs': list(extractor.extract_credential_pairs(content)),
    }


def extract_env_file(content: str) -> dict[str, str]:
    """
    Extract variables from .env file format.

    Args:
        content: .env file content

    Returns:
        Dict of key-value pairs
    """
    env_vars = {}

    for line in content.split('\n'):
        line = line.strip()

        # Skip comments and empty lines
        if not line or line.startswith('#'):
            continue

        # Parse KEY=value
        if '=' in line:
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip().strip('"\'')

            if key and value:
                env_vars[key] = value

    return env_vars
