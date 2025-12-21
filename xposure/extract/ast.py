"""JavaScript AST parsing for tracing secrets."""

import json
import re
from typing import Any, Generator, Optional


class JSASTParser:
    """Parse JavaScript code using AST to extract secrets."""

    def __init__(self, timeout: int = 10):
        """
        Initialize AST parser.

        Args:
            timeout: Timeout for parsing (seconds)
        """
        self.timeout = timeout
        self.parser_available = False

        # Try to import pyjsparser
        try:
            import pyjsparser
            self.parser = pyjsparser.PyJsParser()
            self.parser_available = True
        except ImportError:
            # Fall back to regex-based extraction
            self.parser_available = False

    def extract_assignments(self, js_code: str) -> Generator[dict, None, None]:
        """
        Extract variable assignments from JavaScript code.

        Args:
            js_code: JavaScript source code

        Yields:
            Dicts with:
                - name: variable name
                - value: assigned value
                - type: assignment type (var, const, let, property)
        """
        if self.parser_available:
            try:
                # Try AST parsing
                yield from self._extract_via_ast(js_code)
            except Exception:
                # Fall back to regex
                yield from self._extract_via_regex(js_code)
        else:
            # Regex-only fallback
            yield from self._extract_via_regex(js_code)

    def _extract_via_ast(self, js_code: str) -> Generator[dict, None, None]:
        """
        Extract assignments using AST parsing.

        Args:
            js_code: JavaScript source code

        Yields:
            Assignment dictionaries
        """
        try:
            # Parse JavaScript to AST
            ast = self.parser.parse(js_code)

            # Walk the AST
            yield from self._walk_ast(ast)

        except Exception:
            # Parsing failed, skip
            return

    def _walk_ast(self, node: Any, parent_path: str = "") -> Generator[dict, None, None]:
        """
        Recursively walk AST nodes.

        Args:
            node: AST node
            parent_path: Parent object path

        Yields:
            Assignment dictionaries
        """
        if not isinstance(node, dict):
            return

        node_type = node.get('type')

        # Variable declaration: const x = "value"
        if node_type == 'VariableDeclaration':
            for declarator in node.get('declarations', []):
                name = self._get_identifier(declarator.get('id'))
                value = self._get_literal_value(declarator.get('init'))

                if name and value is not None:
                    yield {
                        'name': name,
                        'value': value,
                        'type': node.get('kind', 'var'),
                    }

        # Assignment: x = "value"
        elif node_type == 'AssignmentExpression':
            name = self._get_identifier(node.get('left'))
            value = self._get_literal_value(node.get('right'))

            if name and value is not None:
                yield {
                    'name': name,
                    'value': value,
                    'type': 'assignment',
                }

        # Object property: {key: "value"}
        elif node_type == 'Property':
            key = self._get_identifier(node.get('key'))
            value = self._get_literal_value(node.get('value'))

            if key and value is not None:
                full_name = f"{parent_path}.{key}" if parent_path else key
                yield {
                    'name': full_name,
                    'value': value,
                    'type': 'property',
                }

        # Recursively process child nodes
        for key, child in node.items():
            if isinstance(child, dict):
                new_path = parent_path
                if node_type == 'ObjectExpression':
                    new_path = parent_path

                yield from self._walk_ast(child, new_path)
            elif isinstance(child, list):
                for item in child:
                    if isinstance(item, dict):
                        yield from self._walk_ast(item, parent_path)

    def _get_identifier(self, node: Optional[dict]) -> Optional[str]:
        """Extract identifier name from node."""
        if not node:
            return None

        if node.get('type') == 'Identifier':
            return node.get('name')

        if node.get('type') == 'Literal':
            return str(node.get('value'))

        return None

    def _get_literal_value(self, node: Optional[dict]) -> Optional[str]:
        """Extract literal value from node."""
        if not node:
            return None

        node_type = node.get('type')

        # String literal
        if node_type == 'Literal':
            value = node.get('value')
            if isinstance(value, str):
                return value

        # Template literal
        if node_type == 'TemplateLiteral':
            quasis = node.get('quasis', [])
            if len(quasis) == 1:  # Simple template without expressions
                return quasis[0].get('value', {}).get('cooked', '')

        return None

    def _extract_via_regex(self, js_code: str) -> Generator[dict, None, None]:
        """
        Extract assignments using regex patterns (fallback).

        Args:
            js_code: JavaScript source code

        Yields:
            Assignment dictionaries
        """
        # Variable declarations: const/let/var NAME = "value"
        var_pattern = r'(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\']+)["\']'

        for match in re.finditer(var_pattern, js_code):
            yield {
                'name': match.group(1),
                'value': match.group(2),
                'type': 'var',
            }

        # Object properties: key: "value"
        prop_pattern = r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:\s*["\']([^"\']+)["\']'

        for match in re.finditer(prop_pattern, js_code):
            yield {
                'name': match.group(1),
                'value': match.group(2),
                'type': 'property',
            }

        # Assignments: NAME = "value"
        assign_pattern = r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\']+)["\']'

        for match in re.finditer(assign_pattern, js_code):
            # Skip if it's a var declaration (already caught)
            if not re.search(r'(?:const|let|var)\s+' + re.escape(match.group(1)), js_code[:match.start()]):
                yield {
                    'name': match.group(1),
                    'value': match.group(2),
                    'type': 'assignment',
                }


def extract_config_objects(js_code: str) -> Generator[dict, None, None]:
    """
    Extract configuration-like objects from JavaScript.

    Args:
        js_code: JavaScript source code

    Yields:
        Configuration objects as dicts
    """
    # Look for config-like variable names
    config_patterns = [
        r'const\s+(config|Config|CONFIG|settings|Settings|env|ENV|credentials|Credentials)\s*=\s*(\{[^}]+\})',
        r'export\s+const\s+(config|Config|settings|env|credentials)\s*=\s*(\{[^}]+\})',
    ]

    for pattern in config_patterns:
        for match in re.finditer(pattern, js_code, re.DOTALL):
            var_name = match.group(1)
            obj_text = match.group(2)

            # Try to parse as JSON (with some fixes)
            try:
                # Convert JS object to JSON
                json_text = obj_text
                json_text = re.sub(r'([{,]\s*)([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:', r'\1"\2":', json_text)
                json_text = re.sub(r"'([^']*)'", r'"\1"', json_text)

                obj = json.loads(json_text)

                yield {
                    'name': var_name,
                    'value': obj,
                    'type': 'config_object',
                }
            except json.JSONDecodeError:
                # Couldn't parse, skip
                continue


def parse_js_file(js_code: str, timeout: int = 10) -> list[dict]:
    """
    Convenience function to parse JavaScript file.

    Args:
        js_code: JavaScript source code
        timeout: Timeout in seconds

    Returns:
        List of extracted assignments
    """
    parser = JSASTParser(timeout=timeout)
    return list(parser.extract_assignments(js_code))
