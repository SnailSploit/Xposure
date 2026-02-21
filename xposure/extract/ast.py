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

        # Try to import esprima (preferred) or pyjsparser (legacy fallback)
        try:
            import esprima
            self._esprima = esprima
            self.parser_available = True
        except ImportError:
            try:
                import pyjsparser
                self._pyjsparser = pyjsparser.PyJsParser()
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
            # Parse JavaScript to AST — esprima returns objects with .toDict()
            if hasattr(self, '_esprima'):
                ast_obj = self._esprima.parseScript(js_code, tolerant=True)
                ast = ast_obj.toDict()
            else:
                ast = self._pyjsparser.parse(js_code)

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

        # Object destructuring: const { apiKey, secret } = config
        elif node_type == 'VariableDeclaration':
            for declarator in node.get('declarations', []):
                id_node = declarator.get('id')
                init_node = declarator.get('init')

                # Check for ObjectPattern (destructuring)
                if id_node and id_node.get('type') == 'ObjectPattern':
                    source_name = self._get_identifier(init_node)
                    for prop in id_node.get('properties', []):
                        key = self._get_identifier(prop.get('key'))
                        if key:
                            yield {
                                'name': key,
                                'value': f"${{{source_name}.{key}}}" if source_name else f"${{...{key}}}",
                                'type': 'destructuring',
                                'source': source_name,
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

        node_type = node.get('type')

        if node_type == 'Identifier':
            return node.get('name')

        if node_type == 'Literal':
            return str(node.get('value'))

        # Handle member expressions: obj.prop or obj["prop"]
        if node_type == 'MemberExpression':
            obj = self._get_identifier(node.get('object'))
            prop = self._get_identifier(node.get('property'))
            if obj and prop:
                return f"{obj}.{prop}"

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

        # Template literal: `string ${expr} more`
        if node_type == 'TemplateLiteral':
            return self._extract_template_literal(node)

        # Binary expression (string concatenation): "a" + "b"
        if node_type == 'BinaryExpression' and node.get('operator') == '+':
            left = self._get_literal_value(node.get('left'))
            right = self._get_literal_value(node.get('right'))
            if left is not None and right is not None:
                return left + right
            # Return partial if one side is a string
            if left is not None:
                return left + "${...}"
            if right is not None:
                return "${...}" + right

        # Member expression for process.env.VAR
        if node_type == 'MemberExpression':
            obj = self._get_identifier(node.get('object'))
            if obj and obj.startswith('process.env'):
                prop = self._get_identifier(node.get('property'))
                if prop:
                    return f"${{process.env.{prop}}}"

        return None

    def _extract_template_literal(self, node: dict) -> Optional[str]:
        """
        Extract template literal value, handling expressions.

        Args:
            node: TemplateLiteral AST node

        Returns:
            Reconstructed template string with ${...} for expressions
        """
        quasis = node.get('quasis', [])
        expressions = node.get('expressions', [])

        if not quasis:
            return None

        # Simple template without expressions
        if len(quasis) == 1 and not expressions:
            return quasis[0].get('value', {}).get('cooked', '')

        # Template with expressions - reconstruct
        parts = []
        for i, quasi in enumerate(quasis):
            cooked = quasi.get('value', {}).get('cooked', '')
            parts.append(cooked)

            # Add expression placeholder if there's a corresponding expression
            if i < len(expressions):
                expr = expressions[i]
                # Try to extract the expression value
                expr_val = self._get_literal_value(expr)
                if expr_val is not None:
                    parts.append(expr_val)
                else:
                    # Use identifier name if available
                    expr_name = self._get_identifier(expr)
                    if expr_name:
                        parts.append(f"${{{expr_name}}}")
                    else:
                        parts.append("${...}")

        return ''.join(parts)

    def _extract_via_regex(self, js_code: str) -> Generator[dict, None, None]:
        """
        Extract assignments using regex patterns (fallback).

        Args:
            js_code: JavaScript source code

        Yields:
            Assignment dictionaries
        """
        seen_values = set()  # Avoid duplicates

        # Variable declarations: const/let/var NAME = "value"
        var_pattern = r'(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\']+)["\']'

        for match in re.finditer(var_pattern, js_code):
            value = match.group(2)
            if value not in seen_values:
                seen_values.add(value)
                yield {
                    'name': match.group(1),
                    'value': value,
                    'type': 'var',
                }

        # Template literal declarations: const NAME = `value`
        template_pattern = r'(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*`([^`]+)`'

        for match in re.finditer(template_pattern, js_code):
            value = match.group(2)
            if value not in seen_values:
                seen_values.add(value)
                yield {
                    'name': match.group(1),
                    'value': value,
                    'type': 'template',
                }

        # Object properties: key: "value"
        prop_pattern = r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:\s*["\']([^"\']+)["\']'

        for match in re.finditer(prop_pattern, js_code):
            value = match.group(2)
            if value not in seen_values:
                seen_values.add(value)
                yield {
                    'name': match.group(1),
                    'value': value,
                    'type': 'property',
                }

        # Object properties with template literals: key: `value`
        prop_template_pattern = r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:\s*`([^`]+)`'

        for match in re.finditer(prop_template_pattern, js_code):
            value = match.group(2)
            if value not in seen_values:
                seen_values.add(value)
                yield {
                    'name': match.group(1),
                    'value': value,
                    'type': 'property_template',
                }

        # process.env patterns: process.env.VAR_NAME or process.env["VAR_NAME"]
        env_pattern = r'process\.env\.([A-Z_][A-Z0-9_]*)'
        for match in re.finditer(env_pattern, js_code):
            yield {
                'name': f'process.env.{match.group(1)}',
                'value': f'${{process.env.{match.group(1)}}}',
                'type': 'env_reference',
            }

        env_bracket_pattern = r'process\.env\[["\']([A-Z_][A-Z0-9_]*)["\']\]'
        for match in re.finditer(env_bracket_pattern, js_code):
            yield {
                'name': f'process.env.{match.group(1)}',
                'value': f'${{process.env.{match.group(1)}}}',
                'type': 'env_reference',
            }

        # Destructuring patterns: const { apiKey, secret } = obj
        destructure_pattern = r'(?:const|let|var)\s*\{\s*([^}]+)\s*\}\s*=\s*([a-zA-Z_$][a-zA-Z0-9_$.]*)'
        for match in re.finditer(destructure_pattern, js_code):
            source = match.group(2)
            props = match.group(1)
            for prop in props.split(','):
                prop = prop.strip()
                # Handle rename: originalName: newName
                if ':' in prop:
                    original, _ = prop.split(':', 1)
                    prop = original.strip()
                if prop and re.match(r'^[a-zA-Z_$][a-zA-Z0-9_$]*$', prop):
                    yield {
                        'name': prop,
                        'value': f'${{{source}.{prop}}}',
                        'type': 'destructuring',
                        'source': source,
                    }

        # Assignments: NAME = "value" (not part of declaration)
        assign_pattern = r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\']([^"\']+)["\']'

        for match in re.finditer(assign_pattern, js_code):
            value = match.group(2)
            if value not in seen_values:
                # Skip if it's a var declaration (already caught)
                preceding = js_code[max(0, match.start()-20):match.start()]
                if not re.search(r'(?:const|let|var)\s*$', preceding):
                    seen_values.add(value)
                    yield {
                        'name': match.group(1),
                        'value': value,
                        'type': 'assignment',
                    }

        # Member assignments: obj.prop = "value"
        member_assign_pattern = r'([a-zA-Z_$][a-zA-Z0-9_$]*(?:\.[a-zA-Z_$][a-zA-Z0-9_$]*)+)\s*=\s*["\']([^"\']+)["\']'

        for match in re.finditer(member_assign_pattern, js_code):
            value = match.group(2)
            if value not in seen_values:
                seen_values.add(value)
                yield {
                    'name': match.group(1),
                    'value': value,
                    'type': 'member_assignment',
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
