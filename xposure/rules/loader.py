"""YAML rule loader for X-POSURE."""

import re
from pathlib import Path
from typing import Optional

import yaml


class Rule:
    """Represents a detection rule."""

    def __init__(self, rule_dict: dict):
        """
        Initialize rule from dictionary.

        Args:
            rule_dict: Rule configuration dictionary
        """
        self.id = rule_dict['id']
        self.name = rule_dict['name']
        self.type = rule_dict['type']
        self.severity = rule_dict.get('severity', 'medium')
        self.pattern = rule_dict['pattern']

        # Compile regex pattern
        flags = 0
        if rule_dict.get('case_insensitive', False):
            flags |= re.IGNORECASE
        if rule_dict.get('multiline', False):
            flags |= re.MULTILINE | re.DOTALL

        try:
            self.compiled_pattern = re.compile(self.pattern, flags)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern in rule {self.id}: {e}")

        # Pairing and context
        self.pair_with = rule_dict.get('pair_with')
        if isinstance(self.pair_with, str):
            self.pair_with = [self.pair_with]

        self.context_required = rule_dict.get('context_required', False)
        self.context_patterns = rule_dict.get('context_patterns', [])

        # Exclusions
        self.exclude_patterns = rule_dict.get('exclude_patterns', [])
        self.exclude_compiled = [re.compile(p, re.IGNORECASE) for p in self.exclude_patterns]

        # Metadata
        self.metadata = rule_dict.get('metadata', {})
        self.verifier = rule_dict.get('verifier')
        self.remediation = rule_dict.get('remediation')
        self.capture_group = rule_dict.get('capture_group', 0)

    def match(self, content: str, context_window: int = 200) -> list[dict]:
        """
        Match rule against content.

        Args:
            content: Content to match against
            context_window: Characters to include in context

        Returns:
            List of match dictionaries
        """
        matches = []

        for match in self.compiled_pattern.finditer(content):
            # Extract value (use capture group if specified)
            if self.capture_group and match.lastindex and match.lastindex >= self.capture_group:
                value = match.group(self.capture_group)
            else:
                value = match.group(0)

            # Clean value
            value = value.strip().strip('"\'`')

            # Skip if excluded
            if any(exc.search(value) for exc in self.exclude_compiled):
                continue

            # Extract context
            start = max(0, match.start() - context_window)
            end = min(len(content), match.end() + context_window)
            context = content[start:end]

            # Check context requirements
            if self.context_required:
                if not self._check_context(context):
                    continue

            matches.append({
                'rule_id': self.id,
                'rule_name': self.name,
                'type': self.type,
                'value': value,
                'severity': self.severity,
                'context': context,
                'start': match.start(),
                'end': match.end(),
                'metadata': self.metadata.copy(),
                'verifier': self.verifier,
                'remediation': self.remediation,
                'pair_with': self.pair_with,
                'capture_group': self.capture_group,
            })

        return matches

    def _check_context(self, context: str) -> bool:
        """
        Check if context contains required patterns.

        Args:
            context: Context string

        Returns:
            True if context is valid
        """
        if not self.context_patterns:
            return True

        # At least one pattern must match
        for pattern in self.context_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True

        return False

    def __repr__(self):
        return f"Rule(id={self.id}, name={self.name}, type={self.type})"


class RuleLoader:
    """Loads and manages detection rules from YAML files."""

    def __init__(self, rules_dir: Optional[Path] = None):
        """
        Initialize rule loader.

        Args:
            rules_dir: Directory containing YAML rule files
        """
        if rules_dir is None:
            # Default to package rules directory
            rules_dir = Path(__file__).parent

        self.rules_dir = Path(rules_dir)
        self.rules: list[Rule] = []
        self.rules_by_id: dict[str, Rule] = {}
        self.rules_by_type: dict[str, list[Rule]] = {}

    def load_all(self):
        """Load all YAML rule files from the rules directory."""
        if not self.rules_dir.exists():
            raise ValueError(f"Rules directory not found: {self.rules_dir}")

        # Find all YAML files
        yaml_files = list(self.rules_dir.glob('*.yaml')) + list(self.rules_dir.glob('*.yml'))

        for yaml_file in yaml_files:
            # Skip __init__ and non-rule files
            if yaml_file.stem.startswith('_'):
                continue

            self.load_file(yaml_file)

    def load_file(self, file_path: Path):
        """
        Load rules from a single YAML file.

        Args:
            file_path: Path to YAML file
        """
        try:
            with open(file_path, 'r') as f:
                data = yaml.safe_load(f)

            if not data or 'rules' not in data:
                return

            for rule_dict in data['rules']:
                try:
                    rule = Rule(rule_dict)
                    self.add_rule(rule)
                except Exception as e:
                    print(f"Warning: Failed to load rule {rule_dict.get('id', 'unknown')}: {e}")

        except Exception as e:
            print(f"Warning: Failed to load rules file {file_path}: {e}")

    def add_rule(self, rule: Rule):
        """
        Add a rule to the loader.

        Args:
            rule: Rule to add
        """
        self.rules.append(rule)
        self.rules_by_id[rule.id] = rule

        if rule.type not in self.rules_by_type:
            self.rules_by_type[rule.type] = []
        self.rules_by_type[rule.type].append(rule)

    def get_rule(self, rule_id: str) -> Optional[Rule]:
        """
        Get rule by ID.

        Args:
            rule_id: Rule identifier

        Returns:
            Rule or None if not found
        """
        return self.rules_by_id.get(rule_id)

    def get_rules_by_type(self, rule_type: str) -> list[Rule]:
        """
        Get all rules of a specific type.

        Args:
            rule_type: Rule type

        Returns:
            List of rules
        """
        return self.rules_by_type.get(rule_type, [])

    def match_all(self, content: str) -> list[dict]:
        """
        Match all rules against content.

        Args:
            content: Content to match

        Returns:
            List of all matches
        """
        matches = []

        for rule in self.rules:
            matches.extend(rule.match(content))

        return matches

    def __len__(self):
        return len(self.rules)

    def __repr__(self):
        return f"RuleLoader(rules={len(self.rules)})"
