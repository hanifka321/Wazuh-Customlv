import re
from typing import Callable, Dict, Any
from .extractor import DottedPathExtractor


class WhereExpressionParser:
    """
    Parses and compiles 'where' expressions into callable predicates.

    Supported operators:
    - == : equality (rule.id == "60122")
    - != : inequality (status != "success")
    - in : list membership (rule.id in ["5710", "5715"])
    - contains(field, "text") : substring search
    - regex(field, "pattern") : regex matching (optional)
    """

    def __init__(self):
        self.extractor = DottedPathExtractor()

    def parse(self, expression: str) -> Callable[[Dict[str, Any]], bool]:
        """
        Parse a where expression and return a callable predicate function.

        Args:
            expression: Where expression string (e.g., 'rule.id == "60122"')

        Returns:
            A callable that takes an event dict and returns bool

        Raises:
            ValueError: If expression syntax is invalid
        """
        expression = expression.strip()

        if not expression:
            raise ValueError("Empty where expression")

        if "contains(" in expression:
            return self._parse_contains(expression)
        elif "regex(" in expression:
            return self._parse_regex(expression)
        elif re.search(r"\s+in\s*\[", expression):
            return self._parse_in(expression)
        elif "!=" in expression:
            return self._parse_comparison(expression, "!=")
        elif "==" in expression:
            return self._parse_comparison(expression, "==")
        else:
            raise ValueError(f"Unsupported expression syntax: {expression}")

    def _parse_comparison(self, expression: str, operator: str) -> Callable[[Dict[str, Any]], bool]:
        """Parse == or != comparison."""
        parts = expression.split(operator, 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid {operator} expression: {expression}")

        field_path = parts[0].strip()
        value_str = parts[1].strip()

        if not value_str:
            raise ValueError(f"Invalid {operator} expression: {expression}")

        expected_value = self._parse_value(value_str)

        if operator == "==":

            def predicate(event: Dict[str, Any]) -> bool:
                actual = self.extractor.extract(event, field_path)
                return bool(actual == expected_value)

        else:

            def predicate(event: Dict[str, Any]) -> bool:
                actual = self.extractor.extract(event, field_path)
                return bool(actual != expected_value)

        return predicate

    def _parse_in(self, expression: str) -> Callable[[Dict[str, Any]], bool]:
        """Parse 'in' list membership."""
        match = re.match(r"(.+?)\s+in\s*\[(.+?)\]", expression.strip())
        if not match:
            raise ValueError(f"Invalid 'in' expression: {expression}")

        field_path = match.group(1).strip()
        values_str = match.group(2).strip()

        values = []
        for val_str in values_str.split(","):
            val_str = val_str.strip()
            if val_str:
                values.append(self._parse_value(val_str))

        def predicate(event: Dict[str, Any]) -> bool:
            actual = self.extractor.extract(event, field_path)
            return actual in values

        return predicate

    def _parse_contains(self, expression: str) -> Callable[[Dict[str, Any]], bool]:
        """Parse contains(field, "text") function."""
        match = re.match(r"contains\s*\(\s*(.+?)\s*,\s*(.+?)\s*\)", expression.strip())
        if not match:
            raise ValueError(f"Invalid contains expression: {expression}")

        field_path = match.group(1).strip()
        search_str = self._parse_value(match.group(2).strip())

        if not isinstance(search_str, str):
            raise ValueError(f"Contains search value must be a string: {search_str}")

        def predicate(event: Dict[str, Any]) -> bool:
            actual = self.extractor.extract(event, field_path)
            if actual is None:
                return False
            return search_str in str(actual)

        return predicate

    def _parse_regex(self, expression: str) -> Callable[[Dict[str, Any]], bool]:
        """Parse regex(field, "pattern") function."""
        match = re.match(r"regex\s*\(\s*(.+?)\s*,\s*(.+?)\s*\)", expression.strip())
        if not match:
            raise ValueError(f"Invalid regex expression: {expression}")

        field_path = match.group(1).strip()
        pattern_str = self._parse_value(match.group(2).strip())

        if not isinstance(pattern_str, str):
            raise ValueError(f"Regex pattern must be a string: {pattern_str}")

        try:
            compiled_pattern = re.compile(pattern_str)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern '{pattern_str}': {e}")

        def predicate(event: Dict[str, Any]) -> bool:
            actual = self.extractor.extract(event, field_path)
            if actual is None:
                return False
            return compiled_pattern.search(str(actual)) is not None

        return predicate

    def _parse_value(self, value_str: str) -> Any:
        """
        Parse a string value literal into its Python type.

        Handles:
        - Quoted strings: "text" or 'text'
        - Numbers: 123, 45.67
        - Booleans: true, false
        - None: null, none
        """
        value_str = value_str.strip()

        if (value_str.startswith('"') and value_str.endswith('"')) or (
            value_str.startswith("'") and value_str.endswith("'")
        ):
            return value_str[1:-1]

        if value_str.lower() in ("true", "false"):
            return value_str.lower() == "true"

        if value_str.lower() in ("null", "none"):
            return None

        try:
            if "." in value_str:
                return float(value_str)
            return int(value_str)
        except ValueError:
            return value_str
