from typing import Callable, Dict, Any, List
from .where_parser import WhereExpressionParser


class CompiledStep:
    """
    A compiled sequence step with pre-compiled where expression.

    Contains the step metadata and a compiled predicate function
    for fast evaluation during sequence matching.
    """

    def __init__(self, step: Dict[str, Any], where_func: Callable[[Dict[str, Any]], bool]):
        """
        Initialize a compiled step.

        Args:
            step: The step dictionary containing 'as' and 'where' fields
            where_func: Compiled predicate function for the where condition
        """
        self.as_alias = step.get("as", "")
        self.where_expr = step.get("where", "")
        self.where_func = where_func
        self.step_index = 0  # Will be set by the compiler

    def matches(self, event: Dict[str, Any]) -> bool:
        """
        Check if an event matches this step's where condition.

        Args:
            event: Event dictionary to test

        Returns:
            True if the event matches the where condition
        """
        try:
            return self.where_func(event)
        except Exception:
            # If there's an error evaluating the predicate,
            # we consider it a non-match to be safe
            return False

    def __repr__(self) -> str:
        return f"CompiledStep(as='{self.as_alias}', where='{self.where_expr}')"


class CompiledRule:
    """
    A compiled rule with pre-compiled where expressions.

    Contains the rule metadata and list of compiled sequence steps
    for fast evaluation during sequence matching.
    """

    def __init__(self, rule: Dict[str, Any], steps: List[CompiledStep]):
        """
        Initialize a compiled rule.

        Args:
            rule: The rule dictionary with id, name, by, within_seconds, sequence, output
            steps: List of compiled sequence steps
        """
        self.rule_id = rule.get("id", "")
        self.rule_name = rule.get("name", "")
        self.by_fields = rule.get("by", [])
        self.within_seconds = rule.get("within_seconds", 300)  # Default 5 minutes
        self.output = rule.get("output", {})
        self.steps = steps

        # Set step indices for easy access
        for i, step in enumerate(self.steps):
            step.step_index = i

    def get_step_count(self) -> int:
        """Get the number of steps in this sequence."""
        return len(self.steps)

    def get_by_fields(self) -> List[str]:
        """Get the list of fields used for correlation."""
        return self.by_fields

    def __repr__(self) -> str:
        return (
            f"CompiledRule(id='{self.rule_id}', "
            f"name='{self.rule_name}', "
            f"steps={len(self.steps)}, "
            f"by={self.by_fields})"
        )


class RuleCompiler:
    """
    Compiles rule where expressions into callable predicates for performance.

    Pre-compiles all where expressions in sequence steps so that
    during runtime evaluation, we just call the predicates instead
    of parsing expressions each time.
    """

    def __init__(self):
        """Initialize the rule compiler."""
        self.where_parser = WhereExpressionParser()

    def compile_rule(self, rule: Dict[str, Any]) -> CompiledRule:
        """
        Compile a rule by pre-compiling all where expressions.

        Args:
            rule: Rule dictionary with sequence steps containing where expressions

        Returns:
            CompiledRule with pre-compiled where predicates

        Raises:
            ValueError: If rule has invalid syntax or missing required fields
        """
        # Validate rule structure
        if not isinstance(rule, dict):
            raise ValueError("Rule must be a dictionary")

        if "sequence" not in rule:
            raise ValueError("Rule must have a 'sequence' field")

        sequence = rule.get("sequence", [])
        if not isinstance(sequence, list) or not sequence:
            raise ValueError("Rule sequence must be a non-empty list")

        # Compile each step in the sequence
        compiled_steps = []
        for step in sequence:
            if not isinstance(step, dict):
                raise ValueError("Each step in sequence must be a dictionary")

            if "as" not in step:
                raise ValueError("Each step must have an 'as' field")

            if "where" not in step:
                raise ValueError("Each step must have a 'where' field")

            # Parse and compile the where expression
            where_expr = step["where"]
            try:
                where_func = self.where_parser.parse(where_expr)
            except Exception as e:
                raise ValueError(f"Invalid where expression '{where_expr}': {e}")

            compiled_step = CompiledStep(step, where_func)
            compiled_steps.append(compiled_step)

        # Create and return the compiled rule
        return CompiledRule(rule, compiled_steps)

    def compile_multiple_rules(self, rules: List[Dict[str, Any]]) -> List[CompiledRule]:
        """
        Compile multiple rules at once.

        Args:
            rules: List of rule dictionaries

        Returns:
            List of CompiledRule objects

        Raises:
            ValueError: If any rule fails to compile
        """
        compiled_rules = []
        for rule in rules:
            try:
                compiled_rule = self.compile_rule(rule)
                compiled_rules.append(compiled_rule)
            except Exception as e:
                raise ValueError(f"Failed to compile rule '{rule.get('id', 'unknown')}': {e}")

        return compiled_rules


def compile_rule(rule: Dict[str, Any]) -> CompiledRule:
    """
    Convenience function to compile a single rule.

    Args:
        rule: Rule dictionary to compile

    Returns:
        CompiledRule object
    """
    compiler = RuleCompiler()
    return compiler.compile_rule(rule)


def compile_rules(rules: List[Dict[str, Any]]) -> List[CompiledRule]:
    """
    Convenience function to compile multiple rules.

    Args:
        rules: List of rule dictionaries to compile

    Returns:
        List of CompiledRule objects
    """
    compiler = RuleCompiler()
    return compiler.compile_multiple_rules(rules)
