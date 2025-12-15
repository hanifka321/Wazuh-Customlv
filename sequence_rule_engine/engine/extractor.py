from typing import Any, Dict


class DottedPathExtractor:
    """
    Extracts values from nested dictionaries using dotted path notation.
    """

    def extract(self, event: Dict[str, Any], path: str, default: Any = None) -> Any:
        """
        Extract a value from a nested dictionary using dotted path notation.

        Examples:
            extract({"agent": {"id": "037"}}, "agent.id") → "037"
            extract({"rule": {"id": "5710"}}, "rule.id") → "5710"
            extract({"data": {"win": {"eventdata": {"status": "0x0"}}}},
                   "data.win.eventdata.status") → "0x0"
            extract({}, "missing.path") → None
            extract({"a": "b"}, "missing.path", "default") → "default"

        Args:
            event: Dictionary to extract from
            path: Dot-separated path to the field
            default: Value to return if path doesn't exist

        Returns:
            The extracted value if found, otherwise the default value
        """
        if not path:
            return default

        if not isinstance(event, dict):
            return default

        keys = path.split(".")
        value = event

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default

        return value

    def extract_multiple(
        self, event: Dict[str, Any], paths: list[str], default: Any = None
    ) -> Dict[str, Any]:
        """
        Extract multiple paths at once.

        Args:
            event: Dictionary to extract from
            paths: List of dot-separated paths
            default: Value to return for missing paths

        Returns:
            Dictionary mapping paths to their extracted values
        """
        return {path: self.extract(event, path, default) for path in paths}
