import json
from typing import List, Dict, Any


def parse_jsonl(jsonl_string: str) -> List[Dict[str, Any]]:
    """
    Parse a JSONL (JSON Lines) formatted string into a list of dictionaries.

    Handles:
    - Comment lines (lines starting with #)
    - Empty lines (whitespace-only)
    - Malformed JSON with descriptive errors

    Args:
        jsonl_string: A string containing newline-delimited JSON objects

    Returns:
        List of parsed event dictionaries

    Raises:
        ValueError: If a non-comment, non-empty line contains invalid JSON
    """
    events = []
    lines = jsonl_string.strip().split("\n") if jsonl_string.strip() else []

    for line_num, line in enumerate(lines, start=1):
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        try:
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError(
                    f"Line {line_num}: Expected JSON object, got {type(event).__name__}"
                )
            events.append(event)
        except json.JSONDecodeError as e:
            raise ValueError(f"Line {line_num}: Invalid JSON - {str(e)}")

    return events
