"""Shared code analysis utilities for deep security scanners."""


def find_line_number(content: str, position: int) -> int:
    """Find the line number for a character position in content.

    Args:
        content: The full text content.
        position: The character offset (0-based) to look up.

    Returns:
        The 1-based line number corresponding to the position.
    """
    return content[:position].count("\n") + 1
