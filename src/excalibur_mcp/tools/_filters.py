"""Shared validation for the list tools' content/date filters.

Tool input is adversarial: a search term reaches Postgres' ``~*`` regex operator,
so it must be a valid regex (Python and Postgres regex dialects differ, but a
``re.compile`` catches the common malformed patterns early and cheaply) and
length-bounded as a guard against pathological patterns. Bad input raises
``ValueError``, which the standard tool error wrapper turns into a refunded
``tool_input_invalid``.
"""

from __future__ import annotations

import re

_SEARCH_MAX = 200


def validate_search(search: str | None) -> str | None:
    """Return a usable regex search term, or ``None`` when empty. Raise on a
    too-long or un-compilable pattern."""
    s = (search or "").strip()
    if not s:
        return None
    if len(s) > _SEARCH_MAX:
        raise ValueError(f"search exceeds {_SEARCH_MAX} characters")
    try:
        re.compile(s)
    except re.error:
        raise ValueError("search must be a valid regular expression")
    return s
