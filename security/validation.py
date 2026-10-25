import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import config

MAX_LEN = config.MAX_QUERY_LEN


def validate_query(value):
    """
    Validates input query string for length, type, and forbidden control characters.
    
    Returns:
        tuple: (clean_text, error_message)
    """
    if value is None:
        return None, "Query input is required."

    if not isinstance(value, str):
        return None, "Query must be a text string."

    text = value.strip()
    if not text:
        return None, "Query cannot be empty or whitespace only."

    if len(text) > MAX_LEN:
        return None, f"Query length ({len(text)} chars) exceeds maximum allowed limit ({MAX_LEN} chars)."

    if "\x00" in text:
        return None, "Null bytes (\\x00) are prohibited."

    # Check for excessive unprintable control characters
    unprintable = sum(1 for c in text if ord(c) < 32 and c not in ("\n", "\r", "\t"))
    if unprintable > 5:
        return None, "Input contains excessive control characters."

    return text, None