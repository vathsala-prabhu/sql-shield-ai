MAX_LEN = 5000


def validate_query(value):
    """Returns (clean_text, error). error is None when the input is valid."""
    if not isinstance(value, str):
        return None, "Query must be a string."
    text = value.strip()
    if not text:
        return None, "Query cannot be empty."
    if len(text) > MAX_LEN:
        return None, f"Query must be at most {MAX_LEN} characters."
    if "\x00" in text:
        return None, "Query contains invalid characters."
    return text, None