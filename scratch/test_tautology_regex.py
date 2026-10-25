import re

# Old regex from gateway.py
old_p = r"\b(or|and)\b\s+(['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?|\d+\s*=\s*\d+)"

# Precise tautology regex where LHS == RHS (e.g. '1'='1', 1=1, 'a'='a', etc.)
# Group 2 is LHS, Group 3 is RHS
tautology_pattern = re.compile(
    r"\b(or|and)\b\s+(['\"]?)([\w]+)\2\s*=\s*\2\3\2",
    re.IGNORECASE
)

samples = [
    "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'",
    "SELECT * FROM users WHERE id = 1 OR 1=1 --",
    "SELECT * FROM users WHERE username = 'admin' OR 'a'='a'",
    "SELECT * FROM products WHERE category = 'books' OR category = 'electronics'",
    "SELECT * FROM orders WHERE status = 'pending' AND total = 100",
]

print("=== Old Regex ===")
for s in samples:
    m = re.search(old_p, s, re.IGNORECASE)
    print(f"{repr(s):<80} -> Matched: {bool(m)}")

print("\n=== Precise Tautology Regex (LHS == RHS) ===")
for s in samples:
    m = tautology_pattern.search(s)
    matched_text = m.group(0) if m else None
    print(f"{repr(s):<80} -> Tautology: {matched_text}")
