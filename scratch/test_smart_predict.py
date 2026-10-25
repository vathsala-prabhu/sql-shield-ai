import joblib
import re

v = joblib.load("models/tfidf_vectorizer.joblib")
rf = joblib.load("models/random_forest.joblib")
xgb = joblib.load("models/xgboost.joblib")

# Precise pattern for tautologies where LHS == RHS, or union, or stacked commands, or comments
ATTACK_FRAGMENTS = [
    re.compile(r"\b(?:or|and)\b\s+(['\"]?)([\w]+)\1\s*=\s*\1\2\1.*", re.IGNORECASE),
    re.compile(r"\bunion\s+(?:all\s+)?select\b.*", re.IGNORECASE),
    re.compile(r";\s*(?:drop|select|insert|update|delete|exec)\b.*", re.IGNORECASE),
    re.compile(r"--.*|/\*.*?\*/|#.*", re.IGNORECASE),
    re.compile(r"\b(?:sleep|waitfor\s+delay|pg_sleep|benchmark)\s*\(.*", re.IGNORECASE),
]

def extract_suspicious_segments(text):
    """
    Extracts potential injection fragments from within a compound query.
    This defends against Benign Prefix Camouflage where a 70-character legitimate query
    dilutes a 10-character injection payload.
    """
    segments = [text]
    for pat in ATTACK_FRAGMENTS:
        for match in pat.finditer(text):
            frag = match.group(0).strip()
            if frag and frag not in segments:
                segments.append(frag)
    return segments

def evaluate_smart_predict(text):
    segments = extract_suspicious_segments(text)
    X = v.transform(segments)
    
    rf_probs = rf.predict_proba(X)[:, 1]
    xgb_probs = xgb.predict_proba(X)[:, 1]
    
    max_rf = float(max(rf_probs))
    max_xgb = float(max(xgb_probs))
    
    full_rf = float(rf_probs[0])
    
    return {
        "text": text,
        "segments": segments,
        "full_rf_score": round(full_rf, 4),
        "composite_rf_score": round(max_rf, 4),
        "composite_xgb_score": round(max_xgb, 4),
        "rf_label": "SQLi" if max_rf >= 0.5 else "Legitimate",
    }

test_suite = [
    # Attacks
    ("SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'", "SQLi"),
    ("SELECT * FROM users WHERE id = 1 OR 1=1 --", "SQLi"),
    ("' UNION SELECT username, password FROM users --", "SQLi"),
    ("admin' OR 1=1 --", "SQLi"),
    ("1; WAITFOR DELAY '0:0:5'--", "SQLi"),
    ("' or 'a'='a", "SQLi"),
    # Legitimate queries
    ("SELECT id, name FROM products WHERE category = 'books' AND in_stock = 1 ORDER BY price ASC", "Legitimate"),
    ("SELECT id, username, email FROM users WHERE status = 'active' AND verified = 1", "Legitimate"),
    ("SELECT * FROM customers WHERE country = 'Germany' OR country = 'Spain'", "Legitimate"),
    ("SELECT name FROM users WHERE id = 5", "Legitimate"),
    ("SELECT * FROM orders WHERE user_id = 42 AND total > 100", "Legitimate"),
]

print("=== Smart Prediction Benchmark ===")
for q, expected in test_suite:
    res = evaluate_smart_predict(q)
    print(f"\nQuery: {q}")
    print(f"  Segments evaluated: {res['segments']}")
    print(f"  Full RF score: {res['full_rf_score']} | Composite RF: {res['composite_rf_score']} | Pred: {res['rf_label']} | Expected: {expected}")
    passed = res['rf_label'] == expected
    print(f"  Status: {'PASSED' if passed else 'FAILED'}")
