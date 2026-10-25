import joblib
import re

rf = joblib.load("models/random_forest.joblib")
v = joblib.load("models/tfidf_vectorizer.joblib")

legit_queries = [
    "SELECT id, name FROM products WHERE category = 'books' AND in_stock = 1 ORDER BY price ASC",
    "SELECT id, username, email FROM users WHERE status = 'active' AND verified = 1",
    "SELECT * FROM customers WHERE country = 'Germany' AND city = 'Berlin'",
    "SELECT name FROM users WHERE id = 5",
]

def get_segments(text):
    segs = [text]
    # Split on WHERE clause if present
    parts = re.split(r"\bwhere\b", text, flags=re.IGNORECASE)
    if len(parts) > 1:
        where_clause = "WHERE" + parts[1]
        segs.append(where_clause.strip())
        # Also split conditions on AND / OR
        conditions = re.split(r"\b(?:and|or)\b", parts[1], flags=re.IGNORECASE)
        for c in conditions:
            if c.strip():
                segs.append(c.strip())
    return segs

print("Testing clause segmentation on Legitimate queries:")
for q in legit_queries:
    segs = get_segments(q)
    X = v.transform(segs)
    probs = rf.predict_proba(X)[:, 1]
    max_prob = max(probs)
    print(f"\nQuery: {q}")
    for s, p in zip(segs, probs):
        print(f"  Segment: {repr(s):<60} -> SQLi prob: {p:.4f}")
    print(f"  >> MAX SQLi probability: {max_prob:.4f}")
