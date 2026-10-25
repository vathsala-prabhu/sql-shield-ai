import joblib
import re

rf = joblib.load("models/random_forest.joblib")
v = joblib.load("models/tfidf_vectorizer.joblib")

q = "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'"

# Segments to test
segments = [
    q,
    "WHERE username = 'admin' AND password = '' OR '1'='1'",
    "username = 'admin' AND password = '' OR '1'='1'",
    "password = '' OR '1'='1'",
    "OR '1'='1'",
    "'1'='1'",
]

print("ML Random Forest probabilities on query segments:")
for s in segments:
    X = v.transform([s])
    p = rf.predict_proba(X)[0]
    print(f"  {repr(s):<55} -> SQLi prob: {p[1]:.4f} (Legit: {p[0]:.4f})")
