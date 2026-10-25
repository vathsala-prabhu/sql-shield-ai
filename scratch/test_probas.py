import joblib
import pandas as pd

v = joblib.load("models/tfidf_vectorizer.joblib")
rf = joblib.load("models/random_forest.joblib")
xgb = joblib.load("models/xgboost.joblib")

queries = [
    "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'",
    "SELECT * FROM users WHERE id = 1 OR 1=1 --",
    "' OR '1'='1'",
    "' or 1=1",
    "admin' OR 1=1 --",
    "SELECT * FROM users WHERE username = 'admin' AND password = ''",
    "SELECT * FROM users WHERE id = 5",
]

for q in queries:
    X = v.transform([q])
    rf_p = rf.predict_proba(X)[0]
    xgb_p = xgb.predict_proba(X)[0]
    print(f"Query: {q}")
    print(f"  RF  -> Legitimate(0): {rf_p[0]:.4f}, SQLi(1): {rf_p[1]:.4f}")
    print(f"  XGB -> Legitimate(0): {xgb_p[0]:.4f}, SQLi(1): {xgb_p[1]:.4f}")
