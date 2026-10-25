import joblib

rf = joblib.load("models/random_forest.joblib")
xgb = joblib.load("models/xgboost.joblib")
v = joblib.load("models/tfidf_vectorizer.joblib")

tails = [
    "OR '1'='1'",
    "' OR '1'='1'",
    "admin' OR '1'='1'",
    "admin' OR 1=1 --",
    "' or 1=1",
    "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'",
]

for s in tails:
    X = v.transform([s])
    rf_p = rf.predict_proba(X)[0]
    xgb_p = xgb.predict_proba(X)[0]
    print(f"{repr(s):<75} RF_SQLi: {rf_p[1]:.4f}  XGB_SQLi: {xgb_p[1]:.4f}")
