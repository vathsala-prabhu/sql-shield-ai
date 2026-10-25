import joblib
import pandas as pd
from pathlib import Path

v = joblib.load("models/tfidf_vectorizer.joblib")
rf = joblib.load("models/random_forest.joblib")
xgb = joblib.load("models/xgboost.joblib")

q = "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'"
print("Raw query:", q)

X = v.transform([str(q)])
print("Non-zero features in X:", X.nnz)

print("RF classes_:", getattr(rf, "classes_", None))
print("RF predict_proba:", rf.predict_proba(X))
print("XGB classes_:", getattr(xgb, "classes_", None))
print("XGB predict_proba:", xgb.predict_proba(X))

# Also check predict_query from ml/predict.py
from ml.predict import predict_query
print("predict_query output:", predict_query(q))
