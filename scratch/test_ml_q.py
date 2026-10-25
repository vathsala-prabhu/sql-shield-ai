import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

train = pd.read_csv("data/train.csv")
val = pd.read_csv("data/val.csv")
test = pd.read_csv("data/test.csv")

q = "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'"

print("Train shape:", train.shape)
print("Val shape:", val.shape)
print("Test shape:", test.shape)

# Let's check existing vectorizer
v_old = joblib.load("models/tfidf_vectorizer.joblib")
rf_old = joblib.load("models/random_forest.joblib")

X_q = v_old.transform([q])
print("Existing RF proba for q:", rf_old.predict_proba(X_q))
