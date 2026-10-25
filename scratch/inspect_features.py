import joblib
import pandas as pd
import numpy as np

v = joblib.load("models/tfidf_vectorizer.joblib")
rf = joblib.load("models/random_forest.joblib")
train = pd.read_csv("data/train.csv")

q = "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'"
X = v.transform([q])
feat_names = np.array(v.get_feature_names_out())
indices = X.indices
weights = X.data

sorted_order = np.argsort(weights)[::-1]
print("Top 25 features in query by TF-IDF weight:")
for idx in sorted_order[:25]:
    feat = feat_names[indices[idx]]
    w = weights[idx]
    in_legit = train[train["y"] == 0]["Query"].str.lower().str.contains(feat, regex=False).sum()
    in_sqli = train[train["y"] == 1]["Query"].str.lower().str.contains(feat, regex=False).sum()
    print(f"{repr(feat):<22} weight={w:.4f} legit_count={in_legit:<5} sqli_count={in_sqli:<5}")
