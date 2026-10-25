import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

train = pd.read_csv("data/train.csv")
val = pd.read_csv("data/val.csv")

q = "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'"

# Test 1: Baseline (current)
v1 = TfidfVectorizer(analyzer="char", ngram_range=(2, 5), max_features=20000)
X1 = v1.fit_transform(train["Query"].astype(str))
rf1 = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rf1.fit(X1, train["y"])
p1 = rf1.predict_proba(v1.transform([q]))[0]
print("Baseline (char 2-5):", p1)

# Test 2: Char 1-5 or sublinear_tf
v2 = TfidfVectorizer(analyzer="char", ngram_range=(1, 5), max_features=20000, sublinear_tf=True)
X2 = v2.fit_transform(train["Query"].astype(str))
rf2 = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rf2.fit(X2, train["y"])
p2 = rf2.predict_proba(v2.transform([q]))[0]
print("Char 1-5 sublinear:", p2)
