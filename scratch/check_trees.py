import joblib
import numpy as np

rf = joblib.load("models/random_forest.joblib")
v = joblib.load("models/tfidf_vectorizer.joblib")
q = "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'"
X = v.transform([q])
votes = [int(tree.predict(X)[0]) for tree in rf.estimators_]
print("Tree votes count:")
print("Votes for 0 (Legit):", votes.count(0))
print("Votes for 1 (SQLi):", votes.count(1))

# What features do the trees split on?
tree = rf.estimators_[0]
print("Tree 0 feature indices used:", tree.tree_.feature[:10])
