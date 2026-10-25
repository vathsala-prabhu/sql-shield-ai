import joblib

rf = joblib.load("models/random_forest.joblib")
v = joblib.load("models/tfidf_vectorizer.joblib")

queries = [
    "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'",
    "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1' --",
    "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'#",
    "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'/*",
    "SELECT * FROM users WHERE username = 'admin' AND password = '' OR 1=1",
    "SELECT * FROM users WHERE username = 'admin' AND password = '' OR 1=1 --",
    "SELECT * FROM users WHERE id = 1 OR 1=1",
    "SELECT * FROM users WHERE id = 1 OR 1=1 --",
]

for q in queries:
    X = v.transform([q])
    p = rf.predict_proba(X)[0]
    print(f"{repr(q):<75} -> Legit: {p[0]:.2f}, SQLi: {p[1]:.2f}")
