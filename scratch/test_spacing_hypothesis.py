import joblib

rf = joblib.load("models/random_forest.joblib")
v = joblib.load("models/tfidf_vectorizer.joblib")

q_user = "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'"
q_spaced = "SELECT * FROM users WHERE username  =  'admin' AND password  =  '' OR '1'  =  '1'"
q_spaced2 = "select * from users where username  =  'admin' and password  =  '' or '1'  =  '1'"

for q in [q_user, q_spaced, q_spaced2]:
    X = v.transform([q])
    p = rf.predict_proba(X)[0]
    print(f"{repr(q):<85} -> Legit: {p[0]:.4f}, SQLi: {p[1]:.4f}")
