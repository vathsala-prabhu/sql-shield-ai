from pathlib import Path
import joblib

MODELS = Path(__file__).resolve().parent.parent / "models"
_vectorizer = joblib.load(MODELS / "tfidf_vectorizer.joblib")
_model = joblib.load(MODELS / "selected_model.joblib")

THRESHOLD = 0.5  # score at or above this is treated as SQL injection


def predict_query(text):
    X = _vectorizer.transform([str(text)])
    score = float(_model.predict_proba(X)[0][1])
    label = "SQLi" if score >= THRESHOLD else "Legitimate"
    return {"label": label, "score": round(score, 4)}


if __name__ == "__main__":
    samples = [
        "SELECT name FROM users WHERE id = 5",
        "SELECT * FROM users WHERE id = 1 OR 1=1 --",
        "' UNION SELECT username, password FROM users --",
    ]
    for s in samples:
        print(s, "->", predict_query(s))