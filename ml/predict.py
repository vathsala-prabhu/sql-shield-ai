import sys
from pathlib import Path
import joblib

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import config

MODELS_DIR = config.MODELS_DIR

# Global cache for vectorizer and models to avoid disk I/O on every request
_CACHE = {
    "vectorizer": None,
    "selected_model": None,
    "random_forest": None,
    "xgboost": None,
}


def _get_vectorizer():
    if _CACHE["vectorizer"] is None:
        _CACHE["vectorizer"] = joblib.load(MODELS_DIR / "tfidf_vectorizer.joblib")
    return _CACHE["vectorizer"]


def _get_model(model_name="selected_model"):
    if model_name not in _CACHE or _CACHE[model_name] is None:
        filename = f"{model_name}.joblib"
        path = MODELS_DIR / filename
        if not path.exists():
            path = MODELS_DIR / "selected_model.joblib"
        _CACHE[model_name] = joblib.load(path)
    return _CACHE[model_name]


def predict_query(text, threshold=None, model_name=None, compare_both=True):
    """
    Transforms text using character n-gram TF-IDF and classifies it using the trained model.
    
    Args:
        text (str): SQL query or input string to inspect.
        threshold (float, optional): Custom decision threshold (0.0 - 1.0). Defaults to config.DEFAULT_THRESHOLD.
        model_name (str, optional): 'selected_model', 'random_forest', or 'xgboost'.
        compare_both (bool): If True, also computes score with the alternative model for comparison.
        
    Returns:
        dict: Classification results with score, label, model used, and optional comparison scores.
    """
    if threshold is None:
        threshold = config.DEFAULT_THRESHOLD
    if model_name is None:
        model_name = config.ACTIVE_MODEL

    vectorizer = _get_vectorizer()
    X = vectorizer.transform([str(text)])

    active_model = _get_model(model_name)
    score = float(active_model.predict_proba(X)[0][1])
    label = "SQLi" if score >= threshold else "Legitimate"

    result = {
        "label": label,
        "score": round(score, 4),
        "threshold": threshold,
        "model_used": model_name,
    }

    if compare_both:
        try:
            rf_model = _get_model("random_forest")
            xgb_model = _get_model("xgboost")
            rf_score = float(rf_model.predict_proba(X)[0][1])
            xgb_score = float(xgb_model.predict_proba(X)[0][1])
            result["comparisons"] = {
                "random_forest": {
                    "score": round(rf_score, 4),
                    "label": "SQLi" if rf_score >= threshold else "Legitimate",
                },
                "xgboost": {
                    "score": round(xgb_score, 4),
                    "label": "SQLi" if xgb_score >= threshold else "Legitimate",
                },
            }
        except Exception:
            pass

    return result


if __name__ == "__main__":
    samples = [
        "SELECT name FROM users WHERE id = 5",
        "SELECT * FROM users WHERE id = 1 OR 1=1 --",
        "' UNION SELECT username, password FROM users --",
    ]
    for s in samples:
        print(s, "->", predict_query(s))