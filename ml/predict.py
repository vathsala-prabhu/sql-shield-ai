import re
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

# Regex patterns to isolate potential injection fragments within compound queries.
# This defends against Benign Prefix Camouflage (where a 60+ char standard query dilutes
# the TF-IDF feature weights of a 10-char injection payload like OR '1'='1').
INJECTION_SEGMENT_PATTERNS = [
    re.compile(r"\b(?:or|and)\b\s+(['\"]?)([\w]+)\1\s*=\s*\1\2\1.*", re.IGNORECASE),
    re.compile(r"\bunion\s+(?:all\s+)?select\b.*", re.IGNORECASE),
    re.compile(r";\s*(?:drop|select|insert|update|delete|exec|alter)\b.*", re.IGNORECASE),
    re.compile(r"\b(?:sleep|waitfor\s+delay|pg_sleep|benchmark)\s*\(.*", re.IGNORECASE),
    re.compile(r"--.*|/\*.*?\*/|#.*", re.IGNORECASE),
]


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


def extract_segments(text):
    """
    Extracts the full query and any candidate injection payload fragments.
    Allows the fitted vectorizer and model to inspect both global context
    and localized payload structures without dilution.
    """
    segments = [str(text)]
    for pat in INJECTION_SEGMENT_PATTERNS:
        for match in pat.finditer(text):
            frag = match.group(0).strip()
            if frag and frag not in segments:
                segments.append(frag)
    return segments


def predict_query(text, threshold=None, model_name=None, compare_both=True):
    """
    Transforms text using the fitted character n-gram TF-IDF vectorizer and classifies
    it using the trained model. Evaluates full query and suspicious sub-clauses to prevent
    benign prefix camouflage from masking injection vectors.
    
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
    segments = extract_segments(text)
    X = vectorizer.transform(segments)

    active_model = _get_model(model_name)
    # predict_proba returns [prob_legitimate (class 0), prob_sqli (class 1)]
    probs = active_model.predict_proba(X)
    sqli_probs = probs[:, 1]

    # Overall score is the maximum malicious probability across full query and payload segments
    max_score = float(max(sqli_probs))
    full_score = float(sqli_probs[0])
    label = "SQLi" if max_score >= threshold else "Legitimate"

    result = {
        "label": label,
        "score": round(max_score, 4),
        "full_query_score": round(full_score, 4),
        "threshold": threshold,
        "model_used": model_name,
        "segments_evaluated": len(segments),
    }

    if compare_both:
        try:
            rf_model = _get_model("random_forest")
            xgb_model = _get_model("xgboost")
            rf_probs = rf_model.predict_proba(X)[:, 1]
            xgb_probs = xgb_model.predict_proba(X)[:, 1]
            rf_max = float(max(rf_probs))
            xgb_max = float(max(xgb_probs))

            result["comparisons"] = {
                "random_forest": {
                    "score": round(rf_max, 4),
                    "label": "SQLi" if rf_max >= threshold else "Legitimate",
                },
                "xgboost": {
                    "score": round(xgb_max, 4),
                    "label": "SQLi" if xgb_max >= threshold else "Legitimate",
                },
            }
        except Exception:
            pass

    return result


if __name__ == "__main__":
    samples = [
        "SELECT name FROM users WHERE id = 5",
        "SELECT * FROM users WHERE id = 1 OR 1=1 --",
        "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'",
        "' UNION SELECT username, password FROM users --",
    ]
    for s in samples:
        print(s, "->", predict_query(s))