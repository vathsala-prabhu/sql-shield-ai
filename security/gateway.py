import json
import os
import re
from pathlib import Path

from ml.predict import predict_query
from database.db import add_incident
from security.validation import validate_query

# Decision threshold (can be changed with the SHIELD_THRESHOLD environment variable)
THRESHOLD = float(os.environ.get("SHIELD_THRESHOLD", 0.5))

_metrics = Path(__file__).resolve().parent.parent / "models" / "metrics.json"
MODEL_NAME = json.loads(_metrics.read_text())["selected_model"]

# Simple patterns that help a human reviewer. They do NOT explain the model's decision.
PATTERNS = {
    "SQL comment marker": r"--|#|/\*",
    "UNION SELECT": r"union\s+(all\s+)?select",
    "OR with equality (possible tautology)": r"\bor\b\s+\S+\s*=\s*\S+",
    "Stacked statement (;)": r";\s*\w",
    "Time-delay function": r"sleep\s*\(|waitfor\s+delay|pg_sleep|benchmark\s*\(",
}

MITIGATION = (
    "Use parameterized queries (prepared statements), validate input, "
    "and give the database account only the permissions it needs."
)


def find_patterns(text):
    lowered = text.lower()
    return [name for name, p in PATTERNS.items() if re.search(p, lowered)]


def process_request(raw_input):
    """Returns (response_dict, http_status)."""
    text, error = validate_query(raw_input)
    if error:
        return {"error": error}, 400

    result = predict_query(text)
    score = result["score"]
    is_sqli = score >= THRESHOLD
    patterns = find_patterns(text)

    if is_sqli:
        predicted, action = "SQLi", "Blocked"
        severity = "High" if score >= 0.9 else "Medium"
        explanation = (
            "The model classified this input as a potential SQL injection. "
            "This is a prediction, not confirmed proof of an attack."
        )
    else:
        predicted, action, severity = "Legitimate", "Allowed", "Low"
        explanation = "The model classified this input as legitimate. It may still be wrong."

    if patterns:
        explanation += " Patterns worth reviewing: " + ", ".join(patterns) + "."

    incident_id = add_incident(
        text, predicted, MODEL_NAME, score, action,
        severity, explanation, MITIGATION,
    )

    return {
        "incident_id": incident_id,
        "predicted_class": predicted,
        "score": score,
        "action": action,
        "severity": severity,
        "patterns": patterns,
        "explanation": explanation,
        "mitigation": MITIGATION,
    }, 200


if __name__ == "__main__":
    for s in ["SELECT name FROM users WHERE id = 5",
              "SELECT * FROM users WHERE id = 1 OR 1=1 --"]:
        print(process_request(s))