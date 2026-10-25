import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import config
from ml.predict import predict_query
from database.db import add_incident
from security.validation import validate_query

# Load selected model name from metrics.json if available
METRICS_PATH = config.MODELS_DIR / "metrics.json"
try:
    if METRICS_PATH.exists():
        SELECTED_MODEL = json.loads(METRICS_PATH.read_text(encoding="utf-8")).get("selected_model", "random_forest")
    else:
        SELECTED_MODEL = "random_forest"
except Exception:
    SELECTED_MODEL = "random_forest"

# Suspicious SQL syntax signatures for defense-in-depth inspection and human explainability
# The tautology regex strictly validates that LHS == RHS (e.g. '1'='1', 1=1, 'a'='a')
# to avoid false matches on benign queries (e.g. category = 'books' OR category = 'electronics').
PATTERNS = {
    "Boolean Tautology (OR/AND True)": r"\b(?:or|and)\b\s+(['\"]?)([\w]+)\1\s*=\s*\1\2\1",
    "SQL Comment Marker": r"(--|#|/\*|\*/)",
    "UNION Data Exfiltration": r"\bunion\s+(?:all\s+)?select\b",
    "Stacked Statement (Semicolon)": r";\s*(?:select|insert|update|delete|drop|alter|create|exec)\b",
    "Time-Delay / Blind SQLi": r"\b(?:sleep\s*\(|waitfor\s+delay|pg_sleep|benchmark\s*\()",
    "System / Schema Probing": r"\b(?:information_schema|sysobjects|sysdatabases|version\s*\(|@@version)\b",
    "Error-Based Injection Vectors": r"\b(?:extractvalue|updatexml|utl_inaddr|cast\s*\(.*as\s+int\))\b",
    "Evasion Hex / Char Encoding": r"(?:0x[0-9a-fA-F]{4,}|char\s*\(\s*\d+\s*\))",
}

DEFAULT_MITIGATION = (
    "Employ parameterized queries (Prepared Statements) with bind parameters. "
    "Enforce strict input validation, utilize an ORM, and apply the Principle of Least Privilege on database credentials."
)


def find_patterns(text):
    """Scans query text against catalog of known SQL injection structural signatures."""
    lowered = text.lower()
    matches = []
    for name, pattern in PATTERNS.items():
        if re.search(pattern, lowered, flags=re.IGNORECASE):
            matches.append(name)
    return matches


def simulate_application_path(is_sqli, query_text):
    """
    Simulates the safe, controlled application execution path for demonstration.
    Legitimate requests proceed to a mock data handler (no raw SQL is ever executed).
    SQL injection attempts are blocked at the gateway before reaching any handler.
    """
    if is_sqli:
        return {
            "status": "blocked",
            "code": 403,
            "gateway_action": "INTERCEPTED_AND_BLOCKED",
            "message": "Gateway security policy triggered. Execution terminated. No query sent to database.",
            "execution_details": "Request was dropped at perimeter inspection layer.",
        }
    else:
        # Safe simulated response
        query_type = "SELECT"
        first_word = query_text.strip().split()[0].upper() if query_text.strip() else "SELECT"
        if first_word in ("INSERT", "UPDATE", "DELETE", "SELECT"):
            query_type = first_word

        return {
            "status": "allowed",
            "code": 200,
            "gateway_action": "PERMITTED_TO_SAFE_HANDLER",
            "message": "Query cleared by ML Shield. Routed to controlled demo application pipeline.",
            "execution_details": f"Simulated {query_type} operation safely evaluated against demo mock data store.",
            "mock_result": {
                "records_affected": 1 if query_type != "SELECT" else 3,
                "read_only_sandbox": True,
                "raw_sql_executed": False,
            },
        }


def process_request(raw_input, threshold=None, model_name=None):
    """
    Main Security Gateway entrance point.
    
    1. Validates input format and length
    2. Runs ML inference via TF-IDF + Classifier with clause segment evaluation
    3. Detects structural patterns for explainability and defense-in-depth enforcement
    4. Evaluates decision against security threshold and attack signatures
    5. Dispatches to safe simulation path or blocks request
    6. Logs security incident with full audit trail in SQLite
    
    Returns:
        tuple: (response_dict, http_status_code)
    """
    text, error = validate_query(raw_input)
    if error:
        return {"error": error, "status": "validation_failed"}, 400

    if threshold is None:
        threshold = config.DEFAULT_THRESHOLD
    if model_name is None:
        model_name = config.ACTIVE_MODEL

    # Run ML prediction (evaluating both full query and candidate injection segments)
    prediction = predict_query(text, threshold=threshold, model_name=model_name, compare_both=True)
    score = prediction["score"]
    patterns = find_patterns(text)

    # In defense-in-depth architecture, an attack is flagged if ML score exceeds threshold
    # OR if verified high-confidence injection signatures (tautologies, UNION, etc.) are present
    is_sqli = (score >= threshold) or (len(patterns) > 0)

    # Determine risk severity and explanation
    if is_sqli:
        predicted = "SQLi"
        action = "Blocked"
        severity = "High" if (score >= 0.85 or "Boolean Tautology" in str(patterns) or "UNION" in str(patterns)) else "Medium"
        explanation = (
            f"The security gateway classified this input as potential SQL Injection with a risk score of {score:.2f} "
            f"(threshold: {threshold:.2f}). Access to the backend was denied."
        )
    else:
        predicted = "Legitimate"
        action = "Allowed"
        severity = "Low"
        explanation = (
            f"The ML model classified this input as legitimate with a risk score of {score:.2f} "
            f"(threshold: {threshold:.2f}). The request was permitted through the controlled demonstration route."
        )

    if patterns:
        explanation += f" Suspicious syntax signatures detected: {', '.join(patterns)}."

    # Execute simulated controlled path
    simulation = simulate_application_path(is_sqli, text)

    # Log incident to SQLite for auditable record
    model_record_name = prediction.get("model_used", SELECTED_MODEL)
    incident_id = add_incident(
        submitted_input=text,
        predicted_class=predicted,
        model_used=model_record_name,
        score=score,
        action_taken=action,
        severity=severity,
        explanation=explanation,
        mitigation=DEFAULT_MITIGATION,
    )

    response_payload = {
        "incident_id": incident_id,
        "input_preview": text[:200] + ("..." if len(text) > 200 else ""),
        "predicted_class": predicted,
        "score": score,
        "full_query_score": prediction.get("full_query_score", score),
        "threshold": threshold,
        "action": action,
        "severity": severity,
        "model_used": model_record_name,
        "comparisons": prediction.get("comparisons", {}),
        "patterns": patterns,
        "explanation": explanation,
        "mitigation": DEFAULT_MITIGATION,
        "simulation": simulation,
        "disclaimer": (
            "SQL SHIELD AI is a defense-in-depth machine learning security layer. "
            "It must complement, not replace, prepared statements and parameterized queries."
        ),
    }

    return response_payload, 200


if __name__ == "__main__":
    for s in [
        "SELECT name FROM users WHERE id = 5",
        "SELECT * FROM users WHERE id = 1 OR 1=1 --",
        "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'",
        "SELECT * FROM products WHERE category = 'books' OR category = 'electronics'",
    ]:
        res, code = process_request(s)
        print(f"{s[:60]:<60} -> {res['action']} ({res['predicted_class']}, Score: {res['score']})")