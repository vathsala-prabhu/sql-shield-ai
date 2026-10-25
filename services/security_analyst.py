import json
import re
import sys
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import config


def redact_sensitive_data(text):
    """
    Privacy-aware redaction: masks potentially sensitive data (passwords, hashes, emails, tokens)
    before any data is dispatched to an external API.
    """
    if not text:
        return text

    # Redact common credential patterns in SQL
    redacted = re.sub(
        r"(password\s*=\s*['\"])([^'\"]+)(['\"])",
        r"\g<1>[REDACTED_PASSWORD]\g<3>",
        text,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(
        r"(pass\s*=\s*['\"])([^'\"]+)(['\"])",
        r"\g<1>[REDACTED_PASSWORD]\g<3>",
        redacted,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(
        r"(token\s*=\s*['\"])([^'\"]+)(['\"])",
        r"\g<1>[REDACTED_TOKEN]\g<3>",
        redacted,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(
        r"[\w\.-]+@[\w\.-]+\.\w+",
        "[REDACTED_EMAIL]",
        redacted,
    )
    return redacted


def generate_fallback_explanation(incident_data, user_question=None):
    """
    Comprehensive, deterministic cybersecurity analysis engine used when no LLM API key
    is configured or when external network calls are disabled.
    """
    query = incident_data.get("submitted_input", incident_data.get("input_preview", "N/A"))
    predicted_class = incident_data.get("predicted_class", "Unknown")
    score = incident_data.get("score", 0.0)
    action = incident_data.get("action", incident_data.get("action_taken", "Unknown"))
    patterns = incident_data.get("patterns", [])
    model_name = incident_data.get("model_used", "Random Forest")

    is_sqli = predicted_class == "SQLi"

    # 1. Executive Summary
    if is_sqli:
        verdict = (
            f"**Verdict:** Potential SQL Injection Detected (Gateway Action: `{action}`).\n\n"
            f"The `{model_name}` classifier assigned a malicious probability score of **{score:.2f}** "
            f"(threshold: {incident_data.get('threshold', 0.5)}). The security gateway blocked this request "
            f"from reaching downstream database handlers."
        )
    else:
        verdict = (
            f"**Verdict:** Legitimate Input (Gateway Action: `{action}`).\n\n"
            f"The `{model_name}` classifier calculated a risk score of **{score:.2f}**, which is below "
            f"the blocking threshold. The request was allowed through the controlled demonstration route."
        )

    # 2. Syntax & Pattern Breakdown
    threat_breakdown = "### [Syntax Analysis]\n"
    if patterns:
        threat_breakdown += "The following suspicious structural patterns were identified:\n"
        for p in patterns:
            if "Comment" in p:
                threat_breakdown += (
                    f"- **{p}:** Injects comment delimiters (`--`, `/*`, `#`) to truncate remainder of the "
                    f"application query, nullifying subsequent integrity checks or WHERE clauses.\n"
                )
            elif "Tautology" in p:
                threat_breakdown += (
                    f"- **{p}:** Introduces an expression that always evaluates to TRUE (e.g. `1=1` or `'a'='a'`). "
                    f"When injected into a WHERE clause, this forces the database to return all rows, frequently used "
                    f"to bypass password checks.\n"
                )
            elif "UNION" in p:
                threat_breakdown += (
                    f"- **{p}:** Leverages `UNION SELECT` to append unauthorized result sets from foreign tables "
                    f"(such as user credentials, credit cards, or schema catalogs) to the application's legitimate query.\n"
                )
            elif "Stacked" in p:
                threat_breakdown += (
                    f"- **{p}:** Uses a statement delimiter (`;`) to piggyback entirely new SQL commands, "
                    f"enabling dangerous operations like `DROP TABLE` or `INSERT INTO users`.\n"
                )
            elif "Time-Delay" in p:
                threat_breakdown += (
                    f"- **{p}:** Invokes time-delay functions (like `sleep()` or `waitfor delay`). This is characteristic "
                    f"of Blind SQL Injection where attackers infer data by observing server response delays.\n"
                )
            else:
                threat_breakdown += f"- **{p}:** Recognized syntactic vector associated with database probing.\n"
    else:
        if is_sqli:
            threat_breakdown += (
                "No classic signature keywords were found, but the model's character n-gram feature representation "
                "detected high semantic similarity to SQL injection training vectors (e.g., atypical quotation patterns "
                "or punctuation clustering).\n"
            )
        else:
            threat_breakdown += "Standard SQL query syntax conforming to ordinary application data access conventions.\n"

    # 3. Model Uncertainty & False Positives Notice
    uncertainty_notice = (
        "### [Model Reliability & False Positives Notice]\n"
        "Machine Learning models are probabilistic classifiers rather than formal query parsers. "
        "A classification of **SQLi** indicates statistical similarity to malicious patterns in the training data, "
        "not definitive proof of an active attack. Conversely, complex obfuscation techniques may produce false negatives. "
        "For this reason, SQL SHIELD AI acts as a complementary defense layer alongside defensive programming."
    )

    # 4. Remediation & Prepared Statements
    remediation = (
        "### [Recommended Defensive Implementation: Prepared Statements]\n"
        "The gold standard for neutralizing SQL injection is to separate SQL code from user-supplied data "
        "using **Parameterized Queries (Prepared Statements)**. The database engine precompiles the query structure "
        "so input is strictly treated as literal data, never executable code.\n\n"
        "**Python (sqlite3 / psycopg2):**\n"
        "```python\n"
        "# VULNERABLE:\n"
        "# cursor.execute(f\"SELECT * FROM users WHERE id = '{user_input}'\")\n"
        "\n"
        "# SECURE (Parameterized):\n"
        "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_input,))\n"
        "```\n\n"
        "**JavaScript / Node.js (mysql2):**\n"
        "```javascript\n"
        "// SECURE (Placeholder ? syntax):\n"
        "const [rows] = await connection.execute(\n"
        "  'SELECT id, username, email FROM users WHERE id = ?',\n"
        "  [userId]\n"
        ");\n"
        "```\n\n"
        "**PHP (PDO):**\n"
        "```php\n"
        "// SECURE (Named Parameters):\n"
        "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n"
        "$stmt->execute(['id' => $userId]);\n"
        "```"
    )

    # 5. Answer to specific user question if provided
    q_and_a = ""
    if user_question:
        q_lower = user_question.lower()
        if "false positive" in q_lower:
            answer = (
                "A false positive occurs when legitimate user input (e.g. a name like *O'Connor* or text with "
                "dashes) resembles SQL operators. To verify, inspect if the input was intended as raw SQL or application data. "
                "In a properly parameterized application, special characters like single quotes are safely escaped by the driver."
            )
        elif "fix" in q_lower or "how to" in q_lower or "prevent" in q_lower:
            answer = (
                "To fix this vulnerability, eliminate string concatenation or f-strings when building SQL queries. "
                "Adopt prepared statements with parameter placeholders (? or :param), apply strict input whitelisting, "
                "and ensure database accounts run with minimal required privileges."
            )
        elif "bypass" in q_lower or "why blocked" in q_lower:
            answer = (
                f"This input was blocked because its calculated risk score ({score:.2f}) met or exceeded the gateway's "
                f"configured blocking threshold. The model flagged character patterns commonly seen in injection payloads."
            )
        else:
            answer = (
                f"Regarding your question ('{user_question}'): SQL SHIELD AI analyzes the structural character n-grams "
                f"of the input. In this incident, the query exhibited features matching SQL injection vectors with score {score:.2f}. "
                f"Defensive engineering should always enforce prepared statements at the persistence layer."
            )

        q_and_a = f"\n\n### [Analyst Q&A Response: \"{user_question}\"]\n{answer}"

    full_report = f"{verdict}\n\n{threat_breakdown}\n{uncertainty_notice}\n\n{remediation}{q_and_a}"

    return {
        "mode": "rule_based_fallback",
        "analysis": full_report,
        "is_sqli": is_sqli,
        "score": score,
        "action": action,
        "patterns": patterns,
    }


def call_gemini_api(incident_data, user_question=None, api_key=None):
    """
    Calls the Google Gemini API to generate an explainable cybersecurity briefing.
    Uses standard library urllib to avoid third-party network dependencies.
    """
    key = api_key or config.GEMINI_API_KEY
    if not key:
        return generate_fallback_explanation(incident_data, user_question)

    query = redact_sensitive_data(
        incident_data.get("submitted_input", incident_data.get("input_preview", ""))
    )
    predicted_class = incident_data.get("predicted_class", "Unknown")
    score = incident_data.get("score", 0.0)
    action = incident_data.get("action", incident_data.get("action_taken", "Unknown"))
    patterns = incident_data.get("patterns", [])
    model_name = incident_data.get("model_used", "Random Forest")

    system_instruction = (
        "You are the AI Security Analyst for SQL SHIELD AI, an academic web security platform. "
        "Your role is to explain machine learning SQL injection detection results to developers in beginner-friendly, "
        "professional cybersecurity terms. Always distinguish probabilistic ML predictions from confirmed attacks. "
        "Acknowledge uncertainty and possible false positives. Always teach parameterized queries (prepared statements) "
        "with short code snippets in Python, Node.js, and PHP. You do NOT make or override the gateway blocking decision."
    )

    prompt = (
        f"Incident Context:\n"
        f"- Analyzed Input (Redacted): {query}\n"
        f"- ML Model: {model_name}\n"
        f"- Classification: {predicted_class}\n"
        f"- Confidence Score: {score:.2f}\n"
        f"- Gateway Action Taken: {action}\n"
        f"- Identified Patterns: {', '.join(patterns) if patterns else 'None explicitly matched'}\n"
    )

    if user_question:
        prompt += f"\nUser Question: {user_question}\n"
    else:
        prompt += (
            "\nPlease provide:\n"
            "1. Clear explanation of why this input was classified this way\n"
            "2. Analysis of suspicious syntax or why it was deemed legitimate\n"
            "3. Concrete secure coding recommendations (Parameterized queries / Prepared statements with examples)\n"
            "4. A reminder that ML is probabilistic and defense-in-depth is essential."
        )

    model_name_api = config.GEMINI_MODEL
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name_api}:generateContent?key={key}"

    payload = {
        "contents": [{"parts": [{"text": f"{system_instruction}\n\n{prompt}"}]}],
        "generationConfig": {"temperature": 0.3, "maxOutputTokens": 1024},
    }

    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=12) as response:
            result = json.loads(response.read().decode("utf-8"))
            candidates = result.get("candidates", [])
            if candidates:
                text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                if text:
                    return {
                        "mode": "gemini_api",
                        "model": model_name_api,
                        "analysis": text,
                        "is_sqli": predicted_class == "SQLi",
                        "score": score,
                        "action": action,
                        "patterns": patterns,
                    }
    except Exception as e:
        # Graceful fallback if API call fails (network issue, invalid key, rate limit)
        fallback = generate_fallback_explanation(incident_data, user_question)
        fallback["mode"] = "fallback_after_api_error"
        fallback["note"] = f"External LLM API unavailable ({str(e)[:60]}). Showing expert local analysis."
        return fallback

    return generate_fallback_explanation(incident_data, user_question)


def analyze_incident(incident_data, user_question=None):
    """
    Main entry point for AI Security Analyst service.
    Directs to Gemini API if configured, otherwise executes the comprehensive local fallback engine.
    """
    if config.GEMINI_API_KEY:
        return call_gemini_api(incident_data, user_question)
    return generate_fallback_explanation(incident_data, user_question)


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    sample = {
        "submitted_input": "SELECT * FROM users WHERE id = 1 OR 1=1 --",
        "predicted_class": "SQLi",
        "score": 0.71,
        "action": "Blocked",
        "patterns": ["SQL Comment Marker", "Boolean Tautology (OR/AND True)"],
        "model_used": "Random Forest",
    }
    res = analyze_incident(sample, user_question="Can you show me how to fix this in Python?")
    print(res["analysis"])
