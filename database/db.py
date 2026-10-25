import sqlite3
from datetime import datetime, timezone
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import config

DB_PATH = config.DB_PATH


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    schema_path = config.BASE_DIR / "database" / "schema.sql"
    with get_connection() as conn:
        conn.executescript(schema_path.read_text(encoding="utf-8"))


def add_incident(submitted_input, predicted_class, model_used, score,
                 action_taken, severity, explanation, mitigation):
    """
    Safely records a security incident or analyzed query using parameterized queries.
    Stores up to 1000 characters of input to prevent storage exhaustion.
    """
    with get_connection() as conn:
        cur = conn.execute(
            """INSERT INTO incidents
               (timestamp, submitted_input, predicted_class, model_used,
                score, action_taken, severity, explanation, mitigation)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
                submitted_input[:1000],
                predicted_class,
                model_used,
                round(float(score), 4),
                action_taken,
                severity,
                explanation,
                mitigation,
            ),
        )
        return cur.lastrowid


def get_incident(incident_id):
    """Retrieves a single incident by ID using a parameterized query."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (int(incident_id),)
        ).fetchone()
        return dict(row) if row else None


def list_incidents(limit=100, action=None, severity=None, search=None):
    """Lists incidents with optional filtering by action, severity, and text search."""
    query = "SELECT * FROM incidents WHERE 1=1"
    params = []

    if action:
        query += " AND action_taken = ?"
        params.append(action)
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if search:
        query += " AND (submitted_input LIKE ? OR explanation LIKE ?)"
        wildcard = f"%{search}%"
        params.extend([wildcard, wildcard])

    query += " ORDER BY id DESC LIMIT ?"
    params.append(int(limit))

    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def get_stats():
    """
    Aggregates incident statistics for dashboard reporting.
    Returns real statistics computed from stored incident records.
    """
    with get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        blocked = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE action_taken = 'Blocked'"
        ).fetchone()[0]
        allowed = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE action_taken = 'Allowed'"
        ).fetchone()[0]
        sqli_detected = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE predicted_class = 'SQLi'"
        ).fetchone()[0]
        legitimate = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE predicted_class = 'Legitimate'"
        ).fetchone()[0]

        high_sev = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE severity = 'High'"
        ).fetchone()[0]
        med_sev = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE severity = 'Medium'"
        ).fetchone()[0]
        low_sev = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE severity = 'Low'"
        ).fetchone()[0]

        detection_rate = round((blocked / total * 100), 1) if total > 0 else 0.0

        return {
            "total_requests": total,
            "blocked_requests": blocked,
            "allowed_requests": allowed,
            "sqli_detected": sqli_detected,
            "legitimate_requests": legitimate,
            "detection_rate_pct": detection_rate,
            "severity_breakdown": {
                "high": high_sev,
                "medium": med_sev,
                "low": low_sev,
            },
        }


def clear_incidents():
    """Clears all logged demonstration incidents and resets auto-increment."""
    with get_connection() as conn:
        conn.execute("DELETE FROM incidents")
        try:
            conn.execute("DELETE FROM sqlite_sequence WHERE name='incidents'")
        except sqlite3.OperationalError:
            pass
        conn.commit()


def delete_incident(incident_id):
    """Deletes a single incident by ID."""
    with get_connection() as conn:
        conn.execute("DELETE FROM incidents WHERE id = ?", (int(incident_id),))
        conn.commit()


if __name__ == "__main__":
    init_db()
    print("Database ready. Incidents stored:", len(list_incidents()))
    print("Current stats:", get_stats())