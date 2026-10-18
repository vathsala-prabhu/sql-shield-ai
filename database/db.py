import sqlite3
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "shield.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_connection() as conn:
        conn.executescript((BASE / "schema.sql").read_text())


def add_incident(submitted_input, predicted_class, model_used, score,
                 action_taken, severity, explanation, mitigation):
    # Only the first 1000 characters are stored, to avoid keeping unnecessary data
    with get_connection() as conn:
        cur = conn.execute(
            """INSERT INTO incidents
               (timestamp, submitted_input, predicted_class, model_used,
                score, action_taken, severity, explanation, mitigation)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"),
             submitted_input[:1000], predicted_class, model_used, score,
             action_taken, severity, explanation, mitigation),
        )
        return cur.lastrowid


def get_incident(incident_id):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        return dict(row) if row else None


def list_incidents(limit=100):
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


if __name__ == "__main__":
    init_db()
    print("Database ready. Incidents stored:", len(list_incidents()))