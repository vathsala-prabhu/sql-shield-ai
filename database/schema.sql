CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    submitted_input TEXT NOT NULL,
    predicted_class TEXT NOT NULL,
    model_used TEXT NOT NULL,
    score REAL,
    action_taken TEXT NOT NULL,
    severity TEXT NOT NULL,
    explanation TEXT,
    mitigation TEXT
);