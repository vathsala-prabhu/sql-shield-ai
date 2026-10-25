import os
import sys
import json
import re
import numpy as np
import pandas as pd
import joblib
from pathlib import Path

def run_robustness():
    root = Path(".").resolve()
    models_dir = root / "models"
    out_dir = root / "audit_report" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)

    vectorizer = joblib.load(models_dir / "tfidf_vectorizer.joblib")
    rf = joblib.load(models_dir / "random_forest.joblib")
    xgb = joblib.load(models_dir / "xgboost.joblib")

    # Import predict_query from ml/predict.py to test the runtime wrapper vs raw model
    sys.path.insert(0, str(root))
    from ml.predict import predict_query

    test_cases = [
        # 1. Standard Injections
        {"category": "baseline_sqli", "input": "' OR '1'='1", "expected": 1},
        {"category": "baseline_sqli", "input": "1' UNION SELECT null, username, password FROM users--", "expected": 1},
        {"category": "baseline_sqli", "input": "admin' --", "expected": 1},
        {"category": "baseline_sqli", "input": "'; DROP TABLE users; --", "expected": 1},
        {"category": "baseline_sqli", "input": "1 AND SLEEP(5)#", "expected": 1},

        # 2. Baseline Legitimate Queries
        {"category": "baseline_legit", "input": "SELECT id, name, email FROM users WHERE id = 10", "expected": 0},
        {"category": "baseline_legit", "input": "UPDATE products SET price = 19.99 WHERE product_id = 42", "expected": 0},
        {"category": "baseline_legit", "input": "INSERT INTO logs (action, timestamp) VALUES ('login', 162983712)", "expected": 0},
        {"category": "baseline_legit", "input": "DELETE FROM sessions WHERE expires_at < NOW()", "expected": 0},

        # 3. Complex Legitimate Queries (CTEs, Window Functions, Subqueries)
        {"category": "complex_legit", "input": "WITH ranked AS (SELECT id, department, salary, ROW_NUMBER() OVER (PARTITION BY department ORDER BY salary DESC) as rnk FROM employees) SELECT * FROM ranked WHERE rnk <= 3", "expected": 0},
        {"category": "complex_legit", "input": "SELECT u.id, u.username, COUNT(o.id) as order_count FROM users u LEFT JOIN orders o ON u.id = o.user_id GROUP BY u.id, u.username HAVING COUNT(o.id) > 5", "expected": 0},
        {"category": "complex_legit", "input": "SELECT * FROM articles WHERE published = 1 AND category IN ('tech', 'science') ORDER BY created_at DESC LIMIT 20 OFFSET 40", "expected": 0},

        # 4. Obfuscated / Evasion Injections
        # Comment insertion
        {"category": "evasion_comment_inline", "input": "1' UN/**/ION SE/**/LECT 1, 2, 3--", "expected": 1},
        # Case variation
        {"category": "evasion_mixed_case", "input": "' oR '1'='1", "expected": 1},
        {"category": "evasion_mixed_case", "input": "1' UnIoN sElEcT user, password FrOm users--", "expected": 1},
        # Whitespace / tab variations
        {"category": "evasion_whitespace", "input": "1'\tUNION\tSELECT\tnull,null--", "expected": 1},
        {"category": "evasion_whitespace", "input": "1'\nOR\n1=1\n--", "expected": 1},
        # Benign Prefix Camouflage (A long legitimate query followed by an injection)
        {"category": "benign_prefix_camouflage", "input": "SELECT product_name, price, stock, category_id, vendor_id, description, created_at, updated_at FROM inventory_items WHERE active = 1 AND deleted_at IS NULL AND category_id = 5 OR 1=1 --", "expected": 1},
        {"category": "benign_prefix_camouflage", "input": "SELECT u.first_name, u.last_name, u.email, u.phone_number, a.address_line_1, a.city, a.postal_code FROM customer_profiles u JOIN addresses a ON u.id = a.customer_id WHERE u.status = 'ACTIVE' AND u.id = '1' UNION SELECT null, null, username, password, null, null, null FROM admin_users --'", "expected": 1},
        # URL Encoding
        {"category": "evasion_url_encoded", "input": "%27%20OR%201%3D1%20--", "expected": 1},
        {"category": "evasion_url_encoded", "input": "1%27%20UNION%20SELECT%20null%2Cnull--", "expected": 1},
        # Hex encoded payloads
        {"category": "evasion_hex", "input": "SELECT * FROM users WHERE username = 0x61646d696e", "expected": 1},
        # Time-based blind variants
        {"category": "evasion_blind", "input": "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--", "expected": 1},
        {"category": "evasion_blind", "input": "1'; WAITFOR DELAY '0:0:5'--", "expected": 1},
        {"category": "evasion_blind", "input": "1' AND pg_sleep(5)--", "expected": 1},
    ]

    robustness_results = []

    for tc in test_cases:
        inp = tc["input"]
        exp = tc["expected"]
        cat = tc["category"]

        # Raw model direct prediction
        X_raw = vectorizer.transform([inp])
        rf_raw_prob = float(rf.predict_proba(X_raw)[0, 1])
        rf_raw_pred = int(rf.predict(X_raw)[0])
        xgb_raw_prob = float(xgb.predict_proba(X_raw)[0, 1])
        xgb_raw_pred = int(xgb.predict(X_raw)[0])

        # predict.py segmented wrapper prediction
        pred_wrapper = predict_query(inp)
        wrapper_prob = pred_wrapper["score"]
        wrapper_label = pred_wrapper["label"]
        wrapper_pred = 1 if wrapper_label == "SQLi" else 0

        robustness_results.append({
            "category": cat,
            "input": inp,
            "expected": exp,
            "rf_raw_pred": rf_raw_pred,
            "rf_raw_prob": round(rf_raw_prob, 4),
            "xgb_raw_pred": xgb_raw_pred,
            "xgb_raw_prob": round(xgb_raw_prob, 4),
            "wrapper_pred": wrapper_pred,
            "wrapper_prob": round(wrapper_prob, 4),
            "rf_pass": bool(rf_raw_pred == exp),
            "xgb_pass": bool(xgb_raw_pred == exp),
            "wrapper_pass": bool(wrapper_pred == exp),
        })

    # Summary by category
    category_summary = {}
    for r in robustness_results:
        cat = r["category"]
        if cat not in category_summary:
            category_summary[cat] = {"total": 0, "rf_pass": 0, "xgb_pass": 0, "wrapper_pass": 0}
        category_summary[cat]["total"] += 1
        if r["rf_pass"]: category_summary[cat]["rf_pass"] += 1
        if r["xgb_pass"]: category_summary[cat]["xgb_pass"] += 1
        if r["wrapper_pass"]: category_summary[cat]["wrapper_pass"] += 1

    # Template similarity / Near-duplicate cluster analysis across splits
    # Let's inspect structural templates: replace literal numbers with <NUM>, strings with <STR>
    def get_template(q):
        s = str(q).lower()
        s = re.sub(r"\'[^\']*\'", "<STR>", s)
        s = re.sub(r'\"[^\"]*\"', "<STR>", s)
        s = re.sub(r"\b\d+\b", "<NUM>", s)
        s = re.sub(r"\s+", " ", s).strip()
        return s

    df_train = pd.read_csv(root / "data" / "train.csv")
    df_val = pd.read_csv(root / "data" / "val.csv")
    df_test = pd.read_csv(root / "data" / "test.csv")

    train_templates = set(df_train["Query"].map(get_template))
    val_templates = set(df_val["Query"].map(get_template))
    test_templates = set(df_test["Query"].map(get_template))

    template_overlap = {
        "train_template_count": len(train_templates),
        "val_template_count": len(val_templates),
        "test_template_count": len(test_templates),
        "train_val_template_overlap": len(train_templates.intersection(val_templates)),
        "train_test_template_overlap": len(train_templates.intersection(test_templates)),
        "val_test_template_overlap": len(val_templates.intersection(test_templates)),
    }

    output = {
        "category_summary": category_summary,
        "template_overlap": template_overlap,
        "detailed_cases": robustness_results
    }

    with open(out_dir / "robustness_and_evasion_results.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print("Robustness test completed. Saved to", out_dir / "robustness_and_evasion_results.json")

if __name__ == "__main__":
    run_robustness()
