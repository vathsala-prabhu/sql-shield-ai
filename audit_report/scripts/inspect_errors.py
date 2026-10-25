import json
import pandas as pd
import joblib
from pathlib import Path

def inspect_errors():
    root = Path(".").resolve()
    models_dir = root / "models"
    data_dir = root / "data"
    out_dir = root / "audit_report" / "results"

    vectorizer = joblib.load(models_dir / "tfidf_vectorizer.joblib")
    rf = joblib.load(models_dir / "random_forest.joblib")
    xgb = joblib.load(models_dir / "xgboost.joblib")

    test_df = pd.read_csv(data_dir / "test.csv")
    X_test = vectorizer.transform(test_df["Query"].astype(str))
    y_test = test_df["y"].values

    rf_preds = rf.predict(X_test)
    rf_probs = rf.predict_proba(X_test)[:, 1]
    xgb_preds = xgb.predict(X_test)
    xgb_probs = xgb.predict_proba(X_test)[:, 1]

    test_df["rf_pred"] = rf_preds
    test_df["rf_prob"] = rf_probs
    test_df["xgb_pred"] = xgb_preds
    test_df["xgb_prob"] = xgb_probs

    # RF False Positives: actual 0, predicted 1
    rf_fp = test_df[(test_df["y"] == 0) & (test_df["rf_pred"] == 1)]
    # RF False Negatives: actual 1, predicted 0
    rf_fn = test_df[(test_df["y"] == 1) & (test_df["rf_pred"] == 0)]

    # XGB False Positives: actual 0, predicted 1
    xgb_fp = test_df[(test_df["y"] == 0) & (test_df["xgb_pred"] == 1)]
    # XGB False Negatives: actual 1, predicted 0
    xgb_fn = test_df[(test_df["y"] == 1) & (test_df["xgb_pred"] == 0)]

    errors = {
        "rf_false_positives": [
            {"query": row["Query"], "prob": float(row["rf_prob"])}
            for _, row in rf_fp.iterrows()
        ],
        "rf_false_negatives": [
            {"query": row["Query"], "prob": float(row["rf_prob"])}
            for _, row in rf_fn.iterrows()
        ],
        "xgb_false_positives": [
            {"query": row["Query"], "prob": float(row["xgb_prob"])}
            for _, row in xgb_fp.iterrows()
        ],
        "xgb_false_negatives": [
            {"query": row["Query"], "prob": float(row["xgb_prob"])}
            for _, row in xgb_fn.iterrows()
        ]
    }

    with open(out_dir / "test_error_analysis.json", "w", encoding="utf-8") as f:
        json.dump(errors, f, indent=2)

    print(f"Error inspection complete:")
    print(f"RF FP: {len(rf_fp)}, RF FN: {len(rf_fn)}")
    print(f"XGB FP: {len(xgb_fp)}, XGB FN: {len(xgb_fn)}")

if __name__ == "__main__":
    inspect_errors()
