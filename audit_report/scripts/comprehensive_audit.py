import os
import sys
import json
import re
import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score, average_precision_score
)

def run_audit():
    root = Path(".").resolve()
    data_dir = root / "data"
    models_dir = root / "models"
    out_dir = root / "audit_report" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)

    results = {}

    # 1. Dataset Loading and Count Verification
    raw_path = data_dir / "Modified_SQL_Dataset.csv"
    clean_path = data_dir / "clean_dataset.csv"
    train_path = data_dir / "train.csv"
    val_path = data_dir / "val.csv"
    test_path = data_dir / "test.csv"

    df_raw = pd.read_csv(raw_path)
    df_clean = pd.read_csv(clean_path)
    df_train = pd.read_csv(train_path)
    df_val = pd.read_csv(val_path)
    df_test = pd.read_csv(test_path)

    results["counts"] = {
        "raw": {
            "total": len(df_raw),
            "columns": list(df_raw.columns),
            "null_queries": int(df_raw["Query"].isnull().sum()),
            "null_labels": int(df_raw["Label"].isnull().sum()),
            "exact_duplicate_rows": int(df_raw.duplicated().sum()),
            "exact_duplicate_queries": int(df_raw.duplicated(subset=["Query"]).sum()),
            "label_distribution": {str(k): int(v) for k, v in df_raw["Label"].value_counts().items()}
        },
        "clean": {
            "total": len(df_clean),
            "columns": list(df_clean.columns),
            "exact_duplicate_queries": int(df_clean.duplicated(subset=["Query"]).sum()),
            "label_distribution": {str(k): int(v) for k, v in df_clean["label"].value_counts().items()},
            "y_distribution": {str(k): int(v) for k, v in df_clean["y"].value_counts().items()}
        },
        "train": {
            "total": len(df_train),
            "y_distribution": {str(k): int(v) for k, v in df_train["y"].value_counts().items()},
            "pos_ratio": float(df_train["y"].mean())
        },
        "val": {
            "total": len(df_val),
            "y_distribution": {str(k): int(v) for k, v in df_val["y"].value_counts().items()},
            "pos_ratio": float(df_val["y"].mean())
        },
        "test": {
            "total": len(df_test),
            "y_distribution": {str(k): int(v) for k, v in df_test["y"].value_counts().items()},
            "pos_ratio": float(df_test["y"].mean())
        }
    }

    # 2. Check Split Mutual Exclusivity and Overlaps
    # Raw exact match
    train_queries = set(df_train["Query"].astype(str))
    val_queries = set(df_val["Query"].astype(str))
    test_queries = set(df_test["Query"].astype(str))

    train_val_overlap = train_queries.intersection(val_queries)
    train_test_overlap = train_queries.intersection(test_queries)
    val_test_overlap = val_queries.intersection(test_queries)

    # Normalized match (lowercase + whitespace collapse)
    def normalize_sql(q):
        return re.sub(r"\s+", " ", str(q).strip().lower())

    train_norm = set(df_train["Query"].map(normalize_sql))
    val_norm = set(df_val["Query"].map(normalize_sql))
    test_norm = set(df_test["Query"].map(normalize_sql))

    train_val_norm_overlap = train_norm.intersection(val_norm)
    train_test_norm_overlap = train_norm.intersection(test_norm)
    val_test_norm_overlap = val_norm.intersection(test_norm)

    results["split_leakage"] = {
        "exact_overlap": {
            "train_val_count": len(train_val_overlap),
            "train_test_count": len(train_test_overlap),
            "val_test_count": len(val_test_overlap),
        },
        "normalized_overlap": {
            "train_val_count": len(train_val_norm_overlap),
            "train_test_count": len(train_test_norm_overlap),
            "val_test_count": len(val_test_norm_overlap),
        }
    }

    # 3. Check for duplicates with conflicting labels in raw dataset
    df_raw_clean = df_raw.dropna(subset=["Query", "Label"]).copy()
    df_raw_clean["key"] = df_raw_clean["Query"].map(normalize_sql)
    grouped = df_raw_clean.groupby("key")["Label"].nunique()
    conflicting_keys = grouped[grouped > 1].index.tolist()
    
    results["conflicts_in_raw"] = {
        "count": len(conflicting_keys),
        "examples": conflicting_keys[:5]
    }

    # Check if any conflicting key made it into clean_dataset or train/val/test
    clean_keys = set(df_clean["Query"].map(normalize_sql))
    results["conflicts_in_clean"] = len(clean_keys.intersection(set(conflicting_keys)))

    # 4. Check TF-IDF Vectorizer Fitting Leakage
    vectorizer = joblib.load(models_dir / "tfidf_vectorizer.joblib")
    
    # We inspect ml/features.py:
    # vectorizer.fit_transform(train["Query"].astype(str))
    # Let's verify whether vectorizer matches fit on train only!
    from sklearn.feature_extraction.text import TfidfVectorizer
    fresh_vec = TfidfVectorizer(
        analyzer="char",
        ngram_range=(2, 5),
        max_features=20000,
    )
    fresh_vec.fit(df_train["Query"].astype(str))
    
    # Compare vocabularies
    saved_vocab = vectorizer.vocabulary_
    fresh_vocab = fresh_vec.vocabulary_
    vocab_diff_keys = set(saved_vocab.keys()).symmetric_difference(set(fresh_vocab.keys()))
    
    # Also check if vectorizer was fitted on full clean dataset
    full_vec = TfidfVectorizer(
        analyzer="char",
        ngram_range=(2, 5),
        max_features=20000,
    )
    full_vec.fit(df_clean["Query"].astype(str))
    full_vocab_diff = set(saved_vocab.keys()).symmetric_difference(set(full_vec.vocabulary_.keys()))

    results["tfidf_audit"] = {
        "saved_vocab_len": len(saved_vocab),
        "fresh_train_vocab_len": len(fresh_vocab),
        "symmetric_diff_with_train_fit": len(vocab_diff_keys),
        "symmetric_diff_with_full_clean_fit": len(full_vocab_diff),
        "idf_vector_len": len(vectorizer.idf_),
        "idf_match_train_fit": bool(np.allclose(vectorizer.idf_, fresh_vec.idf_)),
        "idf_match_full_fit": bool(np.allclose(vectorizer.idf_, full_vec.idf_)) if len(vectorizer.idf_) == len(full_vec.idf_) else False
    }

    # 5. Model Evaluation and Metric Recomputation
    rf = joblib.load(models_dir / "random_forest.joblib")
    xgb = joblib.load(models_dir / "xgboost.joblib")
    sel = joblib.load(models_dir / "selected_model.joblib")

    X_val = vectorizer.transform(df_val["Query"].astype(str))
    y_val = df_val["y"].values

    X_test = vectorizer.transform(df_test["Query"].astype(str))
    y_test = df_test["y"].values

    eval_data = {}
    for split_name, X_split, y_split in [("val", X_val, y_val), ("test", X_test, y_test)]:
        eval_data[split_name] = {}
        for mname, model in [("random_forest", rf), ("xgboost", xgb), ("selected_model", sel)]:
            preds = model.predict(X_split)
            probs = model.predict_proba(X_split)[:, 1] if hasattr(model, "predict_proba") else None
            
            tn, fp, fn, tp = confusion_matrix(y_split, preds, labels=[0, 1]).ravel()
            acc = (tp + tn) / (tp + tn + fp + fn)
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
            spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
            auc = roc_auc_score(y_split, probs) if probs is not None else None
            ap = average_precision_score(y_split, probs) if probs is not None else None

            eval_data[split_name][mname] = {
                "tn": int(tn),
                "fp": int(fp),
                "fn": int(fn),
                "tp": int(tp),
                "accuracy": float(acc),
                "precision": float(prec),
                "recall": float(rec),
                "f1": float(f1),
                "specificity": float(spec),
                "fpr": float(fpr),
                "fnr": float(fnr),
                "roc_auc": float(auc) if auc is not None else None,
                "pr_auc": float(ap) if ap is not None else None,
            }

    results["recomputed_metrics"] = eval_data

    # Verify if selected_model == random_forest predictions
    rf_test_preds = rf.predict(X_test)
    sel_test_preds = sel.predict(X_test)
    preds_identical = bool(np.array_equal(rf_test_preds, sel_test_preds))
    rf_test_probs = rf.predict_proba(X_test)
    sel_test_probs = sel.predict_proba(X_test)
    probs_identical = bool(np.allclose(rf_test_probs, sel_test_probs))
    results["selected_vs_rf_identity"] = {
        "predictions_identical": preds_identical,
        "probabilities_identical": probs_identical
    }

    # 6. Feature Importance Extraction
    feature_names = vectorizer.get_feature_names_out()
    
    # Random Forest importances
    rf_importances = rf.feature_importances_
    rf_top_idx = np.argsort(rf_importances)[::-1][:50]
    rf_top_features = [
        {"rank": i + 1, "feature": feature_names[idx], "importance": float(rf_importances[idx])}
        for i, idx in enumerate(rf_top_idx)
    ]

    # XGBoost importances (gain & weight)
    xgb_booster = xgb.get_booster()
    score_gain = xgb_booster.get_score(importance_type="gain")
    score_weight = xgb_booster.get_score(importance_type="weight")
    
    # Feature names in XGBoost are f0, f1, ... or feature_names
    xgb_top_gain = []
    # Sort gain
    sorted_gain = sorted(score_gain.items(), key=lambda x: x[1], reverse=True)[:50]
    for i, (f_k, g_val) in enumerate(sorted_gain):
        idx = int(f_k.replace("f", "")) if f_k.startswith("f") and f_k[1:].isdigit() else None
        fname = feature_names[idx] if idx is not None and idx < len(feature_names) else f_k
        xgb_top_gain.append({"rank": i + 1, "feature_id": f_k, "feature": fname, "gain": float(g_val)})

    results["feature_analysis"] = {
        "rf_top_50": rf_top_features,
        "xgb_top_50_gain": xgb_top_gain,
        "rf_top_20": rf_top_features[:20],
        "xgb_top_20_gain": xgb_top_gain[:20],
    }

    # Save complete feature table
    rf_df = pd.DataFrame({
        "feature": feature_names,
        "rf_importance": rf_importances
    }).sort_values(by="rf_importance", ascending=False)
    rf_df.to_csv(out_dir / "rf_all_feature_importances.csv", index=False)

    with open(out_dir / "audit_metrics_and_checks.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("Audit run completed successfully. Results saved to", out_dir / "audit_metrics_and_checks.json")

if __name__ == "__main__":
    run_audit()
