import os
import sys
import hashlib
import json
from pathlib import Path
import joblib

def compute_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192 * 16):
            h.update(chunk)
    return h.hexdigest()

def main():
    root = Path(".").resolve()
    models_dir = root / "models"
    data_dir = root / "data"
    
    inventory = {
        "files": {},
        "model_artifacts": {}
    }
    
    target_files = [
        models_dir / "metrics.json",
        models_dir / "val_metrics.json",
        models_dir / "random_forest.joblib",
        models_dir / "xgboost.joblib",
        models_dir / "selected_model.joblib",
        models_dir / "tfidf_vectorizer.joblib",
        data_dir / "Modified_SQL_Dataset.csv",
        data_dir / "clean_dataset.csv",
        data_dir / "train.csv",
        data_dir / "val.csv",
        data_dir / "test.csv",
    ]
    
    for tf in target_files:
        if tf.exists():
            inventory["files"][str(tf.relative_to(root))] = {
                "size_bytes": tf.stat().st_size,
                "sha256": compute_sha256(tf)
            }
            
    # Inspect models safely
    for model_name in ["random_forest", "xgboost", "selected_model", "tfidf_vectorizer"]:
        mp = models_dir / f"{model_name}.joblib"
        if not mp.exists():
            continue
        obj = joblib.load(mp)
        meta = {
            "type": str(type(obj)),
            "class_name": obj.__class__.__name__,
        }
        if hasattr(obj, "get_params"):
            meta["params"] = {k: str(v) for k, v in obj.get_params().items()}
        if hasattr(obj, "n_features_in_"):
            meta["n_features_in_"] = int(obj.n_features_in_)
        if hasattr(obj, "classes_"):
            meta["classes_"] = [int(c) for c in obj.classes_]
        if hasattr(obj, "n_estimators") and obj.n_estimators is not None:
            meta["n_estimators"] = int(obj.n_estimators)
        if hasattr(obj, "get_booster"):
            try:
                booster = obj.get_booster()
                meta["num_boosted_rounds"] = booster.num_boosted_rounds()
            except Exception as e:
                meta["booster_err"] = str(e)
        if hasattr(obj, "estimators_"):
            meta["n_actual_estimators"] = len(obj.estimators_)
        if hasattr(obj, "vocabulary_"):
            meta["vocabulary_size"] = len(obj.vocabulary_)
            meta["ngram_range"] = obj.ngram_range
            meta["analyzer"] = obj.analyzer
            meta["max_features"] = obj.max_features
            meta["min_df"] = obj.min_df
            meta["max_df"] = obj.max_df
            meta["lowercase"] = obj.lowercase
            meta["norm"] = obj.norm
            meta["use_idf"] = obj.use_idf
            meta["sublinear_tf"] = obj.sublinear_tf
            meta["smooth_idf"] = obj.smooth_idf
        inventory["model_artifacts"][model_name] = meta

    out_path = Path("audit_report/artifact_inventory.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(inventory, f, indent=2)
    print("Saved inventory to", out_path)

if __name__ == "__main__":
    main()
