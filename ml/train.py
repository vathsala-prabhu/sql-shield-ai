import json
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import (accuracy_score, precision_score,
                             recall_score, f1_score, confusion_matrix)

# Load the saved vectorizer and the data splits
vectorizer = joblib.load("models/tfidf_vectorizer.joblib")
train = pd.read_csv("data/train.csv")
val = pd.read_csv("data/val.csv")

X_train = vectorizer.transform(train["Query"].astype(str))
y_train = train["y"]
X_val = vectorizer.transform(val["Query"].astype(str))
y_val = val["y"]

# XGBoost imbalance handling
neg = int((y_train == 0).sum())
pos = int((y_train == 1).sum())

models = {
    "random_forest": RandomForestClassifier(
        n_estimators=100, random_state=42, n_jobs=-1
    ),
    "xgboost": XGBClassifier(
        objective="binary:logistic", eval_metric="logloss",
        scale_pos_weight=neg / pos, random_state=42, n_jobs=-1
    ),
}

results = {}
for name, model in models.items():
    print("Training", name, "...")
    model.fit(X_train, y_train)
    joblib.dump(model, f"models/{name}.joblib")

    pred = model.predict(X_val)
    tn, fp, fn, tp = confusion_matrix(y_val, pred).ravel()
    results[name] = {
        "accuracy": float(accuracy_score(y_val, pred)),
        "precision": float(precision_score(y_val, pred)),
        "recall": float(recall_score(y_val, pred)),
        "f1": float(f1_score(y_val, pred)),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
    }

with open("models/val_metrics.json", "w") as f:
    json.dump(results, f, indent=2)

print(json.dumps(results, indent=2))