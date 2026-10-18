import json
import joblib
import pandas as pd
from sklearn.metrics import (accuracy_score, precision_score,
                             recall_score, f1_score, confusion_matrix)

vectorizer = joblib.load("models/tfidf_vectorizer.joblib")
test = pd.read_csv("data/test.csv")
X_test = vectorizer.transform(test["Query"].astype(str))
y_test = test["y"]

with open("models/val_metrics.json") as f:
    val = json.load(f)

# Selection uses VALIDATION results only: highest SQLi recall, then F1
selected = max(val, key=lambda n: (val[n]["recall"], val[n]["f1"]))
print("Selected model (from validation):", selected)

test_results = {}
for name in val:
    model = joblib.load(f"models/{name}.joblib")
    pred = model.predict(X_test)
    tn, fp, fn, tp = confusion_matrix(y_test, pred).ravel()
    test_results[name] = {
        "accuracy": float(accuracy_score(y_test, pred)),
        "precision": float(precision_score(y_test, pred)),
        "recall": float(recall_score(y_test, pred)),
        "f1": float(f1_score(y_test, pred)),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
    }

output = {
    "selected_model": selected,
    "selection_rule": "highest SQLi recall on validation, then F1",
    "validation": val,
    "test": test_results,
}
with open("models/metrics.json", "w") as f:
    json.dump(output, f, indent=2)

# Save the final model under a fixed name for the Flask app
joblib.dump(joblib.load(f"models/{selected}.joblib"),
            "models/selected_model.joblib")

print(json.dumps(test_results, indent=2))