
import os
import json
import joblib
import pandas as pd

# Use a non-GUI backend to avoid Tcl/Tk errors on Windows
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    ConfusionMatrixDisplay
)


def main():
    # Project paths (run this script from the project root)
    vectorizer_path = "models/tfidf_vectorizer.joblib"
    test_path = "data/test.csv"
    validation_path = "models/val_metrics.json"
    output_dir = "evaluation_results"

    os.makedirs(output_dir, exist_ok=True)

    # Load the fitted TF-IDF vectorizer and test dataset
    vectorizer = joblib.load(vectorizer_path)
    test = pd.read_csv(test_path)

    if "Query" not in test.columns or "y" not in test.columns:
        raise ValueError(
            "data/test.csv must contain 'Query' and 'y' columns."
        )

    X_test = vectorizer.transform(test["Query"].astype(str))
    y_test = test["y"]

    # Load validation metrics
    with open(validation_path, "r", encoding="utf-8") as f:
        val = json.load(f)

    # Select the model using validation results only:
    # highest SQL injection recall, then F1-score
    selected = max(
        val,
        key=lambda name: (
            val[name]["recall"],
            val[name]["f1"]
        )
    )

    print("Selected model (from validation):", selected)

    test_results = {}

    for name in val:
        model_path = f"models/{name}.joblib"

        if not os.path.exists(model_path):
            print(f"Skipping missing model: {model_path}")
            continue

        model = joblib.load(model_path)

        # Predict on the held-out test set
        predictions = model.predict(X_test)

        # Assumes labels 0 = legitimate, 1 = SQL injection
        cm = confusion_matrix(
            y_test,
            predictions,
            labels=[0, 1]
        )

        tn, fp, fn, tp = cm.ravel()

        # Calculate evaluation metrics
        test_results[name] = {
            "accuracy": float(
                accuracy_score(y_test, predictions)
            ),
            "precision": float(
                precision_score(
                    y_test, predictions, zero_division=0
                )
            ),
            "recall": float(
                recall_score(
                    y_test, predictions, zero_division=0
                )
            ),
            "f1": float(
                f1_score(
                    y_test, predictions, zero_division=0
                )
            ),
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp)
        }

        # Print the confusion matrix
        print(f"\n{name.upper()} - CONFUSION MATRIX")
        print("Rows: actual; columns: predicted")
        print(cm)

        # Generate and save the confusion matrix image
        display = ConfusionMatrixDisplay(
            confusion_matrix=cm,
            display_labels=[
                "Legitimate",
                "SQL Injection"
            ]
        )

        display.plot(
            cmap="Blues",
            values_format="d"
        )

        plt.title(
            f"{name.replace('_', ' ').title()} "
            "Confusion Matrix"
        )
        plt.tight_layout()

        image_path = os.path.join(
            output_dir,
            f"{name}_confusion_matrix.png"
        )

        plt.savefig(
            image_path,
            dpi=300,
            bbox_inches="tight"
        )

        # No plt.show(): Agg saves directly to PNG
        plt.close()

        print(f"Saved matrix image: {image_path}")

    # Save all evaluation results
    output = {
        "selected_model": selected,
        "selection_rule": (
            "Highest SQL injection recall on validation, "
            "then F1-score"
        ),
        "validation": val,
        "test": test_results
    }

    metrics_path = "models/metrics.json"

    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    # Save the selected model for the Flask application
    selected_model_path = f"models/{selected}.joblib"

    if os.path.exists(selected_model_path):
        joblib.dump(
            joblib.load(selected_model_path),
            "models/selected_model.joblib"
        )
        print("\nSelected model saved for Flask app.")
    else:
        print(
            "\nWarning: selected model file not found: "
            f"{selected_model_path}"
        )

    print("\nTEST RESULTS")
    print(json.dumps(test_results, indent=2))
    print(f"\nMetrics saved to: {metrics_path}")
    print(f"Confusion matrix images saved in: {output_dir}")


if __name__ == "__main__":
    main()
