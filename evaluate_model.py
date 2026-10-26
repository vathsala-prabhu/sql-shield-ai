"""Evaluate SQLQueryShield on a labeled, held-out CSV dataset."""

import argparse
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import torch
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from transformers import AutoModelForSequenceClassification, AutoTokenizer, pipeline


ROOT = Path(__file__).resolve().parent
DEFAULT_TEST_CSV = ROOT / "data" / "test.csv"
DEFAULT_OUTPUT_DIR = ROOT
MODEL_ID = "salmane11/SQLQueryShield"
DOCUMENTED_TRAINING_CSV = (
    "https://huggingface.co/datasets/salmane11/SQLShield/"
    "resolve/main/train.csv"
)
# The model card documents a 128-token fine-tuning limit.
MAX_QUERY_TOKENS = 128


def normalize_query(query: str) -> str:
    """Normalize case and whitespace when checking duplicate SQL text."""
    return re.sub(r"\s+", " ", query.strip().lower())


def normalize_class(value: Any) -> int | None:
    """Return 0 for benign/safe, 1 for malicious, or None for unknown labels."""
    if pd.isna(value):
        return None
    if isinstance(value, (int, float)) and value in (0, 1):
        return int(value)

    label = str(value).strip().casefold()
    if label in {"0", "benign", "legitimate", "safe"}:
        return 0
    if label in {"1", "malicious", "sqli", "sql injection", "vulnerable"}:
        return 1
    return None


def load_test_data(
    csv_path: Path,
) -> tuple[pd.DataFrame, int, int, int, int]:
    """Load, validate, conflict-check, and deduplicate a labeled test CSV."""
    try:
        frame = pd.read_csv(csv_path)
    except FileNotFoundError as error:
        raise ValueError(
            f"Test CSV not found: {csv_path}. Use the held-out data/test.csv "
            "or provide an independent labeled test set with --test-csv."
        ) from error
    except (pd.errors.ParserError, UnicodeDecodeError) as error:
        raise ValueError(f"Could not read test CSV {csv_path}: {error}") from error

    if "Query" not in frame.columns:
        raise ValueError("Test CSV must have a 'Query' column.")

    label_column = next(
        (column for column in ("y", "Label", "label") if column in frame.columns),
        None,
    )
    if label_column is None:
        raise ValueError(
            "Test CSV must have a 'y', 'Label', or 'label' column."
        )

    frame = frame.copy()
    frame["source_row"] = frame.index + 2
    frame["Query"] = frame["Query"].astype("string")
    valid_queries = frame["Query"].notna() & frame["Query"].str.strip().ne("")
    invalid_query_count = int((~valid_queries).sum())
    frame = frame.loc[valid_queries].copy()
    frame["actual"] = frame[label_column].map(normalize_class)
    invalid_label_count = int(frame["actual"].isna().sum())
    frame = frame.loc[frame["actual"].notna()].copy()
    frame["actual"] = frame["actual"].astype(int)
    frame["query_key"] = frame["Query"].map(normalize_query)

    conflicts = (
        frame.groupby("query_key")["actual"].nunique().loc[lambda counts: counts > 1]
    )
    if not conflicts.empty:
        raise ValueError(
            f"Found {len(conflicts)} normalized query value(s) with conflicting "
            "labels in the test data. Correct or remove them before evaluating."
        )

    exact_duplicate_rows = int(frame.duplicated(subset=["Query"]).sum())
    normalized_duplicate_rows = int(frame.duplicated(subset=["query_key"]).sum())
    frame = frame.drop_duplicates(subset=["query_key"], keep="first").reset_index(
        drop=True
    )

    if frame.empty:
        raise ValueError("No valid, labeled, non-empty test examples were found.")

    return (
        frame,
        invalid_query_count,
        invalid_label_count,
        exact_duplicate_rows,
        normalized_duplicate_rows,
    )


def check_local_train_overlap(test_frame: pd.DataFrame) -> int | None:
    """Check the held-out examples against the repository's local training split."""
    train_path = ROOT / "data" / "train.csv"
    if not train_path.exists():
        print(
            "Local train/test overlap: not checked (data/train.csv is missing)."
        )
        return None

    try:
        train = pd.read_csv(train_path, usecols=["Query"])
    except (pd.errors.ParserError, UnicodeDecodeError, ValueError) as error:
        print(f"Local train/test overlap: unable to check ({error}).")
        return None

    train_keys = {
        normalize_query(query)
        for query in train["Query"].dropna().astype(str)
        if normalize_query(query)
    }
    overlap = set(test_frame["query_key"]) & train_keys
    print(f"Normalized query overlap with local data/train.csv: {len(overlap)}")
    if overlap:
        raise ValueError(
            "The held-out test set overlaps data/train.csv. Select an independent "
            "test set before reporting metrics."
        )
    return len(overlap)


def check_huggingface_training_overlap(test_frame: pd.DataFrame) -> None:
    """Compare normalized test SQL with the training split listed in the model card."""
    request = urllib.request.Request(
        DOCUMENTED_TRAINING_CSV,
        headers={"User-Agent": "SQLShieldAI-evaluation/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            training_data = pd.read_csv(response, sep=";")
    except (urllib.error.URLError, TimeoutError, pd.errors.ParserError, ValueError) as error:
        print(
            "Hugging Face training-data overlap: not verified "
            f"(could not read the documented training split: {error})."
        )
        return

    if "query" not in training_data.columns:
        print(
            "Hugging Face training-data overlap: not verified "
            "(the downloaded file did not contain a 'query' column)."
        )
        return

    training_keys = {
        normalize_query(query)
        for query in training_data["query"].dropna().astype(str)
        if normalize_query(query)
    }
    overlap = set(test_frame["query_key"]) & training_keys
    print(
        "Normalized exact query overlap with the model-card "
        f"salmane11/SQLShield train split ({len(training_keys)} unique queries): "
        f"{len(overlap)}"
    )
    if overlap:
        print(
            "WARNING: some evaluation queries are present in the published "
            "training split; metrics may be optimistic."
        )
    else:
        print(
            "No case/whitespace-normalized exact matches were found in that "
            "published split. This does not rule out near-duplicates or other "
            "undocumented training data."
        )


def model_output_to_class(label: str) -> int:
    result = normalize_class(label)
    if result is None:
        raise ValueError(
            f"Unrecognized model output label {label!r}; expected SAFE or MALICIOUS."
        )
    return result


def validate_model_labels(id2label: dict[Any, str]) -> None:
    """Check the model's configured label IDs instead of assuming their order."""
    mapping = {
        int(label_id): normalize_class(label)
        for label_id, label in id2label.items()
    }
    if mapping != {0: 0, 1: 1}:
        raise ValueError(
            "Unexpected model label mapping. Expected id2label to map 0 to "
            f"SAFE/benign and 1 to MALICIOUS; received {id2label!r}."
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate salmane11/SQLQueryShield on an independent labeled CSV."
    )
    parser.add_argument(
        "--test-csv",
        type=Path,
        default=DEFAULT_TEST_CSV,
        help="Independent labeled test CSV (default: data/test.csv).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory for confusion_matrix.png and evaluation_results.csv.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=32,
        help="Number of queries sent through the model per batch.",
    )
    args = parser.parse_args()

    if args.batch_size < 1:
        parser.error("--batch-size must be at least 1.")

    try:
        (
            test_frame,
            invalid_query_count,
            invalid_label_count,
            exact_duplicate_rows,
            normalized_duplicate_rows,
        ) = load_test_data(args.test_csv)
        overlap_count = check_local_train_overlap(test_frame)
        check_huggingface_training_overlap(test_frame)

        if torch.cuda.is_available():
            device: int | str = 0
            print("Inference device: CUDA GPU")
        else:
            device = -1
            print("Inference device: CPU")
            torch.set_num_threads(min(torch.get_num_threads(), 4))
            print(f"PyTorch CPU threads: {torch.get_num_threads()}")

        print(f"Loading Hugging Face model: {MODEL_ID}")
        tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
        model = AutoModelForSequenceClassification.from_pretrained(MODEL_ID)
        print(f"Model id2label mapping: {model.config.id2label}")
        validate_model_labels(model.config.id2label)
        print("Verified model mapping: 0 = SAFE/benign, 1 = MALICIOUS")

        classifier = pipeline(
            "text-classification",
            model=model,
            tokenizer=tokenizer,
            device=device,
        )

        max_positions = getattr(model.config, "max_position_embeddings", None)
        max_length = MAX_QUERY_TOKENS
        if isinstance(max_positions, int):
            max_length = min(max_length, max_positions - 2)
        if max_length < 2:
            raise ValueError("The loaded model has an invalid token sequence limit.")

        queries = test_frame["Query"].tolist()
        tokenized = tokenizer(
            queries,
            add_special_tokens=True,
            truncation=True,
            max_length=max_length + 1,
        )
        truncated = [len(input_ids) > max_length for input_ids in tokenized["input_ids"]]
        predictions = []
        progress_interval = max(args.batch_size * 10, 1)
        for start in range(0, len(queries), args.batch_size):
            predictions.extend(
                classifier(
                    queries[start : start + args.batch_size],
                    batch_size=args.batch_size,
                    truncation=True,
                    max_length=max_length,
                )
            )
            completed = min(start + args.batch_size, len(queries))
            if completed % progress_interval < args.batch_size or completed == len(queries):
                print(f"Inference progress: {completed}/{len(queries)}", flush=True)
        predicted_classes = [
            model_output_to_class(result["label"]) for result in predictions
        ]

        actual_classes = test_frame["actual"].tolist()
        matrix = confusion_matrix(actual_classes, predicted_classes, labels=[0, 1])
        accuracy = accuracy_score(actual_classes, predicted_classes)
        precision = precision_score(
            actual_classes, predicted_classes, pos_label=1, zero_division=0
        )
        recall = recall_score(
            actual_classes, predicted_classes, pos_label=1, zero_division=0
        )
        f1 = f1_score(
            actual_classes, predicted_classes, pos_label=1, zero_division=0
        )
        true_negative, false_positive, false_negative, true_positive = (
            int(value) for value in matrix.ravel()
        )

        args.output_dir.mkdir(parents=True, exist_ok=True)
        figure, axis = plt.subplots(figsize=(6, 5))
        image = axis.imshow(matrix, cmap="Blues")
        figure.colorbar(image, ax=axis)
        axis.set(
            xticks=[0, 1],
            yticks=[0, 1],
            xticklabels=["Benign / SAFE", "Malicious"],
            yticklabels=["Benign / SAFE", "Malicious"],
            xlabel="Predicted label",
            ylabel="Actual label",
            title="SQLQueryShield Confusion Matrix",
        )
        threshold = matrix.max() / 2 if matrix.size else 0
        for row in range(2):
            for column in range(2):
                axis.text(
                    column,
                    row,
                    str(matrix[row, column]),
                    ha="center",
                    va="center",
                    color="white" if matrix[row, column] > threshold else "black",
                )
        figure.tight_layout()
        figure.savefig(args.output_dir / "confusion_matrix.png", dpi=200)
        plt.close(figure)

        results = test_frame[["source_row", "Query", "actual"]].copy()
        results["actual_label"] = results["actual"].map(
            {0: "BENIGN/SAFE", 1: "MALICIOUS"}
        )
        results["predicted"] = predicted_classes
        results["predicted_label"] = results["predicted"].map(
            {0: "BENIGN/SAFE", 1: "MALICIOUS"}
        )
        results["confidence"] = [float(result["score"]) for result in predictions]
        results["truncated_to_model_limit"] = truncated
        results["correct"] = results["actual"] == results["predicted"]
        results.to_csv(args.output_dir / "evaluation_results.csv", index=False)

        print(f"\nEligible unique test examples: {len(test_frame)}")
        print(f"Blank/missing queries excluded: {invalid_query_count}")
        print(f"Missing/unknown labels excluded: {invalid_label_count}")
        print(f"Exact duplicate rows removed: {exact_duplicate_rows}")
        print(f"Normalized duplicate rows removed: {normalized_duplicate_rows}")
        print(f"Queries truncated to {max_length} tokens: {sum(truncated)}")
        if overlap_count == 0:
            print("Local train/test exact overlap check: passed.")

        print("\nConfusion matrix (rows = actual, columns = predicted)")
        print("                    Predicted benign   Predicted malicious")
        print(f"Actual benign       {true_negative:16d}   {false_positive:19d}")
        print(f"Actual malicious    {false_negative:16d}   {true_positive:19d}")
        print("\nMetrics (positive class = malicious)")
        print(f"Accuracy:          {accuracy:.4f}")
        print(f"Precision:         {precision:.4f}")
        print(f"Recall:            {recall:.4f}")
        print(f"F1-score:          {f1:.4f}")
        print(f"False positives:   {false_positive}")
        print(f"False negatives:   {false_negative}")
        print(f"Saved confusion matrix: {args.output_dir / 'confusion_matrix.png'}")
        print(f"Saved per-query results: {args.output_dir / 'evaluation_results.csv'}")

        print("\nSeparate manual checks (not included in the metrics):")
        manual_cases = [
            (
                "User's USER_INPUT placeholder query (context-dependent)",
                "SELECT ItemName, ItemDescription FROM Items "
                "WHERE ItemID = 'USER_INPUT';",
            ),
            (
                "Safely parameterized query (placeholder must be bound as a parameter)",
                "SELECT ItemName, ItemDescription FROM Items WHERE ItemID = ?;",
            ),
        ]
        benign_examples = test_frame.loc[test_frame["actual"] == 0, "Query"]
        if not benign_examples.empty:
            manual_cases.insert(
                1,
                ("Labeled benign example from the test set", benign_examples.iloc[0]),
            )
        malicious_examples = test_frame.loc[test_frame["actual"] == 1, "Query"]
        if not malicious_examples.empty:
            manual_cases.append(
                (
                    "Labeled SQL injection example from the test set",
                    malicious_examples.iloc[0],
                )
            )
        manual_outputs = classifier(
            [query for _, query in manual_cases],
            batch_size=args.batch_size,
            truncation=True,
            max_length=max_length,
        )
        for (description, query), output in zip(manual_cases, manual_outputs):
            print(
                f"- {description}: {output['label']} "
                f"(confidence {float(output['score']):.4f})"
            )
            print(f"  {query}")
        print(
            "The USER_INPUT query's actual vulnerability depends on how the "
            "application constructs and executes it. A parameterized placeholder "
            "is safe only when the value is bound separately; the model prediction "
            "alone does not establish execution safety."
        )
        print(
            "\nEvaluation limitation: the model card names salmane11/SQLShield "
            "and also refers to 'SSQLShield'; the published split comparison "
            "checks normalized exact queries only. Unknown, unpublished, or "
            "near-duplicate training examples cannot be ruled out."
        )
        return 0
    except (ImportError, OSError, RuntimeError, ValueError, KeyError) as error:
        print(f"Evaluation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
