# Dataset Documentation: SQL SHIELD AI

## 1. Dataset Provenance & Overview
- **Raw Dataset Source:** `Modified_SQL_Dataset.csv`
- **Total Initial Rows:** 30,919 queries
- **Initial Columns:** `Query` (SQL text string), `Label` (0 = Legitimate, 1 = SQLi)
- **Initial Class Distribution:**
  - Label 0 (Legitimate): 19,537 samples (63.2%)
  - Label 1 (SQL Injection): 11,382 samples (36.8%)
- **Missing Values:** 0 null rows found in the raw file.
- **Exact Duplicate Rows:** 12 duplicate samples.

## 2. Preprocessing & Deduplication (`ml/preprocess.py`)
1. **Validation & Trimming:** Rows with blank or whitespace-only inputs are eliminated.
2. **Key Normalization:** Whitespace runs are collapsed to single spaces (`\s+` -> ` `) and normalized to lowercase to detect near-duplicates while preserving SQL punctuation, comments (`--`, `/*`, `#`), operators (`=`, `<`, `>`), and single/double quotes.
3. **Contradiction Removal:** Queries with conflicting labels (same query marked as both 0 and 1) are flagged and purged to prevent corrupting gradient updates.
4. **Deduplication:** Near-duplicate queries are removed to prevent data leakage between training and testing partitions.
5. **Clean Dataset:** Saved as `clean_dataset.csv` with **30,814 unique, validated rows**.

## 3. Stratified Partitioning (`ml/split_data.py`)
To prevent data snooping and ensure class balance across splits:
- **Train Set (`train.csv`):** 70% (21,569 rows) — used exclusively for fitting the TF-IDF vectorizer and training classifiers.
- **Validation Set (`val.csv`):** 15% (4,622 rows) — used exclusively for hyperparameter tuning and model selection.
- **Test Set (`test.csv`):** 15% (4,623 rows) — held-out unseen partition used strictly for final reported benchmark metrics.

## 4. Feature Representation (`ml/features.py`)
- **Analyzer:** Character n-grams (`analyzer='char'`)
- **N-gram Range:** (2, 5) — capturing 2-char, 3-char, 4-char, and 5-char subsequences
- **Vocabulary Size:** 20,000 maximum features
- **Fitting Guarantee:** Fitted **only** on `train.csv`; `val.csv` and `test.csv` are transformed using the fitted vocabulary.
