# Technical Data Leakage Audit Report: SQL Shield AI

**Auditor Role:** Senior Machine Learning Engineer & ML Security Auditor  
**Date:** October 25, 2026  
**Repository:** `c:\sql-shield-ai`  
**Target Artifacts Inspected:**  
- `models/tfidf_vectorizer.joblib` (SHA-256: `c509f6758192792d13d86dafd2f4818f0cc989391437144cd78a67e95ac81586`)
- `models/random_forest.joblib` (SHA-256: `e6fd89ef25a7b3016ff8936e736faf9176662c6800310fc9da73362f1b820cc3`)
- `models/xgboost.joblib` (SHA-256: `d0ed4248c3a15455e9048700164fef249023b22a848bc991f82e1f7033bccfd3`)
- `models/selected_model.joblib` (SHA-256: `899878dd17652c00e5c9236872c3d66ddcf417a1c8b34f03f027728c3c78f479`)
- `models/val_metrics.json` (SHA-256: `857719474be3dd16b925eba08549a7a8668a606fedb5a5bee67b67068d394b62`)
- `models/metrics.json` (SHA-256: `86bc99dfef7f5b1e05c0393a50c92cca3ef7a19b1fa7a94e2bd5abae45cf03f7`)

---

## 1. Executive Summary of Leakage Audit

A thorough static and dynamic audit was conducted on the complete data pipeline and trained artifacts of SQL Shield AI.

| Leakage Category | Audit Status | Risk / Severity | Key Verified Evidence |
| :--- | :---: | :---: | :--- |
| **B1. Train/Val/Test Separation** | **PASS** | Negligible | Two-stage stratified split performed on cleaned dataset. Exact record overlap is `0`. Normalized text overlap is `0`. |
| **B2. TF-IDF & Preprocessing Leakage** | **PASS** | Negligible | Vectorizer vocabulary and IDF weights match `train.csv` fit with 0 symmetric difference. No test/validation vocabulary snooping occurred. |
| **B3. Exact & Near-Duplicate Leakage** | **PASS** | Low | Lowercase and whitespace deduplication performed prior to splitting. Conflicting labels (`#name?` and `1`) purged. |
| **B3-Ext. Syntactic Template Overlap** | **WARNING** | Moderate | 250 structural query templates overlap between train and test. While individual payloads differ, template similarity inflates raw test scores. |
| **B4. Label / Target Leakage** | **PASS** | Negligible | Features are extracted strictly from the SQL text string (`Query`). No IDs, targets, or auxiliary metadata columns enter the vectorizer. |
| **B5. Test Set Reuse & Snooping** | **PASS** | Negligible | Model selection rule in `ml/evaluate.py` relies exclusively on validation metrics (`recall` then `f1`). Test set evaluated only after selection. |
| **B6. Feature Dimensionality Consistency**| **PASS** | Negligible | 20,000 character n-gram features preserved identically across vectorizer, Random Forest, and XGBoost. |

---

## 2. Test B1: Train / Validation / Test Separation Audit

### 2.1 Methodology & Code Path
The splitting sequence was traced in [ml/split_data.py](file:///c:/sql-shield-ai/ml/split_data.py#L7-L18):
```python
# First split: 70% train, 30% temporary
train, temp = train_test_split(
    df, test_size=0.30, random_state=42, stratify=df["y"]
)
# Second split: temporary -> 15% validation, 15% test
val, test = train_test_split(
    temp, test_size=0.50, random_state=42, stratify=temp["y"]
)
```

### 2.2 Empirical Verification
Using [audit_report/scripts/comprehensive_audit.py](file:///c:/sql-shield-ai/audit_report/scripts/comprehensive_audit.py):
1. **Total Samples:**
   - Input Clean Dataset: $N = 30,814$
   - Train partition: $N_{\text{train}} = 21,569$ ($70.0006\%$)
   - Validation partition: $N_{\text{val}} = 4,622$ ($14.9997\%$)
   - Test partition: $N_{\text{test}} = 4,623$ ($14.9997\%$)
   - Sum: $21,569 + 4,622 + 4,623 = 30,814$ (Exact balance, 0 lost records).
2. **Stratification Consistency:**
   - Train SQLi ratio: $\frac{7,917}{21,569} = 36.705\%$
   - Validation SQLi ratio: $\frac{1,696}{4,622} = 36.694\%$
   - Test SQLi ratio: $\frac{1,697}{4,623} = 36.708\%$
   - Clean Dataset SQLi ratio: $\frac{11,310}{30,814} = 36.704\%$
   - Maximum drift across splits: $< 0.014\%$ (Stratification is exact).
3. **Set Intersection Check:**
   - Exact string matching:
     - $|\text{Train} \cap \text{Val}| = 0$
     - $|\text{Train} \cap \text{Test}| = 0$
     - $|\text{Val} \cap \text{Test}| = 0$
   - Normalized string matching (`lower()` and `\s+ -> ' '`):
     - $|\text{Train}_{\text{norm}} \cap \text{Val}_{\text{norm}}| = 0$
     - $|\text{Train}_{\text{norm}} \cap \text{Test}_{\text{norm}}| = 0$
     - $|\text{Val}_{\text{norm}} \cap \text{Test}_{\text{norm}}| = 0$

**Status:** `PASS`

---

## 3. Test B2: TF-IDF Preprocessing & Feature Leakage

### 3.1 Mechanism of Potential Leakage
If `TfidfVectorizer.fit()` or `fit_transform()` is executed on the combined dataset prior to splitting, or if validation/test queries contribute to document frequency counts ($DF_t$), inverse document frequency weights ($IDF_t = \ln\frac{1+N}{1+DF_t} + 1$), or the 20,000 top vocabulary tokens, information leaks from the test set into the model's feature representation.

### 3.2 Evidence from Code
In [ml/features.py](file:///c:/sql-shield-ai/ml/features.py#L9-L20):
```python
vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(2, 5),
    max_features=20000,
)
# Fit on TRAINING data only, to prevent data leakage
X_train = vectorizer.fit_transform(train["Query"].astype(str))
X_val = vectorizer.transform(val["Query"].astype(str))
X_test = vectorizer.transform(test["Query"].astype(str))
joblib.dump(vectorizer, "models/tfidf_vectorizer.joblib")
```

### 3.3 Empirical Artifact Verification
We independently fitted two reference vectorizers on identical parameters:
1. `vectorizer_train_only`: Fitted strictly on `data/train.csv` (21,569 rows).
2. `vectorizer_full_clean`: Fitted on `data/clean_dataset.csv` (30,814 rows).

**Empirical Results:**
- Saved artifact vocabulary size: `20,000`
- Symmetric difference between saved vocabulary and `vectorizer_train_only`: **0 tokens**
- Difference between saved vocabulary and `vectorizer_full_clean`: **1,666 tokens**
- Maximum absolute difference in IDF weights between saved artifact and `vectorizer_train_only`: **0.000000000000e+00** (`np.allclose == True`)
- Maximum absolute difference in IDF weights between saved artifact and `vectorizer_full_clean`: Significant divergence (`np.allclose == False`)

**Conclusion:** The artifact `tfidf_vectorizer.joblib` was unequivocally fitted **only** on the training partition.

**Status:** `PASS`

---

## 4. Test B3: Duplicate and Near-Duplicate Leakage

### 4.1 Raw Dataset Duplicates and Contradictions
In [ml/preprocess.py](file:///c:/sql-shield-ai/ml/preprocess.py#L14-L27), the raw dataset `data/Modified_SQL_Dataset.csv` (30,919 rows) was inspected:
- Raw exact duplicate rows: 12
- Raw exact duplicate queries: 14
- Near-duplicates (ignoring case and whitespace runs): 103 queries
- Conflicting queries (same normalized string marked as both Legitimate 0 and SQLi 1): **2 queries**
  - Query 1: `"#name?"`
  - Query 2: `"1"`

### 4.2 Handling of Contradictions
Lines 19–23 of `ml/preprocess.py` compute:
```python
nunique = df.groupby("key")["y"].nunique()
bad_keys = nunique[nunique > 1].index
df = df[~df["key"].isin(bad_keys)]
df = df.drop_duplicates(subset="key")
```
Both conflicting keys (`#name?` and `1`) were completely purged. Neither key appears in `clean_dataset.csv`, `train.csv`, `val.csv`, or `test.csv`.

### 4.3 Syntactic Template Overlap Investigation
While exact and whitespace-normalized queries were deduplicated, real-world SQL injection datasets often contain repeated query templates where only numerical IDs or literal strings differ.

We performed a generalized template analysis by replacing:
- String literals (`'...'` or `"..."`) $\rightarrow$ `<STR>`
- Numeric literals (`\b\d+\b`) $\rightarrow$ `<NUM>`
- Collapsing whitespace.

**Results of Template Clustering:**
- Unique templates in Train: 18,836
- Unique templates in Validation: 4,158
- Unique templates in Test: 4,194
- **Shared templates between Train and Validation:** 267 templates
- **Shared templates between Train and Test:** 250 templates
- **Shared templates between Validation and Test:** 113 templates

**Impact Assessment:**  
The presence of 250 shared syntactic templates between train and test is not technical data leakage (records are distinct queries), but it explains why the model achieves 99.6% accuracy on the test set. The test partition evaluates generalization across similar query structures rather than completely novel database schemas.

**Status:** `PASS` (Record-level) / `WARNING` (Template-level)

---

## 5. Test B4: Label and Target Leakage

### 5.1 Input Schema Audit
Inspected `ml/features.py`, `ml/train.py`, and `ml/predict.py`.
- Features supplied to `vectorizer.fit_transform()`: strictly `df["Query"].astype(str)`.
- No record identifiers, timestamps, database metadata, table prefixes, or target labels are concatenated with the input text.
- Feature names in `vectorizer.get_feature_names_out()` are character sequences between lengths 2 and 5 (e.g. `'1 '`, `' = '`, `' and '`, `'--'`).

**Status:** `PASS`

---

## 6. Test B5: Test Set Snooping and Decision Leakage

### 6.1 Evaluation and Selection Sequence
In [ml/evaluate.py](file:///c:/sql-shield-ai/ml/evaluate.py#L43-L57):
```python
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
```
- The selection algorithm operates strictly on `models/val_metrics.json`.
- The held-out test set `data/test.csv` is loaded and evaluated **after** the selection decision is made.
- Test metrics were never back-propagated to tune thresholds, adjust hyperparameters, or re-select classifiers.

**Status:** `PASS`

---

## 7. Leakage Test Suite Matrix

| Check ID | Audit Test Description | Method | Input Source | Result | Severity |
| :---: | :--- | :--- | :--- | :---: | :---: |
| **L-01** | Split ID & Record Disjointness | Set intersection of query strings | `train.csv`, `val.csv`, `test.csv` | **PASS** | None |
| **L-02** | Normalized Query Disjointness | Case-insensitive & space-collapsed set intersection | `train.csv`, `val.csv`, `test.csv` | **PASS** | None |
| **L-03** | Global TF-IDF Vocabulary Leak | Symmetric difference against fresh train-fit | `tfidf_vectorizer.joblib`, `train.csv` | **PASS** | None |
| **L-04** | Global IDF Weight Snooping | `np.allclose()` check on IDF weights | `tfidf_vectorizer.joblib`, `train.csv` | **PASS** | None |
| **L-05** | Conflicting Label Contamination | Multi-label grouping on normalized query | `clean_dataset.csv`, `Modified_SQL_Dataset.csv` | **PASS** | None |
| **L-06** | Label / Column Leakage in Inputs | Dataframe column tracing | `features.py`, `train.py` | **PASS** | None |
| **L-07** | Test Set Model Selection Leakage | AST & control-flow analysis of `ml/evaluate.py` | `ml/evaluate.py` | **PASS** | None |
| **L-08** | Template Syntactic Overlap | Abstract query skeleton clustering (`<STR>`, `<NUM>`) | `train.csv`, `test.csv` | **WARNING** | Moderate |
| **L-09** | Feature Dimension Consistency | Attribute `n_features_in_` vs vectorizer length | `random_forest.joblib`, `xgboost.joblib` | **PASS** | None |

---

## 8. Remediation and Future Safeguards

1. **Grouped / Schema-Based Splitting:**  
   Future iterations should group queries by database application or schema source so that all variations of a query template belong exclusively to either train, validation, or test.
2. **Pipeline Encapsulation:**  
   While `ml/features.py` and `ml/train.py` correctly fitted the vectorizer on train only, refactoring into an official `sklearn.pipeline.Pipeline` or `imblearn.pipeline.Pipeline` is recommended to prevent accidental regression in future training runs.
