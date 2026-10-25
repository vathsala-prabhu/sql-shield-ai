# Reproducibility Guide & Verification Runbook: SQL Shield AI

**Auditor Role:** Senior Machine Learning Engineer & ML Security Auditor  
**Date:** October 25, 2026  
**Execution Environment:** Windows 11 / PowerShell  
**Python Runtime:** Python 3.13.0 (Virtual Environment at `.\venv\`)

---

## 1. Environment & Dependency Specifications

To achieve exact numerical reproducibility of evaluation metrics and artifact inspections, the following environment configuration is required:

### 1.1 Python and Core Packages
```text
Python: 3.13.0
scikit-learn: 1.9.1
xgboost: 3.4.1
joblib: 1.6.0
pandas: 3.0.6
numpy: 2.5.4
matplotlib: 3.10.8
```

### 1.2 Virtual Environment Setup Command
If recreating the environment from scratch:
```powershell
# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Install exact requirements
pip install -r requirements.txt
```

---

## 2. Artifact Integrity Verification (Hashes & Sizes)

Before running any inspection, verify that project artifacts have not been modified or corrupted by computing their SHA-256 digests.

| Artifact Path | Size (Bytes) | Expected SHA-256 Digest |
| :--- | :---: | :--- |
| `models/metrics.json` | 1,355 | `86bc99dfef7f5b1e05c0393a50c92cca3ef7a19b1fa7a94e2bd5abae45cf03f7` |
| `models/val_metrics.json` | 558 | `857719474be3dd16b925eba08549a7a8668a606fedb5a5bee67b67068d394b62` |
| `models/random_forest.joblib` | 7,655,993 | `e6fd89ef25a7b3016ff8936e736faf9176662c6800310fc9da73362f1b820cc3` |
| `models/xgboost.joblib` | 147,444 | `d0ed4248c3a15455e9048700164fef249023b22a848bc991f82e1f7033bccfd3` |
| `models/selected_model.joblib` | 7,656,249 | `899878dd17652c00e5c9236872c3d66ddcf417a1c8b34f03f027728c3c78f479` |
| `models/tfidf_vectorizer.joblib` | 679,502 | `c509f6758192792d13d86dafd2f4818f0cc989391437144cd78a67e95ac81586` |
| `data/Modified_SQL_Dataset.csv` | 2,284,050 | `60af1d160dcc5c3f61440dc8f0c019e8898243951e283402857c10294c6f5cc5` |
| `data/clean_dataset.csv` | 2,542,565 | `daa19f70648361a342114a905e5b0854089af69d707e4b1b940b985018e18a45` |
| `data/train.csv` | 1,775,605 | `9dd24feaeabc0082a7bc16b9d7085c7cb67bd5ae0d47d57312783ec75ba4a5ec` |
| `data/val.csv` | 390,165 | `93cae2a51c2db4f591d81c4154cc4493bfd3a4436bca77dea050a616a3d28c85` |
| `data/test.csv` | 376,825 | `9674b98fde7b7a953611697be42c16430ca4c785e1e277a19879e96ace293992` |

### Hash Verification Command
Run the provided Phase A inventory script to check digests automatically:
```powershell
.\venv\Scripts\python.exe audit_report/scripts/phase_a_inventory.py
```

---

## 3. Step-by-Step Audit Execution Commands

All audit inspection scripts are strictly non-destructive. They read from `data/` and `models/` and output all reports and intermediate results to `audit_report/`:

### Step 1: Run Full Data Leakage, Metric Recomputation & Feature Audit
```powershell
.\venv\Scripts\python.exe audit_report/scripts/comprehensive_audit.py
```
- **Inputs:** `data/train.csv`, `data/val.csv`, `data/test.csv`, `models/*.joblib`
- **Outputs Created:**
  - `audit_report/results/audit_metrics_and_checks.json`
  - `audit_report/results/rf_all_feature_importances.csv`

### Step 2: Run Robustness, Evasion & Template Overlap Tests
```powershell
.\venv\Scripts\python.exe audit_report/scripts/robustness_and_evasion_test.py
```
- **Inputs:** Serialized models, `ml/predict.py`, partition files.
- **Outputs Created:**
  - `audit_report/results/robustness_and_evasion_results.json`

### Step 3: Run Detailed Error & Failure Mode Inspection
```powershell
.\venv\Scripts\python.exe audit_report/scripts/inspect_errors.py
```
- **Inputs:** `data/test.csv`, models.
- **Outputs Created:**
  - `audit_report/results/test_error_analysis.json`

---

## 4. Re-running the Original Training Pipeline (Reference Only)

> [!CAUTION]
> In Audit Mode, the original models should not be overwritten. If retraining is explicitly requested in the future, execute the entry points in the following sequence:

```powershell
# 1. Clean raw dataset and eliminate contradictory queries
.\venv\Scripts\python.exe ml/preprocess.py

# 2. Perform stratified 70/15/15 partitioning (random_state=42)
.\venv\Scripts\python.exe ml/split_data.py

# 3. Fit TF-IDF character vectorizer on train.csv only
.\venv\Scripts\python.exe ml/features.py

# 4. Train Random Forest and XGBoost classifiers; save val_metrics.json
.\venv\Scripts\python.exe ml/train.py

# 5. Evaluate on held-out test.csv; select winning model based on val recall
.\venv\Scripts\python.exe ml/evaluate.py
```

---

## 5. Random Seeds and Determinism

The pipeline enforces deterministic reproducibility across all stochastic operations:
- **`ml/split_data.py`:** `train_test_split(..., random_state=42)`
- **`ml/train.py`:**
  - `RandomForestClassifier(..., random_state=42)`
  - `XGBClassifier(..., random_state=42)`
- **Parallelism Note:**
  - Both classifiers are initialized with `n_jobs=-1`. Under identical hardware and Scikit-Learn / XGBoost versions, results remain bit-for-bit identical. Across different CPU architectures or major BLAS updates, minimal floating-point variance in XGBoost leaf weights may occur.
