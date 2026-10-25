# Model Validation, Metric Recomputation, and Performance Benchmark: SQL Shield AI

**Auditor Role:** Senior Machine Learning Engineer & ML Security Auditor  
**Date:** October 25, 2026  
**Files Audited:**
- `models/val_metrics.json` (SHA-256: `857719474be3dd16b925eba08549a7a8668a606fedb5a5bee67b67068d394b62`)
- `models/metrics.json` (SHA-256: `86bc99dfef7f5b1e05c0393a50c92cca3ef7a19b1fa7a94e2bd5abae45cf03f7`)
- `evaluation_results/random_forest_confusion_matrix.png`
- `evaluation_results/xgboost_confusion_matrix.png`

---

## 1. Executive Summary & Metric Verification

All reported validation and test metrics were independently recalculated directly from raw test data (`data/test.csv`, $N=4,623$) and validation data (`data/val.csv`, $N=4,622$) using the serialized models.

**Audit Verification Result:**
- **Validation Metrics Match:** 100% precision match across all metrics and confusion matrix cells.
- **Test Metrics Match:** 100% precision match across all metrics and confusion matrix cells.
- **Model Selection Integrity:** The code in [ml/evaluate.py](file:///c:/sql-shield-ai/ml/evaluate.py#L47-L57) strictly executed selection on validation recall and F1-score. The test set was held out and never used during model selection.

---

## 2. Confusion Matrix Definitions in SQL Injection Detection

In this security system, the positive class represents an attack ($y = 1$: SQL Injection) and the negative class represents benign traffic ($y = 0$: Legitimate Query).

```
                      PREDICTED
                 Legitimate (0)    SQL Injection (1)
ACTUAL
Legitimate (0)        TN                 FP
SQL Injection (1)     FN                 TP
```

### Practical Cybersecurity Consequences:
- **True Positive (TP):** An active SQL injection attack is correctly identified and intercepted. Database security is maintained.
- **True Negative (TN):** A benign application query passes through without interruption. Normal business operations proceed smoothly.
- **False Positive (FP) [Type I Error]:** A legitimate user or query is erroneously classified as malicious.
  - *Impact:* Denial of service for valid users, broken application workflows, developer friction, alert fatigue for SOC analysts.
- **False Negative (FN) [Type II Error]:** A malicious SQL injection payload evades the classifier and reaches the database engine.
  - *Impact:* **Catastrophic breach.** Remote code execution, database exfiltration, unauthorized admin creation, data corruption.
  - *Design Priority:* In security gateways, minimizing False Negatives (maximizing Recall) takes paramount precedence over minimizing False Positives.

---

## 3. Mathematical Metric Formulations

### 3.1 Accuracy
\[
\text{Accuracy} = \frac{TP + TN}{TP + TN + FP + FN}
\]
Measures overall correctness. *Limitation:* Can be misleading under class imbalance.

### 3.2 Precision (Positive Predictive Value)
\[
\text{Precision} = \frac{TP}{TP + FP}
\]
The proportion of queries flagged as SQL injection that were genuinely malicious. Measures trustworthiness of alerts.

### 3.3 Recall (True Positive Rate / Sensitivity)
\[
\text{Recall} = \frac{TP}{TP + FN}
\]
The proportion of actual SQL injection attempts successfully detected. Essential metric for breach prevention.

### 3.4 F1-Score (Harmonic Mean)
\[
F_1 = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}} = \frac{2TP}{2TP + FP + FN}
\]
Balances Precision and Recall into a single scalar metric.

### 3.5 Specificity (True Negative Rate)
\[
\text{Specificity} = \frac{TN}{TN + FP}
\]
The proportion of legitimate queries correctly identified as benign.

### 3.6 False Alarm Rates
- **False Positive Rate (FPR / Fall-out):** $\text{FPR} = \frac{FP}{FP + TN} = 1 - \text{Specificity}$
- **False Negative Rate (FNR / Miss Rate):** $\text{FNR} = \frac{FN}{FN + TP} = 1 - \text{Recall}$

---

## 4. Recomputed Validation Performance ($N = 4,622$)

The validation dataset contains $2,926$ Legitimate queries ($63.31\%$) and $1,696$ SQL Injection queries ($36.69\%$).

| Metric | Random Forest (Verified) | XGBoost (Verified) | Difference ($\Delta = \text{RF} - \text{XGB}$) |
| :--- | :---: | :---: | :---: |
| **True Negatives (TN)** | 2,922 | 2,922 | 0 |
| **False Positives (FP)** | 4 | 4 | 0 |
| **False Negatives (FN)** | **6** | 14 | **-8 (Fewer Breaches)** |
| **True Positives (TP)** | **1,690** | 1,682 | **+8 (More Attacks Caught)** |
| **Accuracy** | **0.997836** (99.78%) | 0.996106 (99.61%) | +0.173% |
| **Precision** | **0.997639** (99.76%) | 0.997628 (99.76%) | +0.001% |
| **Recall (Sensitivity)** | **0.996462** (99.65%) | 0.991745 (99.17%) | **+0.472%** |
| **F1-Score** | **0.997050** (99.71%) | 0.994678 (99.47%) | **+0.237%** |
| **Specificity** | 0.998633 (99.86%) | 0.998633 (99.86%) | 0.000% |
| **False Positive Rate (FPR)**| 0.001367 (0.137%) | 0.001367 (0.137%) | 0.000% |
| **False Negative Rate (FNR)**| **0.003538** (0.354%) | 0.008255 (0.825%) | **-0.472%** |
| **ROC-AUC** | 0.999546 | **0.999603** | -0.000057 |
| **PR-AUC** | **0.999515** | 0.999448 | +0.000067 |

---

## 5. Recomputed Held-Out Test Performance ($N = 4,623$)

The test dataset contains $2,926$ Legitimate queries ($63.29\%$) and $1,697$ SQL Injection queries ($36.71\%$).

| Metric | Random Forest (Selected Model) | XGBoost Classifier | Audit Verification Status |
| :--- | :---: | :---: | :---: |
| **True Negatives (TN)** | 2,923 | 2,925 | Verified exact match |
| **False Positives (FP)** | 3 | 1 | Verified exact match |
| **False Negatives (FN)** | **15** | 21 | Verified exact match |
| **True Positives (TP)** | **1,682** | 1,676 | Verified exact match |
| **Accuracy** | **0.996106** (99.61%) | 0.995241 (99.52%) | Recalculated & Verified |
| **Precision** | 0.998220 (99.82%) | **0.999404** (99.94%) | Recalculated & Verified |
| **Recall (Sensitivity)** | **0.991161** (99.12%) | 0.987625 (98.76%) | Recalculated & Verified |
| **F1-Score** | **0.994678** (99.47%) | 0.993480 (99.35%) | Recalculated & Verified |
| **Specificity** | 0.998975 (99.90%) | **0.999658** (99.97%) | Recalculated & Verified |
| **False Positive Rate (FPR)**| 0.001025 (0.103%) | **0.000342** (0.034%) | Recalculated & Verified |
| **False Negative Rate (FNR)**| **0.008839** (0.884%) | 0.012375 (1.238%) | Recalculated & Verified |
| **ROC-AUC** | **0.999448** | 0.999276 | Recalculated & Verified |
| **PR-AUC** | **0.999285** | 0.998988 | Recalculated & Verified |

---

## 6. Model Selection Rule Audit

### 6.1 Formal Selection Criteria
The project configuration mandates:
> **Selection Rule:** Highest SQL injection recall on validation, followed by F1-score as tiebreaker.

### 6.2 Code-Level Execution Trace
In [ml/evaluate.py](file:///c:/sql-shield-ai/ml/evaluate.py#L49-L55):
```python
selected = max(
    val,
    key=lambda name: (
        val[name]["recall"],
        val[name]["f1"]
    )
)
```
- **Validation Recall:**
  - Random Forest: `0.996462`
  - XGBoost: `0.991745`
  - Decision: $\text{Recall}_{\text{RF}} > \text{Recall}_{\text{XGB}}$
- **Validation F1-score:**
  - Random Forest: `0.997050`
  - XGBoost: `0.994678`

**Audit Verification:**  
Random Forest was selected unambiguously based strictly on validation performance. The test set was untouched during selection.

---

## 7. Comparative Generalization Analysis

```
                    VALIDATION vs TEST GENERALIZATION GAP
                    
  Metric         Random Forest (Val -> Test)       XGBoost (Val -> Test)
  Accuracy       0.9978 -> 0.9961  (-0.17%)       0.9961 -> 0.9952  (-0.09%)
  Precision      0.9976 -> 0.9982  (+0.06%)       0.9976 -> 0.9994  (+0.18%)
  Recall         0.9965 -> 0.9912  (-0.53%)       0.9917 -> 0.9876  (-0.41%)
  F1-Score       0.9971 -> 0.9947  (-0.24%)       0.9947 -> 0.9935  (-0.12%)
```

### Observations:
1. **Minimal Generalization Gap:**  
   The drop in F1-score from validation to test is only $0.24\%$ for Random Forest and $0.12\%$ for XGBoost. This demonstrates strong stability across the random partitions.
2. **Trade-off Profile:**
   - **Random Forest:** Maximizes attack recall ($99.12\%$ on test), allowing 15 False Negatives and 3 False Positives.
   - **XGBoost:** Maximizes precision ($99.94\%$ on test), with only 1 False Positive out of 2,926 legitimate queries, but allows 21 False Negatives.
3. **Security Rationale for Selection:**  
   In Web Application Firewall (WAF) deployment, catching 6 additional real attacks (Random Forest FN=15 vs XGBoost FN=21) is worth accepting 2 additional false alarms over 4,623 queries. Thus, the selection of Random Forest aligns with defensive cybersecurity best practices.
