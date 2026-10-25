# Model Card: SQL Shield AI Classifier

**Model Name:** SQL Shield AI - Random Forest SQL Injection Detector  
**Selected Artifact:** `models/selected_model.joblib` (SHA-256: `899878dd17652c00e5c9236872c3d66ddcf417a1c8b34f03f027728c3c78f479`)  
**Vectorizer Artifact:** `models/tfidf_vectorizer.joblib` (SHA-256: `c509f6758192792d13d86dafd2f4818f0cc989391437144cd78a67e95ac81586`)  
**Underlying Architecture:** Scikit-Learn `RandomForestClassifier` (100 Trees)  
**Model Date:** October 2026  
**License:** MIT / Internal Project  

---

## 1. Model Overview & Purpose

### 1.1 Model Description
SQL Shield AI is an ensemble-based machine learning security classifier designed to inspect incoming HTTP database queries and identify SQL injection (SQLi) attacks. It transforms text queries into 20,000 character n-gram TF-IDF features and predicts the probability that the query contains an injection exploit.

### 1.2 Intended Use
- **Primary Domain:** Second-line defensive inspection in Web Application Firewalls (WAF) and API security gateways.
- **Operating Modes:**
  - In-line traffic filtering with configurable rejection thresholds (default: `threshold = 0.5`).
  - Asynchronous SIEM telemetry and threat hunting triage.
  - Hybrid scanning: Combines character n-gram inference with regular-expression payload segment extraction to mitigate benign prefix camouflage.

### 1.3 Out-of-Scope & Prohibited Uses
- **Primary Replacement for Parameterized Queries:** Machine learning must **never** replace prepared statements (`PreparedStatement`, ORM parameterized queries).
- **Standalone Security Perimeter:** Should not be deployed without standard perimeter protections (rate limiting, input validation, network firewalls).
- **Arbitrary Binary / Non-SQL Inspection:** Not designed to classify XSS, CSRF, Path Traversal, or binary executable exploits.

---

## 2. Input and Output Specifications

### 2.1 Input Specification
- **Input Type:** Raw text string (`Query`).
- **Feature Pipeline:**
  1. Character-level sliding window analyzer (`analyzer='char'`).
  2. N-gram range: 2 through 5 characters (`ngram_range=(2, 5)`).
  3. Vocabulary size: Exactly 20,000 character n-grams.
  4. L2 unit vector normalization.

### 2.2 Output Specification
- **Continuous Score:** $\hat{p} \in [0.0, 1.0]$, representing the estimated probability that the query contains an SQL injection attack.
- **Binary Decision:**
  - $\hat{y} = 1$ (`SQLi`) if $\hat{p} \ge \text{threshold}$ (default `0.5`).
  - $\hat{y} = 0$ (`Legitimate`) if $\hat{p} < \text{threshold}$.

---

## 3. Training Data & Methodology

### 3.1 Dataset Provenance
- **Raw Dataset:** `data/Modified_SQL_Dataset.csv` (30,919 queries).
- **Cleaned Dataset:** `data/clean_dataset.csv` (30,814 queries).
- **Partitions:**
  - **Train:** 21,569 queries (13,652 Legitimate, 7,917 SQLi; 36.71% prevalence).
  - **Validation:** 4,622 queries (2,926 Legitimate, 1,696 SQLi; 36.69% prevalence).
  - **Test:** 4,623 queries (2,926 Legitimate, 1,697 SQLi; 36.71% prevalence).
- **Leakage Integrity:** Verified disjoint across all three partitions ($|\text{Train} \cap \text{Test}| = 0$).

### 3.2 Hyperparameters & Configuration
- `n_estimators`: 100
- `criterion`: `'gini'`
- `max_depth`: `None` (trees grown until leaves are pure)
- `max_features`: `'sqrt'` ($\sqrt{20,000} \approx 141$ features considered per split)
- `min_samples_split`: 2
- `min_samples_leaf`: 1
- `bootstrap`: `True`
- `random_state`: 42
- `n_jobs`: -1

---

## 4. Evaluated Performance Benchmarks

### Verified Held-Out Test Set Performance ($N = 4,623$)
- **Accuracy:** `99.61%` (4,605 / 4,623)
- **Precision:** `99.82%` (1,682 / 1,685)
- **Recall (Sensitivity):** `99.12%` (1,682 / 1,697)
- **F1-Score:** `99.47%`
- **Specificity:** `99.90%` (2,923 / 2,926)
- **False Positive Rate (FPR):** `0.10%` (3 false alarms out of 2,926 legitimate queries)
- **False Negative Rate (FNR):** `0.88%` (15 missed attacks out of 1,697 attacks)
- **ROC-AUC:** `0.9994`
- **PR-AUC:** `0.9993`

---

## 5. Security Vulnerabilities, Limitations & Operational Risks

### 5.1 Benign Prefix Camouflage (Token Dilution)
- **Vulnerability:** When a short injection payload (e.g. `OR 1=1 --`) is concatenated to a long, legitimate query (e.g. 500+ characters), L2 normalization dilutes the TF-IDF weights of the attack n-grams.
- **Empirical Test:** Raw Random Forest classified a 250-character query containing `OR 1=1 --` as benign (score `0.42`).
- **Mitigation:** The application runtime in [ml/predict.py](file:///c:/sql-shield-ai/ml/predict.py) applies regex sub-clause segmentation (`extract_segments`) before scoring, raising the detection score to `0.927`.

### 5.2 Hex-Encoded Payload Evasion
- **Vulnerability:** Hexadecimal literals (e.g. `0x61646d696e` representing `'admin'`, or `0x7761697466...` representing `WAITFOR DELAY`) evade detection because the character n-gram vocabulary does not decode hex byte streams.
- **Empirical Test:** `SELECT * FROM users WHERE username = 0x61646d696e` resulted in score `0.18` (False Negative).

### 5.3 Multilingual & Non-English False Positives
- **Vulnerability:** Natural language text submitted into input fields can trigger false alarms if character subsequences collide with SQL keywords.
- **Empirical Test:** Catalan location string `"fogars de la selva"` contains `' sel'`, producing a false positive on XGBoost (score `0.546`).

---

## 6. Maintenance & Deployment Recommendations

1. **Threshold Tuning:**  
   In mission-critical gateways, reduce the operating threshold from `0.50` to `0.35` to minimize False Negatives.
2. **Pre-Inference Hex & URL Normalization:**  
   Implement an automated normalization layer that hex-decodes and URL-decodes inputs before character n-gram extraction.
3. **Continuous Template Monitoring:**  
   Periodically sample production queries and monitor for distribution drift or new database dialect keywords.
