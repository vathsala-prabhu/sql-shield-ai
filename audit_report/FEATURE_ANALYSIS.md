# Comprehensive Feature Engineering and Interpretability Analysis: SQL Shield AI

**Auditor Role:** Senior Machine Learning Engineer & Security ML Auditor  
**Date:** October 25, 2026  
**Artifact Inspected:** `models/tfidf_vectorizer.joblib` (SHA-256: `c509f6758192792d13d86dafd2f4818f0cc989391437144cd78a67e95ac81586`)  
**Trained Models Analyzed:**
- `models/random_forest.joblib` (Gini Impurity Feature Importance)
- `models/xgboost.joblib` (Split Gain Feature Importance)

---

## 1. Raw Input Schema & Preprocessing Pipeline

### 1.1 Input Representation
The model operates on a single raw text field:
- **Column Name:** `Query`
- **Data Type:** String (`object` / `str`)
- **Domain:** SQL query strings, HTTP request parameter values, URL-decoded fragments, and synthetic attack vectors.
- **Auxiliary Columns:** None. (The dataset contains `Label`/`y` for supervised learning, which is excluded from model inputs).

### 1.2 Transformation Sequence
1. **Validation & Casting:** Any null or empty inputs are eliminated (`df.dropna()`, `df["Query"].astype(str)`).
2. **Whitespace Normalization (Deduplication Only):** In `ml/preprocess.py`, consecutive whitespace characters are collapsed (`\s+ -> ' '`) solely to generate a deduplication key (`key`). The actual stored query preserves original spacing and casing for training.
3. **Vectorizer Preprocessing:** The fitted `TfidfVectorizer` automatically converts all characters to lowercase prior to n-gram generation (`lowercase=True`).

---

## 2. Verified TF-IDF Configuration

The configuration extracted directly from `models/tfidf_vectorizer.joblib` was verified:

| Parameter | Saved Artifact Value | Verified Implementation Details |
| :--- | :--- | :--- |
| **Analyzer** | `'char'` | Character-level sliding window (character n-grams) |
| **N-gram Range** | `(2, 5)` | Evaluates sub-tokens of length 2, 3, 4, and 5 |
| **Max Features** | `20,000` | Top 20,000 character n-grams by corpus term frequency |
| **Min Document Frequency (`min_df`)** | `1` | Retains all n-grams appearing in $\ge 1$ training document |
| **Max Document Frequency (`max_df`)** | `1.0` | No upper bound exclusion for high-frequency n-grams |
| **Lowercase** | `True` | Case-insensitive tokenization |
| **Norm** | `'l2'` | Euclidean unit vector normalization: $\sum x_i^2 = 1$ |
| **Use IDF** | `True` | Inverse Document Frequency weighting applied |
| **Smooth IDF** | `True` | Adds 1 to document counts: prevents division by zero |
| **Sublinear TF** | `False` | Standard raw term count frequency: $TF(t, d) = f_{t,d}$ |

---

## 3. Mathematical Formulation of TF-IDF

For a character n-gram token $t$ in a SQL query document $d$, within a training corpus of $N = 21,569$ documents:

### 3.1 Term Frequency (TF)
\[
\operatorname{TF}(t, d) = f_{t, d}
\]
where $f_{t, d}$ is the raw count of occurrences of character sequence $t$ in document $d$.

### 3.2 Inverse Document Frequency (IDF) with Smoothing
Because `smooth_idf=True` in scikit-learn:
\[
\operatorname{IDF}(t) = \ln\left( \frac{1 + N}{1 + \operatorname{DF}(t)} \right) + 1
\]
where $\operatorname{DF}(t)$ is the number of training documents containing the character n-gram $t$.

### 3.3 Raw TF-IDF Weight
\[
\operatorname{TFIDF}_{\text{raw}}(t, d) = \operatorname{TF}(t, d) \times \operatorname{IDF}(t)
\]

### 3.4 L2 Normalization
To prevent query length from biasing the vector magnitude, L2 normalization scales the feature vector $v$ to unit length:
\[
\mathbf{x} = \frac{\mathbf{v}}{\|\mathbf{v}\|_2} = \frac{\mathbf{v}}{\sqrt{\sum_{i=1}^{20,000} v_i^2}}
\]

---

## 4. Why Character-Level N-Grams Fit SQL Injection Detection

1. **Robustness to Syntax Manipulation:**  
   Unlike word-level tokenizers (which split strictly on whitespace), character n-grams capture punctuation, comments, and operator boundaries:
   - Quotes: `'`, `"`
   - Comments: `--`, `/*`, `*/`, `#`
   - Comparison and Arithmetic: `=`, `<`, `>`, `+`, `-`
   - Grouping: `(`, `)`, `;`
2. **Whitespace Invariance:**  
   Attackers frequently bypass keyword filters using alternative whitespace (`UNION%0ASELECT`, `UNION/*comment*/SELECT`, or `1'OR'1'='1`). A character sliding window captures sequences like `'or'`, `r '`, `'1`, `1'`, `='` regardless of spaces.
3. **Detection of Concatenations & Encodings:**  
   Subsequences like `0x`, `char`, `conv`, `sleep`, `waitf` are captured even if embedded directly adjacent to punctuation (e.g. `1;waitfor`).

---

## 5. Top 50 Feature Importance Analysis

### 5.1 Random Forest (Mean Decrease in Impurity / Gini Importance)
Computed across 100 decision trees on the 20,000 features:

| Rank | Feature N-gram | RF Importance | Security Domain Context |
| :---: | :--- | :---: | :--- |
| **1** | `'1 '` | `0.017661` | Numeric literal in boolean tautology payloads (e.g. `' OR 1=1 --`) |
| **2** | `' = '` | `0.014738` | Equality comparison operator in injections and filters |
| **3** | `') '` | `0.014374` | Subquery / function closing parenthesis in nested injection payloads |
| **4** | `' and '`| `0.011879` | Logical conjunction clause in tautologies and blind injections |
| **5** | `'--'` | `0.011661` | Standard SQL line-comment terminator to truncate remainder of query |
| **6** | `' a'` | `0.011418` | Subquery alias prefix (`AS a`, `) a`) commonly used in blind injections |
| **7** | `' ='` | `0.010949` | Comparison operator without leading space |
| **8** | `' ) a'` | `0.010551` | Explicit derived table alias pattern: `(SELECT ...) a` |
| **9** | `' se'` | `0.009837` | Beginning of `SELECT` keyword in UNION or subquery injections |
| **10** | `' )'` | `0.009281` | Closing parenthesis with trailing whitespace |
| **11** | `') ) )'`| `0.008389` | Triple closing parenthesis in deeply nested stacked or blind payloads |
| **12** | `'( '` | `0.007643` | Opening parenthesis with whitespace |
| **13** | `'nd '` | `0.007589` | Terminal fragment of `AND ` |
| **14** | `' from'`| `0.007408` | `FROM` clause in data-exfiltration queries |
| **15** | `') ) '`| `0.007364` | Double closing parenthesis pattern |
| **16** | `' ) ) '`| `0.007110`| Spaced double closing parenthesis |
| **17** | `' ) '` | `0.006892` | Spaced single closing parenthesis |
| **18** | `'fr'` | `0.006435` | Subsequence of `from` |
| **19** | `' ('` | `0.006393` | Opening parenthesis clause |
| **20** | `'on a'` | `0.006349` | Join / alias fragment: `UNION ALL`, `ON a` |
| **21** | `'( 5'` | `0.006315` | Argument in `SLEEP(5)` or `BENCHMARK(5000000)` |
| **22** | `'or '` | `0.006016` | Logical disjunction operator |
| **23** | `') and'`| `0.005708`| Stacked clause conjunction: `) AND 1=1` |
| **24** | `' ) )'`| `0.005463`| Closing parenthesis chain |
| **25** | `'5 )'` | `0.005304` | Closing argument in time-delay functions: `SLEEP(5)` |
| **26** | `' or '`| `0.005283` | Isolated `OR` operator |
| **27** | `' f'` | `0.005275` | Initial character of `FROM` clause |
| **28** | `'all s'`| `0.005190`| Fragment of `UNION ALL SELECT` |
| **29** | `' -'` | `0.004978` | Negative numeric prefix or beginning of `--` comment |
| **30** | `' all'`| `0.004940`| Keyword fragment of `UNION ALL` |
| **31** | `') )'` | `0.004933` | Subquery closure |
| **32** | `' ( '` | `0.004906` | Isolated parenthesis |
| **33** | `' fro'`| `0.004899`| Beginning of `FROM` |
| **34** | `'= '` | `0.004779` | Equality operator with space |
| **35** | `'om'` | `0.004766` | Suffix of `from` |
| **36** | `'fro'` | `0.004736` | Subsequence of `from` |
| **37** | `' sele'`| `0.004443`| Beginning of `SELECT` keyword |
| **38** | `'here '`| `0.004437`| End of `WHERE ` clause |
| **39** | `'from '`| `0.004331`| Complete `FROM ` keyword with space |
| **40** | `'l sel'`| `0.004319`| Fragment of `ALL SELECT` |
| **41** | `'and '` | `0.004319`| Conjunction keyword |
| **42** | `'1\' '` | `0.004288`| Quoted number ending: `'1' ` |
| **43** | `'ll s'` | `0.004143`| Fragment of `ALL SELECT` |
| **44** | `'m '` | `0.004125` | Word boundary ending in m |
| **45** | `'r '` | `0.004034` | Word boundary ending in r |
| **46** | `') a'` | `0.003698` | Alias closure: `) AS a` |
| **47** | `'d '` | `0.003679` | Word boundary ending in d |
| **48** | `'ro'` | `0.003566` | Subsequence of `from` |
| **49** | `') an'`| `0.003514`| Subsequence of `) AND` |
| **50** | `'nio'` | `0.003506` | Subsequence of `UNION` |

---

### 5.2 XGBoost (Split Gain Feature Importance)
The top 20 features ranked by total split gain:

| Rank | Feature ID | Feature N-gram | Split Gain | Dominant Signal |
| :---: | :---: | :--- | :---: | :--- |
| **1** | `f1130` | `' ='` | `2442.44` | Equality assignment in injection payloads |
| **2** | `f8577` | `'all s'` | `1753.77` | Direct indicator of `UNION ALL SELECT` |
| **3** | `f1135` | `' = \''` | `1485.02` | String literal tautology comparison: `='1'` |
| **4** | `f2014` | `' on'` | `752.94` | Join clause or boolean evaluation |
| **5** | `f3313` | `') '` | `311.17` | Subquery / function closure |
| **6** | `f11390`| `'ere'` | `305.81` | Core sequence of `WHERE` clause |
| **7** | `f17031`| `'rom w'` | `292.97` | Boundary transition: `FROM ... WHERE` |
| **8** | `f10573`| `'e ='` | `289.64` | Identifier equality comparison (e.g. `where =`) |
| **9** | `f1324` | `' all '` | `268.86` | Explicit `ALL` keyword in UNION attacks |
| **10** | `f509` | `' * )'` | `181.37` | Aggregate function in blind injection: `COUNT(*)` |
| **11** | `f6063` | `'5 '` | `181.02` | Time-delay argument: `5 ` (as in `SLEEP(5)`) |
| **12** | `f13436`| `'leep '` | `179.71` | Time-delay keyword: `SLEEP ` |
| **13** | `f11888`| `'fro'` | `178.79` | Keyword fragment of `FROM` |
| **14** | `f53` | `' \'0'` | `169.09` | Numeric string comparison payload: `'0'='0'` |
| **15** | `f8659` | `'and ('` | `163.13` | Nested blind condition: `AND (SELECT ...)` |
| **16** | `f311` | `' ( 5'` | `149.24` | Argument in `SLEEP( 5)` |
| **17** | `f511` | `' * f'` | `137.85` | Projection transition: `SELECT * FROM` |
| **18** | `f627` | `' 1#'` | `137.18` | MySQL inline comment bypass: ` 1#` |
| **19** | `f2725` | `'\' u'` | `128.11` | Quote preceding union attack: `' UNION` |
| **20** | `f11889`| `'from'` | `92.25` | Data access clause |

---

## 6. Security Domain Interpretation & False Alarm Risks

### 6.1 Attack Indicators
1. **Union-Based Injection:**
   - Features: `'all s'`, `'all '`, `'nio'`, `'\' u'`
   - Context: Attackers append `UNION ALL SELECT` to mirror columns and extract unauthorized data.
2. **Boolean Tautology Injections:**
   - Features: `'1 '`, `' = '`, `' = \''`, `' or '`, `'1\' '`
   - Context: Attackers inject `OR '1'='1'` or `OR 1=1` to force SQL query predicate evaluation to true.
3. **Time-Based Blind Injections:**
   - Features: `'leep '`, `'5 '`, `'( 5'`, `') a'`
   - Context: Attackers inject database sleep functions (e.g. `SLEEP(5)`, `pg_sleep(5)`) and wrap them in subquery aliases `) a` to measure server response delay.
4. **Comment Truncation:**
   - Features: `'--'`, `' 1#'`
   - Context: Terminates SQL syntax and neutralizes subsequent developer-defined predicates.

### 6.2 Empirical False-Alarm Failure Modes
Because character n-grams do not understand natural language semantics or grammatical context, collisions occur with non-SQL text:

1. **Catalan / Spanish Place Names:**  
   - Empirical False Positive in test set: `"fogars de la selva"` (XGBoost predicted SQLi with probability `0.546`).
   - Root Cause: `"de la selva"` contains the character sequence `' sel'` which is one of the highest-ranked features indicative of `SELECT`.
2. **Short English Words & Initials:**  
   - Empirical False Positives in test set: `"dyck"` (RF prob `0.605`), `"us"` (RF prob `0.520`), `"79"` (RF prob `0.500`).
   - Root Cause: The absence of surrounding context allows short character sequences to match high-frequency sub-tokens from attack payloads.

---

## 7. Limitations of Feature Importance Metrics

1. **Impurity Importance Bias:**  
   Tree-based Gini importance preferentially favors features that appear frequently in splits, even if their individual predictive power is correlated with adjacent n-grams (e.g. `'fro'`, `'from'`, `'rom'`, `'om'` all represent the same token `FROM`).
2. **Lack of Causal Attribution:**  
   The presence of `' from'` or `') '` does not cause a query to be malicious; rather, malicious queries in the dataset are frequently complex nested subqueries that happen to include multiple clauses and closing parentheses.
3. **Feature Dilution (Benign Prefix Camouflage):**  
   Because L2 normalization divides raw TF-IDF weights by the total query vector norm $\|\mathbf{v}\|_2$, embedding a 10-character attack payload (`OR 1=1 --`) inside a 300-character legitimate query reduces the attack n-gram weights below the decision boundary. (Detailed further in the Model Audit Report).
