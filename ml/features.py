import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer

train = pd.read_csv("data/train.csv")
val = pd.read_csv("data/val.csv")
test = pd.read_csv("data/test.csv")

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

print("Train features:", X_train.shape)
print("Validation features:", X_val.shape)
print("Test features:", X_test.shape)