import pandas as pd

df = pd.read_csv("data/Modified_SQL_Dataset.csv")

# 1. Remove rows with missing query or label
df = df.dropna(subset=["Query", "Label"])
df["Query"] = df["Query"].astype(str).str.strip()
df = df[df["Query"] != ""]

# 2. Normalize labels into two classes
df["y"] = df["Label"].astype(int)
df["label"] = df["y"].map({0: "Legitimate", 1: "SQLi"})

# 3. Duplicate check (ignoring only case and extra spaces, text itself is untouched)
df["key"] = df["Query"].str.lower().str.replace(r"\s+", " ", regex=True)
print("Exact duplicates:", df.duplicated(subset=["Query"]).sum())
print("Near duplicates:", df.duplicated(subset=["key"]).sum())

# 4. Remove queries that appear with conflicting labels
nunique = df.groupby("key")["y"].nunique()
bad_keys = nunique[nunique > 1].index
print("Queries with conflicting labels:", len(bad_keys))
df = df[~df["key"].isin(bad_keys)]

# 5. Remove duplicates
df = df.drop_duplicates(subset="key")

# 6. Save the clean file
df[["Query", "label", "y"]].to_csv("data/clean_dataset.csv", index=False)
print("\nClean rows:", len(df))
print(df["label"].value_counts())