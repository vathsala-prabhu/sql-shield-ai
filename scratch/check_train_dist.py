import pandas as pd

train = pd.read_csv("data/train.csv")
print("Total train rows:", len(train))
print("Train legit (0):", (train["y"] == 0).sum())
print("Train sqli (1):", (train["y"] == 1).sum())

select_queries = train[train["Query"].str.lower().str.startswith("select")]
print("\nTrain queries starting with 'select':")
print("Total starting with select:", len(select_queries))
print("Label distribution:\n", select_queries["label"].value_counts())

where_queries = train[train["Query"].str.lower().str.contains("where")]
print("\nTrain queries containing 'where':")
print("Total containing where:", len(where_queries))
print("Label distribution:\n", where_queries["label"].value_counts())
