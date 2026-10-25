import pandas as pd
import re

df = pd.read_csv("data/clean_dataset.csv")

print("Checking queries containing '1'='1':")
sub = df[df["Query"].str.contains(r"1['\"]?\s*=\s*['\"]?1", case=False, regex=True)]
print("Total with 1=1:", len(sub))
print("Labels distribution for 1=1:\n", sub["label"].value_counts())
print("\nSample queries with 1=1:")
print(sub[["Query", "label"]].head(15).to_string())

print("\n" + "="*50)
print("Checking queries containing 'admin':")
sub_admin = df[df["Query"].str.contains(r"admin", case=False, regex=True)]
print("Total with admin:", len(sub_admin))
print("Labels distribution for admin:\n", sub_admin["label"].value_counts())
print(sub_admin[["Query", "label"]].head(15).to_string())
