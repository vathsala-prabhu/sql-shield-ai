import pandas as pd

pd.set_option("display.max_colwidth", 100)

df = pd.read_csv("data/clean_dataset.csv")
q = df["Query"].str.lower()

patterns = [r"union", r"union\s+select", r"or\s+1\s*=\s*1", r"--"]
for p in patterns:
    sub = df[q.str.contains(p, regex=True)]
    print(p, "->", sub["label"].value_counts().to_dict())

print("\nSample legitimate rows:")
print(df[df["y"] == 0]["Query"].sample(8, random_state=1).to_string())

print("\nSample SQLi rows containing 'union':")
print(df[(df["y"] == 1) & q.str.contains("union")]["Query"].head(8).to_string())