import pandas as pd

clean = pd.read_csv("data/clean_dataset.csv")
train = pd.read_csv("data/train.csv")

# Check for obvious SQL injection patterns in clean where y == 0 (Legitimate)
patterns = [
    r"or\s+1\s*=\s*1",
    r"or\s+'1'\s*=\s*'1'",
    r'or\s+"1"\s*=\s*"1"',
    r'or\s+""\s*=\s*""',
    r"or\s+''\s*=\s*''",
    r"drop\s+table",
    r"union\s+select",
    r"exec\s+xp_",
]

for pat in patterns:
    mislabeled = clean[(clean["y"] == 0) & clean["Query"].str.contains(pat, case=False, regex=True)]
    print(f"Clean rows with y==0 matching {pat}: {len(mislabeled)}")
    if len(mislabeled) > 0:
        for q in mislabeled["Query"].head(3):
            print("   ->", repr(q))
