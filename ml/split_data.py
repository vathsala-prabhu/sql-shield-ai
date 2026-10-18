import pandas as pd
from sklearn.model_selection import train_test_split

df = pd.read_csv("data/clean_dataset.csv")

# First split: 70% train, 30% temporary
train, temp = train_test_split(
    df, test_size=0.30, random_state=42, stratify=df["y"]
)

# Second split: temporary -> 15% validation, 15% test
val, test = train_test_split(
    temp, test_size=0.50, random_state=42, stratify=temp["y"]
)

train.to_csv("data/train.csv", index=False)
val.to_csv("data/val.csv", index=False)
test.to_csv("data/test.csv", index=False)

for name, part in [("Train", train), ("Validation", val), ("Test", test)]:
    print(name, len(part), part["label"].value_counts().to_dict())