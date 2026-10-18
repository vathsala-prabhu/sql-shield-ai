import pandas as pd

path = "data/Modified_SQL_Dataset.csv"

try:
    df = pd.read_csv(path)
except UnicodeDecodeError:
    df = pd.read_csv(path, encoding="latin-1")

print("Shape (rows, columns):", df.shape)
print("\nColumn names:", list(df.columns))
print("\nFirst 5 rows:")
print(df.head())
print("\nMissing values per column:")
print(df.isnull().sum())
print("\nExact duplicate rows:", df.duplicated().sum())

label_col = df.columns[-1]
print(f"\nLabel column guess: '{label_col}'")
print(df[label_col].value_counts())