import pandas as pd

train = pd.read_csv("data/train.csv")

# Let's find out how many training samples have 'or' and '=' and '1'
q_lower = "select * from users where username = 'admin' and password = '' or '1'='1'"

# Check exact substrings
sub_1 = train[train["Query"].str.lower().str.contains("admin", regex=False)]
print("Train queries with 'admin':", len(sub_1), sub_1["label"].value_counts().to_dict())

sub_2 = train[train["Query"].str.lower().str.contains("username", regex=False)]
print("Train queries with 'username':", len(sub_2), sub_2["label"].value_counts().to_dict())

sub_3 = train[train["Query"].str.lower().str.contains("password", regex=False)]
print("Train queries with 'password':", len(sub_3), sub_3["label"].value_counts().to_dict())

sub_4 = train[train["Query"].str.lower().str.contains("users", regex=False)]
print("Train queries with 'users':", len(sub_4), sub_4["label"].value_counts().to_dict())

sub_5 = train[train["Query"].str.lower().str.contains("1'='1", regex=False)]
print("Train queries with \"1'='1\":", len(sub_5), sub_5["label"].value_counts().to_dict())

sub_6 = train[train["Query"].str.lower().str.contains("'1' = '1", regex=False)]
print("Train queries with \"'1' = '1\":", len(sub_6), sub_6["label"].value_counts().to_dict())

sub_7 = train[train["Query"].str.lower().str.contains("1 = 1", regex=False)]
print("Train queries with \"1 = 1\":", len(sub_7), sub_7["label"].value_counts().to_dict())

sub_8 = train[train["Query"].str.lower().str.contains("1=1", regex=False)]
print("Train queries with \"1=1\":", len(sub_8), sub_8["label"].value_counts().to_dict())
