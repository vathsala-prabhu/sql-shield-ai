import pandas as pd

train = pd.read_csv("data/train.csv")

for spaces in ["1=1", "1 = 1", "1  =  1", "'1'='1'", "'1' = '1'", "'1'  =  '1'"]:
    cnt = train["Query"].str.contains(spaces, regex=False)
    print(f"'{spaces}': total={cnt.sum()}, labels={train[cnt]['label'].value_counts().to_dict()}")
