import time
import torch
import pandas as pd
from transformers import AutoTokenizer, AutoModelForSequenceClassification

test_df = pd.read_csv("data/test.csv")
print(f"Total rows in test.csv: {len(test_df)}")

device = "cuda" if torch.cuda.is_available() else "cpu"
print(f"Using device: {device}")

model_id = "salmane11/SQLQueryShield"
tokenizer = AutoTokenizer.from_pretrained(model_id)
model = AutoModelForSequenceClassification.from_pretrained(model_id)
model.to(device)
model.eval()

# Test speed on 100 queries
subset = test_df["Query"].iloc[:100].tolist()
t0 = time.time()
with torch.no_grad():
    inputs = tokenizer(subset, padding=True, truncation=True, max_length=128, return_tensors="pt").to(device)
    outputs = model(**inputs)
    probs = torch.softmax(outputs.logits, dim=-1)
elapsed = time.time() - t0
print(f"100 queries took {elapsed:.2f}s ({elapsed/100*1000:.1f} ms/query)")
estimated_total = (elapsed / 100) * len(test_df)
print(f"Estimated time for full test set ({len(test_df)} rows): {estimated_total:.1f}s (~{estimated_total/60:.1f} min)")
