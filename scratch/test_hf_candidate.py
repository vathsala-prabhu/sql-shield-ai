import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline

model_id = "salmane11/SQLQueryShield"
print("Attempting to load tokenizer for:", model_id)
tokenizer = AutoTokenizer.from_pretrained(model_id)
print("Tokenizer loaded successfully:", type(tokenizer).__name__)

print("Attempting to load model weights for:", model_id)
device = "cuda" if torch.cuda.is_available() else "cpu"
model = AutoModelForSequenceClassification.from_pretrained(model_id)
model.to(device)
model.eval()
print("Model loaded successfully onto:", device)
print("Config id2label:", model.config.id2label)
print("Config label2id:", model.config.label2id)

clf = pipeline("text-classification", model=model, tokenizer=tokenizer, device=device, truncation=True, max_length=512)

test_queries = [
    ("Benign 1", "SELECT name, email FROM users WHERE id = 5"),
    ("Benign 2", "SELECT * FROM products WHERE category = 'books' AND price < 20"),
    ("Benign with param placeholder", "SELECT ItemName, ItemDescription FROM Items WHERE ItemID = 'USER_INPUT';"),
    ("SQLi 1", "SELECT * FROM users WHERE id = 1 OR 1=1 --"),
    ("SQLi 2", "admin' --"),
    ("SQLi 3", "' UNION SELECT username, password FROM users --"),
    ("SQLi 4", "1; DROP TABLE users; --"),
]

for desc, q in test_queries:
    res = clf(q)[0]
    print(f"[{desc}] '{q}' -> Label: {res['label']}, Score: {res['score']:.4f}")
