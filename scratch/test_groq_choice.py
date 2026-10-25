import urllib.request
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import config

groq_url = "https://api.groq.com/openai/v1/chat/completions"

for model in ["openai/gpt-oss-120b", "openai/gpt-oss-20b", "qwen/qwen3.8-27b"]:
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "Where is Mysore? Answer in 1 sentence."}],
        "max_tokens": 100
    }
    req = urllib.request.Request(
        groq_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {config.GROQ_API_KEY}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            print(f"Model {model} SUCCESS:\n", data["choices"][0]["message"]["content"])
            break
    except urllib.error.HTTPError as e:
        print(f"Model {model} HTTPError:", e.code, e.read().decode()[:200])
