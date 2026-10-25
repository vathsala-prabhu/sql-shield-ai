import urllib.request
import urllib.error
import json
import sys

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import config

print("Testing Groq API with proper User-Agent...", flush=True)

groq_url = "https://api.groq.com/openai/v1/chat/completions"
groq_payload = {
    "model": config.GROQ_MODEL,
    "messages": [
        {"role": "user", "content": "Where is Mysore? Answer in 1 sentence."}
    ],
}

headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {config.GROQ_API_KEY}",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}

req = urllib.request.Request(
    groq_url,
    data=json.dumps(groq_payload).encode("utf-8"),
    headers=headers,
    method="POST"
)

try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        print("Groq Response:\n", data["choices"][0]["message"]["content"], flush=True)
except urllib.error.HTTPError as e:
    print(f"Groq HTTPError: {e.code}", e.read().decode()[:300], flush=True)
except Exception as e:
    print(f"Groq Exception: {e}", flush=True)
