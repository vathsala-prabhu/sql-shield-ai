import urllib.request
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import config

url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent?key={config.GEMINI_API_KEY}"
payload = {"contents": [{"parts": [{"text": "Where is Mysore? Answer in 1 sentence."}]}]}

req = urllib.request.Request(
    url,
    data=json.dumps(payload).encode("utf-8"),
    headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
    method="POST"
)

try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode())
        print("Gemini 3.8 Flash SUCCESS:")
        print(data["candidates"][0]["content"]["parts"][0]["text"].encode("ascii", "replace").decode())
except urllib.error.HTTPError as e:
    print("Gemini HTTPError:", e.code, e.read().decode()[:300])
except Exception as e:
    print("Gemini Exception:", e)
