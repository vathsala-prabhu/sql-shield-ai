import urllib.request
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import config

req = urllib.request.Request(
    "https://api.groq.com/openai/v1/models",
    headers={
        "Authorization": f"Bearer {config.GROQ_API_KEY}",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }
)

try:
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode())
        print("Available Groq Models:")
        for m in data.get("data", []):
            print(" -", m["id"])
except Exception as e:
    print("Error querying Groq models:", e)
