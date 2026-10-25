import urllib.request
import json

data = json.dumps({"query": "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'"}).encode("utf-8")
req = urllib.request.Request("http://127.0.0.1:5000/api/detect", data=data, headers={"Content-Type": "application/json"})
with urllib.request.urlopen(req) as res:
    payload = json.loads(res.read().decode())
    print("Live API Action:", payload["action"])
    print("Live API Class :", payload["predicted_class"])
    print("Live API Score :", payload["score"])
    print("Live Patterns  :", payload["patterns"])
    print("Simulation     :", payload["simulation"]["status"])
