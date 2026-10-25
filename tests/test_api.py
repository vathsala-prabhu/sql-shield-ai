import sys
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import app


class TestAPI(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_health_endpoint(self):
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "healthy")

    def test_stats_endpoint(self):
        res = self.client.get("/api/stats")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("total_requests", data)
        self.assertIn("detection_rate_pct", data)

    def test_detect_endpoint_success(self):
        res = self.client.post("/api/detect", json={
            "query": "SELECT * FROM users WHERE id = 1 OR 1=1 --"
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["action"], "Blocked")
        self.assertEqual(data["predicted_class"], "SQLi")

    def test_detect_endpoint_validation_error(self):
        res = self.client.post("/api/detect", json={"query": ""})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertIn("error", data)

    def test_incidents_list_endpoint(self):
        res = self.client.get("/api/incidents")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIsInstance(data, list)

    def test_metrics_endpoint(self):
        res = self.client.get("/api/metrics")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("selected_model", data)
        self.assertIn("test", data)

    def test_security_analyst_endpoint(self):
        with patch("app.analyze_incident", return_value={
            "mode": "gemini_api",
            "analysis": "Use Prepared Statements for user-supplied values.",
        }):
            res = self.client.post("/api/security-analyst", json={
                "query": "SELECT * FROM users WHERE id = 1 OR 1=1 --",
                "question": "How do I fix this in Python?"
            })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("analysis", data)
        self.assertIn("Prepared Statements", data["analysis"])


if __name__ == "__main__":
    unittest.main()
