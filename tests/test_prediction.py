import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.predict import predict_query


class TestPrediction(unittest.TestCase):
    def test_benign_query_prediction(self):
        query = "SELECT id, name FROM products WHERE id = 10"
        result = predict_query(query)
        self.assertIn("label", result)
        self.assertIn("score", result)
        self.assertEqual(result["label"], "Legitimate")
        self.assertLess(result["score"], 0.5)

    def test_sqli_query_prediction(self):
        query = "SELECT * FROM users WHERE id = 1 OR 1=1 --"
        result = predict_query(query)
        self.assertIn("label", result)
        self.assertIn("score", result)
        self.assertEqual(result["label"], "SQLi")
        self.assertGreaterEqual(result["score"], 0.5)

    def test_problem_query_regression(self):
        # Regression test for: SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'
        query = "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'"
        result = predict_query(query)
        self.assertEqual(result["label"], "SQLi")
        self.assertGreaterEqual(result["score"], 0.5)
        # Verify both comparative models identify the threat
        self.assertEqual(result["comparisons"]["random_forest"]["label"], "SQLi")
        self.assertEqual(result["comparisons"]["xgboost"]["label"], "SQLi")

    def test_benign_query_with_or_condition(self):
        # Benign OR condition should NOT trigger false positive
        query = "SELECT * FROM products WHERE category = 'books' OR category = 'electronics'"
        result = predict_query(query)
        self.assertEqual(result["label"], "Legitimate")
        self.assertLess(result["score"], 0.5)

    def test_benign_complex_query(self):
        query = "SELECT u.id, u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id WHERE o.total > 50"
        result = predict_query(query)
        self.assertEqual(result["label"], "Legitimate")
        self.assertLess(result["score"], 0.5)

    def test_threshold_adjustment(self):
        query = "SELECT * FROM users WHERE id = 1 OR 1=1 --"
        # If threshold is artificially set to 0.99, it should report Legitimate at that threshold
        result = predict_query(query, threshold=0.99)
        self.assertEqual(result["threshold"], 0.99)
        self.assertEqual(result["label"], "Legitimate")

    def test_comparative_models_present(self):
        query = "SELECT 1"
        result = predict_query(query, compare_both=True)
        self.assertIn("comparisons", result)
        self.assertIn("random_forest", result["comparisons"])
        self.assertIn("xgboost", result["comparisons"])


if __name__ == "__main__":
    unittest.main()
