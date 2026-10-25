import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from security.validation import validate_query
from security.gateway import process_request, find_patterns


class TestGateway(unittest.TestCase):
    def test_validation_empty_query(self):
        text, err = validate_query("")
        self.assertIsNone(text)
        self.assertIsNotNone(err)

    def test_validation_null_bytes(self):
        text, err = validate_query("SELECT * FROM users\x00")
        self.assertIsNone(text)
        self.assertIn("Null bytes", err)

    def test_pattern_detection(self):
        patterns = find_patterns("SELECT * FROM users WHERE id = 1 OR 1=1 --")
        self.assertTrue(any("Comment" in p for p in patterns))
        self.assertTrue(any("Tautology" in p for p in patterns))

        union_patterns = find_patterns("' UNION SELECT 1, 2, 3 --")
        self.assertTrue(any("UNION" in p for p in union_patterns))

    def test_tautology_precision_avoids_false_positives(self):
        # Benign query with OR condition between different values
        benign_query = "SELECT * FROM products WHERE category = 'books' OR category = 'electronics'"
        patterns = find_patterns(benign_query)
        self.assertFalse(any("Tautology" in p for p in patterns))

        # Malicious tautology where LHS == RHS
        attack_query = "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'"
        attack_patterns = find_patterns(attack_query)
        self.assertTrue(any("Tautology" in p for p in attack_patterns))

    def test_gateway_blocks_injection(self):
        payload = "SELECT * FROM users WHERE id = 1 OR 1=1 --"
        res, status = process_request(payload)
        self.assertEqual(status, 200)
        self.assertEqual(res["action"], "Blocked")
        self.assertEqual(res["predicted_class"], "SQLi")
        self.assertGreaterEqual(res["incident_id"], 1)
        self.assertEqual(res["simulation"]["status"], "blocked")

    def test_problem_query_blocked(self):
        # Regression test for the user's reported problem query
        payload = "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'"
        res, status = process_request(payload)
        self.assertEqual(status, 200)
        self.assertEqual(res["action"], "Blocked")
        self.assertEqual(res["predicted_class"], "SQLi")
        self.assertGreaterEqual(res["score"], 0.5)
        self.assertEqual(res["simulation"]["status"], "blocked")
        self.assertIn("Boolean Tautology (OR/AND True)", res["patterns"])

    def test_gateway_allows_legitimate(self):
        payload = "SELECT id, title FROM books WHERE author = 'Orwell'"
        res, status = process_request(payload)
        self.assertEqual(status, 200)
        self.assertEqual(res["action"], "Allowed")
        self.assertEqual(res["predicted_class"], "Legitimate")
        self.assertEqual(res["simulation"]["status"], "allowed")

    def test_gateway_allows_benign_or_condition(self):
        payload = "SELECT * FROM products WHERE category = 'books' OR category = 'electronics'"
        res, status = process_request(payload)
        self.assertEqual(status, 200)
        self.assertEqual(res["action"], "Allowed")
        self.assertEqual(res["predicted_class"], "Legitimate")
        self.assertEqual(res["simulation"]["status"], "allowed")


if __name__ == "__main__":
    unittest.main()
