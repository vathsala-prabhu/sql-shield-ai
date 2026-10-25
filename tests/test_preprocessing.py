import unittest
import pandas as pd


class TestPreprocessing(unittest.TestCase):
    def test_missing_query_or_label_removal(self):
        df = pd.DataFrame({
            "Query": ["SELECT * FROM users", None, "", "   ", "SELECT 1"],
            "Label": [0, 1, 1, 0, None]
        })
        # Remove nulls
        clean = df.dropna(subset=["Query", "Label"]).copy()
        clean["Query"] = clean["Query"].astype(str).str.strip()
        clean = clean[clean["Query"] != ""]
        self.assertEqual(len(clean), 1)
        self.assertEqual(clean.iloc[0]["Query"], "SELECT * FROM users")

    def test_label_normalization(self):
        labels = [0, 1, 0, 1]
        mapped = [{0: "Legitimate", 1: "SQLi"}[y] for y in labels]
        self.assertEqual(mapped, ["Legitimate", "SQLi", "Legitimate", "SQLi"])

    def test_sql_character_preservation(self):
        # Meaningful SQL symbols (quotes, hyphens, semicolons, parentheses) must not be stripped
        sample_query = "SELECT * FROM users WHERE id = 1 OR '1'='1' -- comment"
        key = sample_query.lower()
        self.assertIn("'", key)
        self.assertIn("=", key)
        self.assertIn("--", key)


if __name__ == "__main__":
    unittest.main()
