import sys
import json
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services import security_analyst


class TestSecurityAnalyst(unittest.TestCase):
    def setUp(self):
        self.incident = {
            "submitted_input": "SELECT * FROM users WHERE id = 1",
            "predicted_class": "Legitimate",
            "score": 0.34,
            "action": "Allowed",
            "patterns": [],
            "model_used": "selected_model",
        }

    def test_specific_question_uses_gemini_response(self):
        question = "hi"
        gemini_result = {"mode": "gemini_api", "analysis": "Hello! What would you like to know?"}
        with (
            patch.object(security_analyst.config, "GEMINI_API_KEY", "gemini-test-key"),
            patch.object(security_analyst.config, "GROQ_API_KEY", "groq-test-key"),
            patch.object(security_analyst, "call_gemini_api", return_value=gemini_result) as gemini,
            patch.object(security_analyst, "call_groq_api") as groq,
        ):
            result = security_analyst.analyze_incident(self.incident, question)

        self.assertEqual(result, gemini_result)
        gemini.assert_called_once_with(self.incident, question)
        groq.assert_not_called()

    def test_groq_prompt_prioritizes_the_specific_question(self):
        response = MagicMock()
        response.read.return_value = json.dumps({
            "choices": [{"message": {"content": "Hello! What would you like to know?"}}]
        }).encode("utf-8")
        response.__enter__.return_value = response
        with (
            patch.object(security_analyst.config, "GROQ_API_KEY", "groq-test-key"),
            patch.object(security_analyst.config, "GROQ_MODEL", "test-model"),
            patch.object(security_analyst.urllib.request, "urlopen", return_value=response) as urlopen,
        ):
            result = security_analyst.call_groq_api(self.incident, "hi")

        request = urlopen.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))
        self.assertEqual(result["mode"], "groq_api")
        self.assertIn("User Question: hi", payload["messages"][1]["content"])
        self.assertIn("answer this question directly", payload["messages"][1]["content"].lower())
        self.assertIn("Do not produce a generic incident report", payload["messages"][0]["content"])

    def test_groq_is_used_when_gemini_fails(self):
        question = "Why was this blocked?"
        gemini_result = {
            "mode": "fallback_after_api_error",
            "note": "Gemini request timed out.",
        }
        groq_result = {"mode": "groq_api", "analysis": "This input was allowed because its score was below threshold."}
        with (
            patch.object(security_analyst.config, "GEMINI_API_KEY", "gemini-test-key"),
            patch.object(security_analyst.config, "GROQ_API_KEY", "groq-test-key"),
            patch.object(security_analyst, "call_gemini_api", return_value=gemini_result),
            patch.object(security_analyst, "call_groq_api", return_value=groq_result) as groq,
        ):
            result = security_analyst.analyze_incident(self.incident, question)

        self.assertEqual(result, groq_result)
        groq.assert_called_once_with(self.incident, question)

    def test_provider_failure_does_not_return_generic_report_for_question(self):
        question = "hi"
        fallback = {
            "mode": "fallback_after_api_error",
            "note": "Gemini request timed out.",
        }
        groq_fallback = {
            "mode": "fallback_after_groq_api_error",
            "note": "Groq could not be reached.",
        }
        with (
            patch.object(security_analyst.config, "GEMINI_API_KEY", "gemini-test-key"),
            patch.object(security_analyst.config, "GROQ_API_KEY", "groq-test-key"),
            patch.object(security_analyst, "call_gemini_api", return_value=fallback),
            patch.object(security_analyst, "call_groq_api", return_value=groq_fallback),
        ):
            result = security_analyst.analyze_incident(self.incident, question)

        self.assertEqual(result["mode"], "local_provider_unavailable")
        self.assertIn("couldn't generate an AI answer", result["analysis"])
        self.assertNotIn("Recommended Defensive Implementation", result["analysis"])
        self.assertIn("Gemini request timed out.", result["note"])
        self.assertIn("Groq could not be reached.", result["note"])


if __name__ == "__main__":
    unittest.main()
