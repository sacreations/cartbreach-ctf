import sys
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

for mod_name in ("bcrypt", "psycopg", "psycopg.rows"):
    try:
        __import__(mod_name)
    except ImportError:
        sys.modules[mod_name] = MagicMock()

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "services" / "platform-api"))

from fastapi.testclient import TestClient
from app.main import app, sessions


class TestUnintendedSolutions(unittest.TestCase):
    """
    Rigorously tests boundary conditions to ensure participants cannot bypass
    challenge stages via unintended shortcuts, brute-forcing, or privilege leaks.
    """

    def setUp(self):
        self.client = TestClient(app)
        sessions.clear()

        # Regular participant user session
        self.participant_user = {
            "id": 42,
            "username": "participant_bob",
            "email": "bob@cartbreach.local",
            "role": "participant",
            "status": "approved",
            "auth_provider": "local",
        }
        self.session_token = "valid-participant-session"
        sessions[self.session_token] = (self.participant_user, time.time() + 3600)
        self.client.cookies.set("cartbreach_session", self.session_token)

    @patch("app.main.query_database")
    def test_cannot_access_locked_stage_without_prerequisites(self, mock_query):
        """Participants must NOT be able to access Stage 3 without solving Stages 1 and 2."""
        mock_query.return_value = [{"stage_id": 1}]  # Only stage 1 solved

        # Request Stage 3 details
        response = self.client.get("/api/v1/challenges/3")
        self.assertEqual(response.status_code, 403)
        self.assertIn("Prerequisite", response.json()["detail"])

    @patch("app.main.query_database")
    def test_cannot_skip_to_terminal_stage_6(self, mock_query):
        """Participants must NOT be able to view Stage 6 Web Terminal brief before stages 1..5."""
        mock_query.return_value = [{"stage_id": 1}, {"stage_id": 2}]

        response = self.client.get("/api/v1/challenges/6")
        self.assertEqual(response.status_code, 403)
        self.assertIn("Prerequisite", response.json()["detail"])

    def test_invalid_flags_are_strictly_rejected(self):
        """Submitting non-matching or arbitrary flags must return valid: False."""
        bogus_flags = [
            "SLIIT{wrong_flag_attempt}",
            "FLAG{fake_format}",
            "'' OR '1'='1",
            "<script>alert(1)</script>",
        ]
        for flag in bogus_flags:
            response = self.client.post("/api/v1/flags/submit", json={"flag": flag})
            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertFalse(data["valid"])

    @patch("app.main.query_database")
    def test_unauthenticated_request_cannot_view_challenges(self, mock_query):
        """Unauthenticated requests must be rejected immediately."""
        self.client.cookies.clear()
        response = self.client.get("/api/v1/challenges")
        self.assertEqual(response.status_code, 401)

    @patch("app.main.query_database")
    def test_regular_participant_cannot_call_admin_reset_endpoints(self, mock_query):
        """Ordinary participants must NOT be able to trigger administrative resets."""
        # Participant attempts to reset all challenges
        response = self.client.post("/api/v1/admin/challenges/reset-all")
        self.assertEqual(response.status_code, 403)
        self.assertIn("Administrator role required", response.json()["detail"])

        # Participant attempts to reset another user's progress
        response = self.client.post("/api/v1/admin/users/1/reset-challenges")
        self.assertEqual(response.status_code, 403)
        self.assertIn("Administrator role required", response.json()["detail"])

    @patch("app.main.query_database")
    def test_regular_participant_cannot_view_admin_matrix(self, mock_query):
        """Participants must NOT be able to view admin telemetry or other users' solves."""
        response = self.client.get("/api/v1/admin/challenges")
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
