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


class TestResetRecovery(unittest.TestCase):
    """
    Validates state recovery, challenge progression reset, and telemetry updates
    under administrative control.
    """

    def setUp(self):
        self.client = TestClient(app)
        sessions.clear()

        # Admin user session
        self.admin_user = {
            "id": 1,
            "username": "admin_root",
            "email": "admin@cartbreach.local",
            "role": "admin",
            "status": "approved",
            "auth_provider": "local",
        }
        self.session_token = "admin-session-token"
        sessions[self.session_token] = (self.admin_user, time.time() + 3600)
        self.client.cookies.set("cartbreach_session", self.session_token)

    @patch("app.main.execute_database")
    def test_admin_user_challenge_reset_success(self, mock_exec):
        """Admin resetting a user's challenge progression must execute database deletion."""
        mock_exec.return_value = None

        response = self.client.post("/api/v1/admin/users/10/reset-challenges")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["user_id"], 10)
        self.assertIn("Reset all challenge progress", data["message"])
        mock_exec.assert_called_once()

    @patch("app.main.execute_database")
    def test_admin_single_stage_reset_success(self, mock_exec):
        """Admin resetting a specific stage must execute targeted deletion."""
        mock_exec.return_value = None

        response = self.client.post("/api/v1/admin/users/10/reset-challenges/3")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["user_id"], 10)
        self.assertEqual(data["stage_id"], 3)
        self.assertIn("Reset stage 3", data["message"])
        mock_exec.assert_called_once()

    @patch("app.main.execute_database")
    def test_admin_global_reset_all_challenges(self, mock_exec):
        """Admin resetting platform-wide challenge solves must clear challenge_solves table."""
        mock_exec.return_value = None

        response = self.client.post("/api/v1/admin/challenges/reset-all")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertIn("All challenge solves have been reset", data["message"])
        mock_exec.assert_called_once()


if __name__ == "__main__":
    unittest.main()
