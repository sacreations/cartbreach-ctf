import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "services" / "platform-api"))

from fastapi.testclient import TestClient
from app.main import app, sessions


class TestGoogleAuthAndApprovalFlow(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        sessions.clear()

    def test_google_login_redirect_mock_mode(self):
        response = self.client.get("/api/v1/auth/google/login", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/api/v1/auth/google/callback?mock=true", response.headers["location"])

    @patch("app.main.query_database")
    def test_google_callback_creates_pending_user(self, mock_query):
        # 1. No existing user with this sub or email
        # 2. Check username availability
        # 3. Insert user returning new row
        mock_query.side_effect = [
            [],  # check existing
            [],  # check username collision
            [
                {
                    "id": 42,
                    "username": "new_google_user",
                    "email": "new_google_user@cartbreach.local",
                    "role": "guest",
                    "status": "pending",
                    "auth_provider": "google",
                    "google_sub": "mock-google-1234",
                }
            ],
        ]

        response = self.client.get(
            "/api/v1/auth/google/callback?mock=true&mock_email=new_google_user@cartbreach.local",
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("cartbreach_session", response.cookies)
        session_cookie = response.cookies["cartbreach_session"]

        # User is authenticated at /api/v1/auth/me
        me_resp = self.client.get(
            "/api/v1/auth/me",
            cookies={"cartbreach_session": session_cookie},
        )
        self.assertEqual(me_resp.status_code, 200)
        user_data = me_resp.json()["user"]
        self.assertEqual(user_data["status"], "pending")
        self.assertEqual(user_data["role"], "guest")

        # But challenges endpoint blocks pending users
        ch_resp = self.client.get(
            "/api/v1/challenges",
            cookies={"cartbreach_session": session_cookie},
        )
        self.assertEqual(ch_resp.status_code, 403)
        self.assertIn("Account pending administrator approval", ch_resp.json()["detail"])

    @patch("app.main.query_database")
    def test_admin_approval_unlocks_challenges(self, mock_query):
        # Seed an admin session
        admin_session = "admin_sess_token"
        sessions[admin_session] = (
            {"id": 1, "username": "admin", "role": "admin", "status": "approved"},
            9999999999.0,
        )

        # Seed a pending user session
        user_session = "user_sess_token"
        sessions[user_session] = (
            {"id": 42, "username": "new_user", "role": "guest", "status": "pending"},
            9999999999.0,
        )

        # Admin approves user 42
        mock_query.return_value = [
            {"id": 42, "username": "new_user", "role": "guest", "status": "approved"}
        ]
        approve_resp = self.client.post(
            "/api/v1/admin/users/42/approve",
            cookies={"cartbreach_session": admin_session},
        )
        self.assertEqual(approve_resp.status_code, 200)
        self.assertEqual(approve_resp.json()["user"]["status"], "approved")

        # In-memory session was updated in real time
        self.assertEqual(sessions[user_session][0]["status"], "approved")

        # User can now access challenges
        ch_resp = self.client.get(
            "/api/v1/challenges",
            cookies={"cartbreach_session": user_session},
        )
        self.assertEqual(ch_resp.status_code, 200)
        self.assertIn("challenges", ch_resp.json())


if __name__ == "__main__":
    unittest.main()
