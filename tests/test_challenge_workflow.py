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
from app.main import app, sessions, CHALLENGES_DATA


class TestChallengeWorkflow(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        sessions.clear()
        self.participant_user = {
            "id": 10,
            "username": "agent_alpha",
            "email": "agent@cartbreach.local",
            "role": "participant",
            "status": "approved",
            "auth_provider": "local",
        }
        self.session_token = "test-participant-session-token"
        sessions[self.session_token] = (self.participant_user, time.time() + 3600)
        self.client.cookies.set("cartbreach_session", self.session_token)

    @patch("app.main.query_database")
    def test_list_challenges_initial_state(self, mock_query):
        # User has no solves yet
        mock_query.return_value = []

        response = self.client.get("/api/v1/challenges")
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["score"], 0)
        self.assertEqual(data["solved_count"], 0)
        self.assertEqual(data["total_count"], 6)

        challenges = data["challenges"]
        self.assertEqual(len(challenges), 6)
        self.assertEqual(challenges[0]["status"], "available")
        for stage in challenges[1:]:
            self.assertEqual(stage["status"], "locked")

    @patch("app.main.query_database")
    def test_get_stage_details_available(self, mock_query):
        # Stage 1 is available
        mock_query.return_value = []

        response = self.client.get("/api/v1/challenges/1")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("challenge", data)
        stage = data["challenge"]

        self.assertEqual(stage["id"], 1)
        self.assertEqual(stage["status"], "available")
        self.assertIn("briefing", stage)
        self.assertIn("target_info", stage)
        self.assertIn("instructions", stage)
        self.assertIn("hints", stage)
        # Verify secret flag is not leaked in the details payload
        self.assertNotIn("flag", stage)

    @patch("app.main.query_database")
    def test_get_stage_details_locked(self, mock_query):
        # Stage 2 is locked when Stage 1 is unsolved
        mock_query.return_value = []

        response = self.client.get("/api/v1/challenges/2")
        self.assertEqual(response.status_code, 403)
        self.assertIn("Prerequisite", response.json()["detail"])

    @patch("app.main.query_database")
    def test_get_stage_details_stage_6_terminal(self, mock_query):
        # Stage 6 solved status requires stages 1..5 solved
        mock_query.return_value = [{"stage_id": i} for i in range(1, 6)]

        response = self.client.get("/api/v1/challenges/6")
        self.assertEqual(response.status_code, 200)
        stage = response.json()["challenge"]
        self.assertEqual(stage["id"], 6)
        self.assertIn("terminal", stage["briefing"].lower())
        self.assertIn("target_info", stage)
        # Check that interactive terminal endpoint is documented in target info
        endpoints = stage["target_info"].get("endpoints", [])
        self.assertTrue(any("terminal" in ep.lower() for ep in endpoints))

    @patch("app.main.query_database")
    def test_submit_flag_incorrect(self, mock_query):
        mock_query.return_value = []

        response = self.client.post(
            "/api/v1/challenges/1/submit",
            json={"flag": "SLIIT{wrong_flag_attempt}"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Incorrect flag", response.json()["detail"])

    @patch("app.main.query_database")
    def test_submit_flag_locked_challenge(self, mock_query):
        mock_query.return_value = []

        response = self.client.post(
            "/api/v1/challenges/2/submit",
            json={"flag": "SLIIT{c4rt_br34ch_1d0r_0rd3r_byp455}"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("Challenge is locked", response.json()["detail"])

    @patch("app.main.query_database")
    def test_submit_flag_success_and_unlock_progression(self, mock_query):
        # 1. get_user_solved_stages before submit -> empty
        # 2. INSERT into challenge_solves
        # 3. get_user_solved_stages after submit -> returns stage 1
        mock_query.side_effect = [
            [],  # check solves before
            None,  # INSERT query
            [{"stage_id": 1}],  # updated solves for score calc
        ]

        correct_flag = CHALLENGES_DATA[0]["flag"]
        response = self.client.post(
            "/api/v1/challenges/1/submit",
            json={"flag": correct_flag},
        )
        self.assertEqual(response.status_code, 200)
        result = response.json()

        self.assertEqual(result["status"], "correct")
        self.assertEqual(result["stage_id"], 1)
        self.assertEqual(result["points"], 100)
        self.assertEqual(result["total_score"], 100)
        self.assertTrue(result["unlocked_next"])

    @patch("app.main.query_database")
    def test_submit_flag_already_solved(self, mock_query):
        mock_query.return_value = [{"stage_id": 1}]

        correct_flag = CHALLENGES_DATA[0]["flag"]
        response = self.client.post(
            "/api/v1/challenges/1/submit",
            json={"flag": correct_flag},
        )
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["status"], "already_solved")

    @patch("app.main.query_database")
    def test_leaderboard_endpoint(self, mock_query):
        # query returns individual solves joined with users table
        mock_query.return_value = [
            {"user_id": 10, "username": "agent_alpha", "stage_id": 1, "solved_at": None},
            {"user_id": 10, "username": "agent_alpha", "stage_id": 2, "solved_at": None},
            {"user_id": 11, "username": "agent_beta", "stage_id": 1, "solved_at": None},
        ]

        response = self.client.get("/api/v1/leaderboard")
        self.assertEqual(response.status_code, 200)
        teams = response.json()["teams"]

        self.assertEqual(len(teams), 2)
        self.assertEqual(teams[0]["username"], "agent_alpha")
        self.assertEqual(teams[0]["score"], 250)  # 100 + 150
        self.assertEqual(teams[0]["solves"], 2)
        self.assertEqual(teams[0]["rank"], 1)

        self.assertEqual(teams[1]["username"], "agent_beta")
        self.assertEqual(teams[1]["score"], 100)
        self.assertEqual(teams[1]["solves"], 1)
        self.assertEqual(teams[1]["rank"], 2)


if __name__ == "__main__":
    unittest.main()
