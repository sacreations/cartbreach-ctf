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
        self.assertIn("suggested_tools", stage)
        self.assertIsInstance(stage["suggested_tools"], list)
        self.assertGreater(len(stage["suggested_tools"]), 0)
        self.assertIn("service", stage["target_info"])
        self.assertIn("protocol", stage["target_info"])
        self.assertIn("auth_context", stage["target_info"])
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


    @patch("app.main.query_database")
    def test_get_stage_details_dynamic_domain(self, mock_query):
        mock_query.return_value = []

        # When accessed through Cloudflare tunnel host
        response = self.client.get(
            "/api/v1/challenges/1",
            headers={
                "Host": "portal.my-ctf.com",
                "X-Forwarded-Proto": "https",
            },
        )
        self.assertEqual(response.status_code, 200)
        endpoints = response.json()["challenge"]["target_info"]["endpoints"]
        # Should have both hosted domain and local fallback endpoints
        self.assertTrue(any("https://git.my-ctf.com" in ep for ep in endpoints))
        self.assertTrue(any("http://localhost:8080" in ep for ep in endpoints))
        self.assertTrue(any("[PUBLIC]" in ep for ep in endpoints))
        self.assertTrue(any("[LOCAL]" in ep for ep in endpoints))

    @patch("app.main.query_database")
    def test_get_stage_details_local_mode(self, mock_query):
        mock_query.return_value = []

        # When accessed locally via localhost
        response = self.client.get(
            "/api/v1/challenges/1",
            headers={"Host": "localhost:8000"},
        )
        self.assertEqual(response.status_code, 200)
        endpoints = response.json()["challenge"]["target_info"]["endpoints"]
        # Should contain local endpoints without requiring public prefix
        self.assertTrue(any("http://localhost:8080" in ep for ep in endpoints))
        self.assertFalse(any("[PUBLIC]" in ep for ep in endpoints))

    @patch("app.main.query_database")
    def test_stage_6_hosted_terminal_endpoint(self, mock_query):
        mock_query.return_value = [{"stage_id": i} for i in range(1, 6)]

        response = self.client.get(
            "/api/v1/challenges/6",
            headers={
                "Host": "portal.ctf-event.org",
                "X-Forwarded-Proto": "https",
            },
        )
        self.assertEqual(response.status_code, 200)
        endpoints = response.json()["challenge"]["target_info"]["endpoints"]
        self.assertTrue(any("https://portal.ctf-event.org/terminal/" in ep for ep in endpoints))
        self.assertTrue(any("http://portal.cartbreach.local/terminal/" in ep for ep in endpoints))

    def _set_admin_session(self):
        admin_user = {
            "id": 1,
            "username": "admin",
            "email": "admin@cartbreach.local",
            "role": "admin",
            "status": "approved",
            "auth_provider": "local",
        }
        token = "test-admin-session-token"
        sessions[token] = (admin_user, time.time() + 3600)
        self.client.cookies.set("cartbreach_session", token)
        return admin_user

    def test_admin_challenges_status_forbidden_for_participant(self):
        response = self.client.get("/api/v1/admin/challenges")
        self.assertEqual(response.status_code, 403)
        self.assertIn("Admin access required", response.json()["detail"])

    @patch("app.main.query_database")
    def test_admin_challenges_status_success(self, mock_query):
        self._set_admin_session()
        mock_query.side_effect = [
            [
                {
                    "stage_id": 1,
                    "user_id": 10,
                    "username": "agent_alpha",
                    "solved_at": None,
                }
            ],
            [
                {
                    "total_users": 5,
                    "approved_participants": 2,
                }
            ],
        ]

        response = self.client.get("/api/v1/admin/challenges")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["total_stages"], 6)
        self.assertEqual(data["total_solves"], 1)
        self.assertEqual(data["total_users"], 5)
        self.assertEqual(data["approved_participants"], 2)
        self.assertEqual(data["completed_all_count"], 0)

        stages = data["stages"]
        self.assertEqual(len(stages), 6)
        stage_1 = stages[0]
        self.assertEqual(stage_1["id"], 1)
        self.assertEqual(stage_1["solve_count"], 1)
        self.assertEqual(stage_1["solve_rate"], 50.0)
        self.assertEqual(len(stage_1["solvers"]), 1)
        self.assertEqual(stage_1["solvers"][0]["username"], "agent_alpha")

    @patch("app.main.query_database")
    def test_admin_reset_user_challenges(self, mock_query):
        self._set_admin_session()
        mock_query.side_effect = [
            [{"id": 10, "username": "agent_alpha"}],
            [{"stage_id": 1}, {"stage_id": 2}],
        ]

        response = self.client.post("/api/v1/admin/users/10/reset-challenges")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["user_id"], 10)
        self.assertEqual(result["username"], "agent_alpha")
        self.assertEqual(result["cleared_count"], 2)
        self.assertEqual(result["cleared_stages"], [1, 2])

    def test_admin_reset_user_challenges_forbidden_for_participant(self):
        response = self.client.post("/api/v1/admin/users/10/reset-challenges")
        self.assertEqual(response.status_code, 403)
        self.assertIn("Admin access required", response.json()["detail"])

    @patch("app.main.query_database")
    def test_admin_reset_user_challenges_not_found(self, mock_query):
        self._set_admin_session()
        mock_query.return_value = []

        response = self.client.post("/api/v1/admin/users/999/reset-challenges")
        self.assertEqual(response.status_code, 404)
        self.assertIn("User not found", response.json()["detail"])

    @patch("app.main.query_database")
    def test_admin_reset_user_stage(self, mock_query):
        self._set_admin_session()
        mock_query.side_effect = [
            [{"id": 10, "username": "agent_alpha"}],
            [{"stage_id": 2}],
        ]

        response = self.client.post("/api/v1/admin/users/10/reset-challenges/2")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["user_id"], 10)
        self.assertEqual(result["stage_id"], 2)
        self.assertTrue(result["cleared"])

    @patch("app.main.query_database")
    def test_admin_reset_all_challenges(self, mock_query):
        self._set_admin_session()
        mock_query.return_value = [{"id": 1}, {"id": 2}, {"id": 3}]

        response = self.client.post("/api/v1/admin/challenges/reset-all")
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["cleared_count"], 3)

    @patch("app.main.query_database")
    def test_admin_users_includes_solve_progress(self, mock_query):
        self._set_admin_session()
        mock_query.side_effect = [
            [
                {
                    "id": 10,
                    "username": "agent_alpha",
                    "email": "agent@cartbreach.local",
                    "role": "participant",
                    "status": "approved",
                    "auth_provider": "local",
                    "created_at": None,
                }
            ],
            [
                {"user_id": 10, "stage_id": 1},
                {"user_id": 10, "stage_id": 3},
            ],
        ]

        response = self.client.get("/api/v1/admin/users")
        self.assertEqual(response.status_code, 200)
        users = response.json()["users"]
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]["solved_stages"], [1, 3])
        self.assertEqual(users[0]["solve_count"], 2)


if __name__ == "__main__":
    unittest.main()
