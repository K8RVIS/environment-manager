import importlib.util
import json
import os
import pathlib
import time
import types
import unittest
from unittest.mock import MagicMock, patch


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
MAIN_PATH = PROJECT_ROOT / "main.py"


def load_module():
    spec = importlib.util.spec_from_file_location("environment_manager_main", MAIN_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SignatureVerificationTests(unittest.TestCase):
    def test_verify_slack_signature_accepts_valid_signature(self):
        module = load_module()
        body = "token=t&command=%2Fstart_dev&user_id=U123"
        timestamp = "1710000000"
        secret = "super-secret"

        signature = module.build_slack_signature(secret, timestamp, body)

        self.assertTrue(
            module.verify_slack_signature(
                signing_secret=secret,
                timestamp=timestamp,
                signature=signature,
                raw_body=body,
                current_time=1710000000,
            )
        )

    def test_verify_slack_signature_rejects_invalid_signature(self):
        module = load_module()

        self.assertFalse(
            module.verify_slack_signature(
                signing_secret="super-secret",
                timestamp="1710000000",
                signature="v0=deadbeef",
                raw_body="command=%2Fstart_dev",
                current_time=1710000000,
            )
        )


class ConfigTests(unittest.TestCase):
    def test_load_user_namespace_map_parses_json(self):
        module = load_module()

        with patch.dict(
            os.environ,
            {"SLACK_USER_NAMESPACE_MAP": json.dumps({"U123": "team-a", "U456": "team-b"})},
            clear=False,
        ):
            self.assertEqual(
                module.load_user_namespace_map(),
                {"U123": "team-a", "U456": "team-b"},
            )


class HandlerTests(unittest.TestCase):
    def setUp(self):
        self.event_template = {
            "headers": {},
            "body": "",
            "isBase64Encoded": False,
            "requestContext": {
                "http": {
                    "method": "POST",
                }
            },
        }

    def _build_event(self, module, body, secret="super-secret", timestamp=None):
        current_timestamp = timestamp or str(int(time.time()))
        signature = module.build_slack_signature(secret, current_timestamp, body)
        event = dict(self.event_template)
        event["body"] = body
        event["headers"] = {
            "x-slack-request-timestamp": current_timestamp,
            "x-slack-signature": signature,
            "content-type": "application/x-www-form-urlencoded",
        }
        return event

    def test_lambda_handler_rejects_unknown_user(self):
        module = load_module()
        body = "command=%2Fstart_dev&user_id=U999&user_name=unknown"
        event = self._build_event(module, body)

        with patch.dict(
            os.environ,
            {
                "SLACK_SIGNING_SECRET": "super-secret",
                "SLACK_USER_NAMESPACE_MAP": json.dumps({"U123": "team-a"}),
            },
            clear=False,
        ):
            response = module.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 403)
        payload = json.loads(response["body"])
        self.assertIn("허용되지 않은 사용자", payload["text"])

    def test_lambda_handler_dispatches_start_dev_workflow(self):
        module = load_module()
        body = "command=%2Fstart_dev&user_id=U123&user_name=alice"
        event = self._build_event(module, body)

        with patch.dict(
            os.environ,
            {
                "SLACK_SIGNING_SECRET": "super-secret",
                "SLACK_USER_NAMESPACE_MAP": json.dumps({"U123": "team-a"}),
                "GITHUB_TARGET_OWNER": "K8RVIS",
                "GITHUB_TARGET_REPO": "eks-secure-infra",
                "GITHUB_WORKFLOW_FILENAME": "orchestrate-environment.yml",
            },
            clear=False,
        ):
            with patch.object(module, "dispatch_workflow") as dispatch_workflow:
                response = module.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        dispatch_workflow.assert_called_once()
        dispatch_kwargs = dispatch_workflow.call_args.kwargs
        self.assertEqual(dispatch_kwargs["owner"], "K8RVIS")
        self.assertEqual(dispatch_kwargs["repo"], "eks-secure-infra")
        self.assertEqual(dispatch_kwargs["workflow_filename"], "orchestrate-environment.yml")
        self.assertEqual(
            dispatch_kwargs["inputs"],
            {
                "operation": "start",
                "slack_user_id": "U123",
                "namespace": "team-a",
                "request_id": dispatch_kwargs["inputs"]["request_id"],
            },
        )

    def test_lambda_handler_returns_hello_world_for_hello_command(self):
        module = load_module()
        body = "command=%2Fhello&user_id=U123&user_name=alice"
        event = self._build_event(module, body)

        with patch.dict(
            os.environ,
            {
                "SLACK_SIGNING_SECRET": "super-secret",
                "SLACK_USER_NAMESPACE_MAP": json.dumps({"U123": "team-a"}),
            },
            clear=False,
        ):
            response = module.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        payload = json.loads(response["body"])
        self.assertEqual(payload["text"], "hello, world")

    def test_lambda_handler_formats_status_from_s3_state(self):
        module = load_module()
        body = "command=%2Fstatus_dev&user_id=U123&user_name=alice"
        event = self._build_event(module, body)
        state = {
            "infra_status": "running",
            "active_namespaces": ["team-a", "team-c"],
            "active_users": {"U123": "team-a", "U789": "team-c"},
            "pending_operation": None,
            "last_error": None,
            "updated_at": "2026-04-14T10:00:00Z",
        }

        fake_s3 = MagicMock()
        fake_s3.get_object.return_value = {
            "Body": types.SimpleNamespace(read=lambda: json.dumps(state).encode("utf-8"))
        }

        with patch.dict(
            os.environ,
            {
                "SLACK_SIGNING_SECRET": "super-secret",
                "SLACK_USER_NAMESPACE_MAP": json.dumps({"U123": "team-a"}),
                "STATE_BUCKET": "state-bucket",
                "STATE_KEY": "environment-manager/state.json",
            },
            clear=False,
        ):
            with patch.object(module.boto3, "client", return_value=fake_s3):
                response = module.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        payload = json.loads(response["body"])
        self.assertIn("환경 상태: 실습 가능", payload["text"])
        self.assertIn("현재 실습 중: <@U123> (team-a), <@U789> (team-c)", payload["text"])
        self.assertIn("현재 namespace: team-a, team-c", payload["text"])

    def test_lambda_handler_formats_pending_status_as_creating(self):
        module = load_module()
        body = "command=%2Fstatus_dev&user_id=U123&user_name=alice"
        event = self._build_event(module, body)
        state = {
            "infra_status": "running",
            "active_namespaces": ["team-a", "team-c"],
            "active_users": {"U123": "team-a", "U789": "team-c"},
            "pending_operation": {
                "operation": "start",
                "namespace": "team-c",
            },
            "last_error": None,
            "updated_at": "2026-04-14T10:00:00Z",
        }

        fake_s3 = MagicMock()
        fake_s3.get_object.return_value = {
            "Body": types.SimpleNamespace(read=lambda: json.dumps(state).encode("utf-8"))
        }

        with patch.dict(
            os.environ,
            {
                "SLACK_SIGNING_SECRET": "super-secret",
                "SLACK_USER_NAMESPACE_MAP": json.dumps({"U123": "team-a"}),
                "STATE_BUCKET": "state-bucket",
                "STATE_KEY": "environment-manager/state.json",
            },
            clear=False,
        ):
            with patch.object(module.boto3, "client", return_value=fake_s3):
                response = module.lambda_handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        payload = json.loads(response["body"])
        self.assertIn("환경 상태: 생성 중", payload["text"])
        self.assertIn("진행 중 작업: start(team-c)", payload["text"])


if __name__ == "__main__":
    unittest.main()
