import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import time
import uuid
from typing import Any
from urllib import request as urllib_request
from urllib.parse import parse_qs

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

try:
    import boto3
except ModuleNotFoundError:  # pragma: no cover - local fallback
    class _MissingBoto3:
        def client(self, *args: Any, **kwargs: Any) -> Any:
            raise ModuleNotFoundError("boto3 is not installed")

    boto3 = _MissingBoto3()


def default_state() -> dict[str, Any]:
    return {
        "infra_status": "stopped",
        "active_namespaces": [],
        "active_users": {},
        "pending_operation": None,
        "last_error": None,
        "updated_at": None,
    }


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def build_slack_signature(signing_secret: str, timestamp: str, raw_body: str) -> str:
    base = f"v0:{timestamp}:{raw_body}".encode("utf-8")
    digest = hmac.new(signing_secret.encode("utf-8"), base, hashlib.sha256).hexdigest()
    return f"v0={digest}"


def verify_slack_signature(
    signing_secret: str,
    timestamp: str | None,
    signature: str | None,
    raw_body: str,
    current_time: int | None = None,
) -> bool:
    if not signing_secret or not timestamp or not signature:
        return False

    try:
        ts_value = int(timestamp)
    except (TypeError, ValueError):
        return False

    now = current_time if current_time is not None else int(time.time())
    if abs(now - ts_value) > 300:
        return False

    expected = build_slack_signature(signing_secret, timestamp, raw_body)
    return hmac.compare_digest(expected, signature)


def load_user_namespace_map() -> dict[str, str]:
    raw = os.environ.get("SLACK_USER_NAMESPACE_MAP", "{}")
    parsed = json.loads(raw)

    if not isinstance(parsed, dict):
        raise RuntimeError("SLACK_USER_NAMESPACE_MAP must be a JSON object")

    mapping: dict[str, str] = {}
    for user_id, namespace in parsed.items():
        mapping[str(user_id)] = str(namespace)
    return mapping


def decode_body(event: dict[str, Any]) -> str:
    raw_body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        return base64.b64decode(raw_body).decode("utf-8")
    return raw_body


def normalize_headers(event: dict[str, Any]) -> dict[str, str]:
    headers = event.get("headers") or {}
    return {str(key).lower(): str(value) for key, value in headers.items()}


def parse_slack_command(raw_body: str) -> dict[str, str]:
    parsed = parse_qs(raw_body, keep_blank_values=True)
    return {key: values[0] for key, values in parsed.items()}


def json_response(status_code: int, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(payload, ensure_ascii=False),
    }


def channel_response(text: str) -> dict[str, Any]:
    return json_response(200, {"response_type": "in_channel", "text": text})


def normalize_private_key(private_key_pem: str) -> str:
    normalized = private_key_pem.strip()
    if "\\n" in normalized:
        normalized = normalized.replace("\\n", "\n")
    return normalized


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("utf-8")


def build_github_app_jwt(app_id: str, private_key_pem: str, now: int | None = None) -> str:
    issued_at = now if now is not None else int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"iat": issued_at - 60, "exp": issued_at + 540, "iss": app_id}

    signing_input = ".".join(
        [
            b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")),
            b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")),
        ]
    )

    private_key = serialization.load_pem_private_key(
        normalize_private_key(private_key_pem).encode("utf-8"),
        password=None,
    )
    signature = private_key.sign(
        signing_input.encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return f"{signing_input}.{b64url_encode(signature)}"


def create_installation_token(app_id: str, private_key_pem: str, installation_id: str) -> str:
    jwt_token = build_github_app_jwt(app_id=app_id, private_key_pem=private_key_pem)
    request = urllib_request.Request(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        headers={
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="POST",
    )
    with urllib_request.urlopen(request, timeout=10) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return payload["token"]


def dispatch_workflow(owner: str, repo: str, workflow_filename: str, inputs: dict[str, str], ref: str | None = None) -> None:
    token = create_installation_token(
        app_id=require_env("GITHUB_APP_ID"),
        private_key_pem=require_env("GITHUB_APP_PRIVATE_KEY"),
        installation_id=require_env("GITHUB_INSTALLATION_ID"),
    )
    workflow_ref = ref or os.environ.get("GITHUB_WORKFLOW_REF", "main")
    request = urllib_request.Request(
        f"https://api.github.com/repos/{owner}/{repo}/actions/workflows/{workflow_filename}/dispatches",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
        data=json.dumps({"ref": workflow_ref, "inputs": inputs}).encode("utf-8"),
        method="POST",
    )
    with urllib_request.urlopen(request, timeout=10) as response:
        if response.status not in {200, 201, 204}:
            raise RuntimeError(f"GitHub workflow dispatch failed with status {response.status}")


def load_state() -> dict[str, Any]:
    bucket = require_env("STATE_BUCKET")
    key = require_env("STATE_KEY")
    s3_module = boto3
    if not hasattr(s3_module, "client"):
        import boto3 as s3_module

    client = s3_module.client("s3", region_name=os.environ.get("AWS_REGION"))

    try:
        response = client.get_object(Bucket=bucket, Key=key)
    except Exception as exc:
        error_response = getattr(exc, "response", {}) or {}
        error_code = error_response.get("Error", {}).get("Code")
        if error_code in {"NoSuchKey", "404", "NoSuchBucket"}:
            return default_state()
        raise

    body = response["Body"].read().decode("utf-8")
    if not body.strip():
        return default_state()

    state = default_state()
    state.update(json.loads(body))
    return state


def format_status_message(state: dict[str, Any]) -> str:
    namespaces = state.get("active_namespaces") or []
    active_users = state.get("active_users") or {}
    pending = state.get("pending_operation")
    last_error = state.get("last_error")
    environment_status = derive_environment_status(state)

    lines = [
        f"환경 상태: {environment_status}",
        f"현재 namespace: {', '.join(namespaces) if namespaces else '없음'}",
    ]

    if active_users:
        user_lines = ", ".join(
            f"<@{user_id}> ({namespace})" for user_id, namespace in sorted(active_users.items())
        )
        lines.append(f"현재 실습 중: {user_lines}")
    else:
        lines.append("현재 실습 중: 없음")

    if pending:
        lines.append(
            f"진행 중 작업: {pending.get('operation', 'unknown')}({pending.get('namespace', 'unknown')})"
        )

    if last_error:
        lines.append(f"최근 오류: {last_error.get('message', 'unknown error')}")

    if state.get("updated_at"):
        lines.append(f"마지막 갱신: {state['updated_at']}")

    return "\n".join(lines)


def derive_environment_status(state: dict[str, Any]) -> str:
    pending = state.get("pending_operation")
    if pending:
        operation = pending.get("operation")
        if operation == "start":
            return "생성 중"
        if operation == "stop":
            return "삭제 중"

    if state.get("last_error"):
        return "오류"

    if state.get("infra_status") == "running":
        return "실습 가능"

    return "중지됨"


def handle_command(command_name: str, slack_user_id: str, request_id: str) -> dict[str, Any]:
    user_namespace_map = load_user_namespace_map()
    namespace = user_namespace_map.get(slack_user_id)
    if namespace is None:
        return json_response(403, {"response_type": "ephemeral", "text": "허용되지 않은 사용자입니다."})

    if command_name == "hello":
        return channel_response("hello, world!")

    if command_name == "status_dev":
        state = load_state()
        return channel_response(format_status_message(state))

    if command_name not in {"start_dev", "stop_dev"}:
        return json_response(400, {"response_type": "ephemeral", "text": f"지원하지 않는 명령어입니다: /{command_name}"})

    operation = "start" if command_name == "start_dev" else "stop"
    dispatch_workflow(
        owner=require_env("GITHUB_TARGET_OWNER"),
        repo=require_env("GITHUB_TARGET_REPO"),
        workflow_filename=os.environ.get("GITHUB_WORKFLOW_FILENAME", "orchestrate-environment.yml"),
        inputs={
            "operation": operation,
            "slack_user_id": slack_user_id,
            "namespace": namespace,
            "request_id": request_id,
        },
    )
    return channel_response(f"`/{command_name}` 요청을 접수했습니다. `/status_dev`로 확인하세요.")


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    try:
        method = (((event.get("requestContext") or {}).get("http") or {}).get("method") or "POST").upper()
        if method != "POST":
            return json_response(405, {"text": "POST only"})

        raw_body = decode_body(event)
        headers = normalize_headers(event)
        if not verify_slack_signature(
            signing_secret=require_env("SLACK_SIGNING_SECRET"),
            timestamp=headers.get("x-slack-request-timestamp"),
            signature=headers.get("x-slack-signature"),
            raw_body=raw_body,
        ):
            return json_response(401, {"response_type": "ephemeral", "text": "요청 서명 검증에 실패했습니다."})

        payload = parse_slack_command(raw_body)
        command_name = payload.get("command", "").lstrip("/")
        slack_user_id = payload.get("user_id", "")
        request_id = (
            ((event.get("requestContext") or {}).get("requestId"))
            or payload.get("trigger_id")
            or str(uuid.uuid4())
        )
        return handle_command(command_name=command_name, slack_user_id=slack_user_id, request_id=request_id)
    except Exception as exc:  # pragma: no cover - explicit error path
        return json_response(500, {"response_type": "ephemeral", "text": f"요청 처리 중 오류가 발생했습니다: {exc}"})
