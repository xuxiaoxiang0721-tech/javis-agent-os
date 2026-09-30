"""TypeSafe's fixed-endpoint System One transport, with per-attempt accounting.

No SDK, automatic retry, environment mutation, or OpenAI/Qwen credentials are used.
Application policy validates the individual typed answers. This module only
accepts bounded JSON and preserves the provider's response shape.
"""
from __future__ import annotations

import asyncio
import json
import logging
import math
import os
from pathlib import Path
import re
import socket
import stat
import sys
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

CODE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE_ROOT / "tools/memory-adapter"))
from javis_memory_adapter.usage_meter import UsageMeter

ENDPOINT = "https://api.typesafe.ai/v1/systemone"
PROVIDER_HOST = "api.typesafe.ai"
# These are deliberately conservative byte limits, not token estimates. Never
# truncate source material to fit: the caller must reduce its candidate batch.
MAX_STATE_QUESTION_BYTES = 28 * 1024
MAX_REQUEST_BYTES = 56 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_ENV_BYTES = 16 * 1024
_LABEL = re.compile(r"[A-Za-z0-9_.:/-]{1,160}\Z")
_LOGGER = logging.getLogger(__name__)


class JevError(RuntimeError):
    code = "jev_error"

    def __init__(self):
        super().__init__(self.code)


class JevNotConfigured(JevError):
    code = "jev_credentials_unconfigured"


class JevAuthenticationError(JevError):
    code = "jev_authentication_failed"


class JevTransientError(JevError):
    code = "jev_transient_error"


class JevRequestTooLarge(JevError):
    code = "jev_request_too_large"


class JevInvalidRequest(JevError):
    code = "jev_invalid_request"


class JevInvalidResponse(JevError):
    code = "jev_invalid_response"


class JevHTTPError(JevError):
    code = "jev_http_error"


class _CredentialsFileError(Exception):
    def __init__(self, status):
        self.status = status


def _key(value):
    """Reject empty/template values without assuming a secret-key prefix."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    canonical = re.sub(r"[\s_-]+", "", value).casefold()
    if (not value or len(value) > 4096 or not value.isascii()
            or any(ord(c) <= 32 or ord(c) == 127 for c in value)
            or "<" in value or ">" in value or "${" in value
            or canonical in {"...", "…", "changeme", "replaceme",
                             "replacewithyourapikey", "yourapikey", "yourtypesafeapikey",
                             "typesafeapikey", "yourkey", "apikey", "placeholder", "none", "null"}
            or value.casefold().startswith(("your_", "your-", "replace_", "replace-"))):
        return None
    return value


def _read_key_file(path):
    """Read a private regular file without following links or evaluating shell."""
    path = Path(os.path.abspath(path))
    # POSIX ownership/mode checks are required. Windows ACLs cannot be inferred
    # from chmod bits; a Windows caller can provide the environment variable.
    if not hasattr(os, "geteuid") or not hasattr(os, "O_NOFOLLOW"):
        if not path.exists():
            return None
        raise _CredentialsFileError("unsafe_credentials_file")
    fd = None
    try:
        for item in (*reversed(path.parents), path):
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise _CredentialsFileError("unsafe_credentials_file")
        before = path.lstat()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or info.st_mode & 0o077
                or (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino)):
            raise _CredentialsFileError("unsafe_credentials_file")
        if info.st_size > MAX_ENV_BYTES:
            raise _CredentialsFileError("invalid_credentials_file")
        raw = os.read(fd, MAX_ENV_BYTES + 1)
        after = os.fstat(fd)
        if (len(raw) > MAX_ENV_BYTES or
                (info.st_size, info.st_mtime_ns, info.st_ctime_ns) !=
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise _CredentialsFileError("invalid_credentials_file")
        text = raw.decode("utf-8-sig")
    except FileNotFoundError:
        return None
    except _CredentialsFileError:
        raise
    except (OSError, UnicodeError):
        raise _CredentialsFileError("unsafe_credentials_file") from None
    finally:
        if fd is not None:
            os.close(fd)
    found = False
    value = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"(?:export\s+)?TYPESAFE_API_KEY\s*=\s*(.*)", line)
        if not match or found:
            raise _CredentialsFileError("invalid_credentials_file")
        found = True
        raw_value = match.group(1).strip()
        if raw_value[:1] in ("'", '"'):
            quote = raw_value[0]
            quoted = re.fullmatch(re.escape(quote) + r"([^\r\n]*?)" + re.escape(quote) + r"\s*(?:#.*)?", raw_value)
            if not quoted or quote in quoted.group(1):
                raise _CredentialsFileError("invalid_credentials_file")
            value = quoted.group(1)
        else:
            value = re.split(r"\s+#", raw_value, maxsplit=1)[0].strip()
            if value.startswith("#"):
                value = ""
    return _key(value)


def _credentials(root, env_path=None):
    # An explicitly empty environment value intentionally disables file fallback.
    if "TYPESAFE_API_KEY" in os.environ:
        return _key(os.environ["TYPESAFE_API_KEY"])
    expected = Path(os.path.abspath(Path(root) / "tools/typesafe/.env"))
    # Keep the argument for dependency injection compatibility, but never read
    # Graphiti's dotenv (or a different provider's secret file) by accident.
    if env_path is not None and Path(os.path.abspath(env_path)) != expected:
        raise _CredentialsFileError("invalid_credentials_file")
    return _read_key_file(expected)


def credentials_status(root):
    """Read-only public projection; never disclose key, hash, or file location."""
    try:
        configured = bool(_credentials(root))
    except _CredentialsFileError as exc:
        return {"configured": False, "status": exc.status}
    return {"configured": configured, "status": "configured" if configured else "not_configured"}


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")


def _payload(state, questions, model):
    if not isinstance(model, str) or not _LABEL.fullmatch(model):
        raise JevInvalidRequest()
    if not isinstance(questions, dict) or not questions:
        raise JevInvalidRequest()
    if not isinstance(state, (str, dict, list)) and state is not None:
        raise JevInvalidRequest()
    try:
        state_size = len(_json_bytes(state))
        for name, question in questions.items():
            if (not isinstance(name, str) or not name or not isinstance(question, dict)
                    or question.get("type") not in {"noul", "choice", "score"}):
                raise JevInvalidRequest()
            if state_size + len(_json_bytes({name: question})) > MAX_STATE_QUESTION_BYTES:
                raise JevRequestTooLarge()
        data = _json_bytes({"model": model, "state": state, "questions": questions})
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError):
        raise JevInvalidRequest() from None
    if len(data) > MAX_REQUEST_BYTES:
        raise JevRequestTooLarge()
    return data


def _safe_label(value):
    return value if isinstance(value, str) and _LABEL.fullmatch(value) else None


def _usage_fields(body, headers):
    body = body if isinstance(body, dict) else {}
    raw = body.get("usage")
    usage = None
    if isinstance(raw, dict):
        usage = {key: raw[key] for key in ("input_tokens", "output_tokens", "total_tokens")
                 if type(raw.get(key)) is int and 0 <= raw[key] <= 10**12}
    return {"usage": usage, "actual_model": _safe_label(body.get("model")),
            "provider_request_id": _safe_label(headers.get("x-typesafe-request-id") if headers else None)}


def _read_json(response):
    data = response.read(MAX_RESPONSE_BYTES + 1)
    if len(data) > MAX_RESPONSE_BYTES:
        raise JevInvalidResponse()
    try:
        value = json.loads(data)
    except (ValueError, UnicodeError, RecursionError):
        raise JevInvalidResponse() from None
    if not isinstance(value, dict):
        raise JevInvalidResponse()
    return value


class JevClient:
    def __init__(self, root, run_id=None, scope=None, timeout=60, env_path=None):
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0 < timeout <= 300):
            raise JevInvalidRequest()
        self.root, self.env_path = Path(root), env_path
        self.run_id, self.scope, self.timeout = run_id, scope, timeout
        self.meter = UsageMeter(root)

    async def evaluate(self, state, questions, *, model, stage):
        try:
            key = _credentials(self.root, self.env_path)
        except _CredentialsFileError:
            raise JevNotConfigured() from None
        if not key:
            raise JevNotConfigured()
        data = _payload(state, questions, model)

        def request():
            from memory_controls import reserve_call
            # One reservation per actual urllib request. Transport has no retries.
            reserve_call(self.root, self.scope, stage, 'jev_' + uuid.uuid4().hex)
            req = Request(ENDPOINT, data=data, method="POST", headers={
                "Authorization": "Bearer " + key, "Content-Type": "application/json", "Accept": "application/json"})
            # start() is durable and must succeed before the first network byte.
            attempt = self.meter.start(stage, model, PROVIDER_HOST,
                                       run_id=self.run_id, scope=self.scope)
            started = time.monotonic()

            def finish(**fields):
                try:
                    self.meter.finish(attempt, duration_ms=round((time.monotonic() - started) * 1000), **fields)
                except Exception:
                    # Preserve the paid response. A retry would incur a new charge;
                    # the durable start remains pending for accounting inspection.
                    _LOGGER.warning("jev_usage_finish_failed; request remains pending")

            status = None
            headers = None
            body = None
            try:
                with build_opener(_NoRedirect()).open(req, timeout=self.timeout) as response:
                    status, headers = response.status, response.headers
                    body = _read_json(response)
                    if (not _safe_label(body.get("model")) or not isinstance(body.get("answers"), dict)):
                        raise JevInvalidResponse()
            except HTTPError as exc:
                status, headers = exc.code, exc.headers
                try:
                    body = _read_json(exc)
                except Exception:
                    body = None
                finally:
                    exc.close()
                finish(**_usage_fields(body, headers), status="http_error", http_status=status, error_type="HTTPError")
                if status in (401, 403):
                    raise JevAuthenticationError() from None
                if status in (408, 429) or 500 <= status <= 599:
                    raise JevTransientError() from None
                raise JevHTTPError() from None
            except JevInvalidResponse:
                finish(**_usage_fields(body, headers), status="invalid_response", http_status=status,
                       error_type="InvalidResponse")
                raise JevInvalidResponse() from None
            except (URLError, TimeoutError, socket.timeout, OSError):
                finish(**_usage_fields(body, headers), status="transport_error", http_status=status,
                       error_type="TransportError")
                raise JevTransientError() from None
            except Exception:
                finish(**_usage_fields(body, headers), status="invalid_response" if status else "transport_error",
                       http_status=status, error_type="UnexpectedTransportError")
                raise JevInvalidResponse() from None
            finish(**_usage_fields(body, headers), status="success", http_status=status)
            return body

        # Cancelling the asyncio waiter cannot stop urllib's worker thread. It
        # still records the actual response, instead of fabricating zero usage.
        return await asyncio.to_thread(request)
