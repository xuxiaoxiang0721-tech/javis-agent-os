"""Meter every actual OpenAI SDK HTTP attempt without storing prompts or vectors.

The SDK and Graphiti may retry independently. Instrumenting AsyncClient.send,
rather than SDK create(), records all of those attempts separately. The default
OpenAI HTTP client supplies the SDK's normal proxy, timeout and connection limits.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from typing import Any

from openai import DefaultAsyncHttpxClient


logger = logging.getLogger(__name__)


class UsageMeterWriteError(RuntimeError):
    """An accounting start failed; no request may be sent on that attempt."""


class MeteredAsyncHttpClient(DefaultAsyncHttpxClient):
    MAX_JSON_BYTES = 64 * 1024 * 1024

    def __init__(self, *, meter, stage: str, model: str, run_id=None, scope=None, request_guard=None,
                 billing_mode='api', request_validator=None, **kwargs):
        # Redirects inside HTTPX bypass this send-level accounting hook and
        # can change the credential destination. Never follow them implicitly.
        kwargs['follow_redirects'] = False
        super().__init__(**kwargs)
        self._usage_meter = meter
        self._usage_stage = stage
        self._usage_model = model
        self._usage_run_id = run_id
        self._usage_scope = scope
        self._request_guard = request_guard
        if billing_mode not in {'api', 'subscription'}:
            raise ValueError('invalid_billing_mode')
        self._billing_mode = billing_mode
        self._request_validator = request_validator

    async def _request_metadata(self, request):
        # Content is read only to select allowlisted scalar metadata. It is never
        # passed to the meter, exception strings, logging, or persistent storage.
        value = {}
        try:
            body = await request.aread()
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                value = parsed
        except (ValueError, TypeError):
            pass
        model = value.get("model")
        if not isinstance(model, str) or not model or len(model) > 256:
            model = self._usage_model
        embedding = request.url.path.rstrip('/').endswith('/embeddings')
        meta: dict[str, Any] = {"request_type": "embedding" if embedding else "chat"}
        if self._billing_mode == 'subscription':
            if (request.method != 'POST' or str(request.url) != 'https://api.openai.com/v1/responses'
                    or value.get('store') is not False or value.get('stream') is not True):
                raise ValueError('subscription_request_not_allowed')
            meta['billing_mode'] = 'subscription'
        if type(value.get("enable_thinking")) is bool:
            meta["enable_thinking"] = value["enable_thinking"]
        if embedding and isinstance(value.get("input"), list):
            inputs = value["input"]
            # A flat token-ID array is one embedding input, not a text batch.
            meta["batch_size"] = 1 if inputs and all(type(x) is int for x in inputs) else len(inputs)
        host = request.url.host
        if request.url.port is not None:
            host = f"{host}:{request.url.port}"
        return model, host, meta

    def _start(self, model, host, meta):
        attempt = 'usage_' + uuid.uuid4().hex
        if self._request_guard is not None:
            self._request_guard(scope=self._usage_scope, stage=self._usage_stage, attempt_id=attempt)
        else:
            from .runtime import runtime_module
            root = getattr(self._usage_meter, 'root', None)
            if root is None:
                raise UsageMeterWriteError('memory_processing_root_required; request_not_sent')
            runtime_module('memory_controls').reserve_call(root, self._usage_scope, self._usage_stage, attempt)
        try:
            return self._usage_meter.start(self._usage_stage, model, host,
                run_id=self._usage_run_id, scope=self._usage_scope, request_meta=meta, attempt_id=attempt)
        except Exception:
            raise UsageMeterWriteError("usage_start_failed; request_not_sent") from None

    def _finish(self, attempt_id, **kwargs):
        try:
            return self._usage_meter.finish(attempt_id, **kwargs)
        except Exception:
            # Keep the durable pending start and preserve the real response.
            # Raising here would make the SDK retry a successful, paid call.
            logger.warning("usage_finish_failed; attempt_remains_pending")
            return None

    async def send(self, request, **kwargs):
        kwargs['follow_redirects'] = False
        model, host, meta = await self._request_metadata(request)
        if self._request_validator is not None:
            self._request_validator(request)
        attempt_id = self._start(model, host, meta)
        started = time.perf_counter()
        response = None
        try:
            response = await super().send(request, **kwargs)
            # Buffer the bounded extraction response for accounting. HTTP still
            # uses stream=true; the SDK consumes all SSE events from this cache.
            await response.aread()
        except BaseException as error:
            self._finish(attempt_id, usage=None, actual_model=None,
                status="cancelled" if isinstance(error, asyncio.CancelledError) else "transport_error",
                http_status=response.status_code if response is not None else None,
                error_type=type(error).__name__, duration_ms=(time.perf_counter() - started) * 1000,
                provider_request_id=None)
            if response is not None:
                try:
                    await response.aclose()
                except BaseException:
                    pass
            raise

        status = "success" if 200 <= response.status_code < 300 else "http_error"
        usage = None
        actual_model = None
        error_type = None
        try:
            if len(response.content) > self.MAX_JSON_BYTES:
                raise ValueError("response_too_large_for_usage_parser")
            # Subscription requests already passed the endpoint/store/stream
            # checks above. Parse their required SSE protocol even when the
            # provider omits or mislabels Content-Type; never accept plain JSON.
            if (self._billing_mode == 'subscription' or
                    response.headers.get('content-type', '').split(';')[0].strip() == 'text/event-stream'):
                from .subscription_stream import inspect_sse
                summary = inspect_sse(response.content)
                usage, actual_model = summary['usage'], summary['model']
                if status == 'success' and summary['status'] != 'completed':
                    status, error_type = 'invalid_response', summary['error_type']
            else:
                value = response.json()
                if not isinstance(value, dict):
                    raise ValueError("non_object_response")
                usage = value.get("usage") if isinstance(value.get("usage"), dict) else None
                actual_model = value.get("model") if isinstance(value.get("model"), str) else None
        except (ValueError, TypeError):
            error_type = "UsageResponseUnparseable"
            if status == "success":
                status = "invalid_response"
        self._finish(attempt_id, usage=usage, actual_model=actual_model, status=status,
            http_status=response.status_code, error_type=error_type,
            duration_ms=(time.perf_counter() - started) * 1000,
            provider_request_id=response.headers.get("x-request-id") or response.headers.get("request-id"))
        return response
