"""Official OpenAI Graphiti client with explicit parameter and error boundaries."""
from graphiti_core.llm_client.openai_client import OpenAIClient
from graphiti_core.cross_encoder.client import CrossEncoderClient


MEMORY_VALIDATION_ERROR_CODES = frozenset({
    'openai_memory_structured_output_incomplete_or_refused',
    'openai_memory_json_output_incomplete_or_refused',
    'subscription_structured_schema_required',
    'subscription_response_failed',
    'subscription_response_incomplete',
    'subscription_duplicate_completion',
    'subscription_stream_truncated',
    'subscription_response_model_mismatch',
    'subscription_message_incomplete',
    'subscription_response_refused',
    'subscription_schema_fields_invalid',
    'subscription_output_item_invalid',
    'subscription_output_item_duplicate',
    'subscription_output_item_conflict',
    'subscription_output_items_incomplete',
    'subscription_output_missing',
    'subscription_event_after_completion',
})


def memory_validation_error_code(exc):
    """Return only our literal validation codes; never echo provider text."""
    if (type(exc) is ValueError and len(exc.args) == 1 and isinstance(exc.args[0], str)
            and exc.args[0] in MEMORY_VALIDATION_ERROR_CODES):
        return exc.args[0]
    return None


class LocalMemoryReranker(CrossEncoderClient):
    """Explicit local fallback; Graphiti must not create an unmetered SDK."""
    async def rank(self, query, passages):
        from .hybrid_retrieval import lexical_score
        return sorted([(text, float(lexical_score(text, query))) for text in passages],
                      key=lambda pair: pair[1], reverse=True)


class MemoryOpenAIClient(OpenAIClient):
    # Provider retries are the metered SDK's responsibility. Do not feed a local
    # pause/configuration exception back to a model as a repair prompt.
    MAX_RETRIES = 0

    async def _create_structured_completion(self, model, messages, temperature, max_tokens,
            response_model, reasoning=None, verbosity=None):
        response = await self.client.responses.parse(model=model, input=messages,
            max_output_tokens=max_tokens, text_format=response_model, store=False)
        if getattr(response, 'status', None) != 'completed' or getattr(response, 'output_parsed', None) is None:
            raise ValueError('openai_memory_structured_output_incomplete_or_refused')
        return response

    async def _create_completion(self, model, messages, temperature, max_tokens,
            response_model=None, reasoning=None, verbosity=None):
        response = await self.client.chat.completions.create(model=model, messages=messages,
            max_completion_tokens=max_tokens, response_format={'type': 'json_object'}, store=False)
        if (not response.choices or response.choices[0].finish_reason != 'stop'
                or getattr(response.choices[0].message, 'refusal', None)):
            raise ValueError('openai_memory_json_output_incomplete_or_refused')
        return response

    async def _generate_response(self, messages, response_model=None, max_tokens=None, model_size=None):
        # Do not use Graphiti's exception logger, which includes provider text.
        from .runtime import held_error
        try:
            converted = self._convert_messages_to_openai_format(messages)
            model = self._get_model_for_size(model_size)
            if response_model:
                response = await self._create_structured_completion(model, converted, None,
                    max_tokens or self.max_tokens, response_model)
                return self._handle_structured_response(response)
            response = await self._create_completion(model, converted, None, max_tokens or self.max_tokens)
            return self._handle_json_response(response)
        except Exception as exc:
            held = held_error(exc)
            if held is not None:
                raise held from None
            code = memory_validation_error_code(exc)
            if code is not None:
                raise ValueError(code) from None
            raise ValueError('openai_memory_' + type(exc).__name__) from None


class MemorySubscriptionClient(MemoryOpenAIClient):
    """ChatGPT plan inference only: explicit schema, Responses SSE, no fallback."""
    def __init__(self, *args, root, account_id, **kwargs):
        super().__init__(*args, **kwargs)
        self._subscription_root = root
        self._subscription_account_id = account_id

    def _wait(self, code, retry_after=None):
        from .runtime import runtime_module
        runtime_module('chatgpt_subscription').record_inference_failure(
            self._subscription_root, expected_account_id=self._subscription_account_id, code=code,
            retry_after_seconds=retry_after)
        raise runtime_module('memory_model_config').MemoryModelUnavailable('chatgpt_subscription_' + code)

    async def _create_structured_completion(self, model, messages, temperature, max_tokens,
            response_model, reasoning=None, verbosity=None):
        import json
        from types import SimpleNamespace
        from openai import APIStatusError
        from openai.lib._pydantic import to_strict_json_schema
        if response_model is None:
            raise ValueError('subscription_structured_schema_required')
        schema = to_strict_json_schema(response_model)
        converted = [{**message, 'role': 'developer' if message.get('role') == 'system' else message.get('role')}
                     for message in messages]
        completed = None
        added_items, done_items = {}, {}
        try:
            stream = await self.client.responses.create(model=model, input=converted, store=False, stream=True,
                text={'format': {'type':'json_schema','name':response_model.__name__,
                    'schema':schema,'strict':True}})
            async with stream:
                async for event in stream:
                    kind = getattr(event, 'type', None)
                    if completed is not None:
                        raise ValueError('subscription_duplicate_completion' if kind == 'response.completed'
                                         else 'subscription_event_after_completion')
                    if kind in {'response.output_item.added', 'response.output_item.done'}:
                        _subscription_record_item(event, added_items if kind.endswith('.added') else done_items)
                    if kind in {'response.failed', 'error'}:
                        error = getattr(getattr(event, 'response', None), 'error', None) or event
                        code = getattr(error, 'code', None)
                        if code in {'subscription_sharing_usage_limit_exceeded','subscription_sharing_usage_unavailable'}:
                            self._wait('usage_limit_exceeded' if code.endswith('limit_exceeded') else 'usage_unavailable')
                        raise ValueError('subscription_response_failed')
                    if kind == 'response.incomplete':
                        raise ValueError('subscription_response_incomplete')
                    if kind == 'response.completed':
                        if completed is not None:
                            raise ValueError('subscription_duplicate_completion')
                        completed = event.response
            if completed is None or getattr(completed, 'status', None) != 'completed':
                raise ValueError('subscription_stream_truncated')
            if getattr(completed, 'model', None) != model:
                raise ValueError('subscription_response_model_mismatch')
            parts = []
            for item in _subscription_completed_output(completed, added_items, done_items):
                if item.type == 'message':
                    if getattr(item, 'status', None) != 'completed':
                        raise ValueError('subscription_message_incomplete')
                    for content in item.content:
                        if content.type == 'refusal':
                            raise ValueError('subscription_response_refused')
                        if content.type == 'output_text':
                            parts.append(content.text)
            output = ''.join(parts)
            if not output:
                raise ValueError('subscription_output_missing')
            _required_schema_fields(json.loads(output), schema, schema)
            parsed = response_model.model_validate_json(output, strict=True, extra='forbid')
            return SimpleNamespace(status='completed', output_text=output, output_parsed=parsed,
                                   usage=completed.usage, model=completed.model)
        except APIStatusError as exc:
            retry = None
            try:
                retry = float(exc.response.headers.get('retry-after', ''))
            except (ValueError, TypeError):
                pass
            if exc.status_code in {401,403,429}:
                self._wait({401:'login_required',403:'access_denied',429:'usage_limit_exceeded'}[exc.status_code], retry)
            raise

    async def _create_completion(self, *args, **kwargs):
        raise ValueError('subscription_structured_schema_required')


def _subscription_record_item(event, items):
    index, item = getattr(event, 'output_index', None), getattr(event, 'item', None)
    identity = getattr(item, 'id', None)
    if (type(index) is not int or not 0 <= index < 1024 or not isinstance(identity, str)
            or not identity or not isinstance(getattr(item, 'type', None), str)):
        raise ValueError('subscription_output_item_invalid')
    if index in items or any(previous.id == identity for previous in items.values()):
        raise ValueError('subscription_output_item_duplicate')
    items[index] = item


def _subscription_completed_output(completed, added_items, done_items):
    """Recover finalized stream items when the completion omits its output.

    Responses create(stream=True) returns raw events. Unlike responses.stream(),
    it does not assemble output_item.done events into the completed response.
    Deltas are never sufficient evidence of a complete, non-refused message.
    """
    terminal = getattr(completed, 'output', None)
    if terminal is not None and not isinstance(terminal, list):
        raise ValueError('subscription_output_item_invalid')
    if done_items:
        if set(done_items) != set(range(len(done_items))) or (added_items and set(added_items) != set(done_items)):
            raise ValueError('subscription_output_items_incomplete')
        for index, added in added_items.items():
            done = done_items[index]
            if added.id != done.id or added.type != done.type:
                raise ValueError('subscription_output_item_conflict')
        finalized = [done_items[index] for index in sorted(done_items)]
        for item in finalized:
            status = getattr(item, 'status', None)
            if item.type == 'message' and status != 'completed':
                raise ValueError('subscription_message_incomplete')
            if status not in {None, 'completed'}:
                raise ValueError('subscription_output_items_incomplete')
        if terminal:
            if len(terminal) != len(finalized):
                raise ValueError('subscription_output_item_conflict')
            for supplied, done in zip(terminal, finalized):
                # Both objects were decoded with the same installed SDK schema.
                # Compare complete finalized values, excluding absent optionals.
                if supplied.model_dump(mode='json', exclude_none=True) != done.model_dump(mode='json', exclude_none=True):
                    raise ValueError('subscription_output_item_conflict')
        else:
            terminal = finalized
    if not terminal:
        raise ValueError('subscription_output_missing')
    return terminal


def _required_schema_fields(value, schema, root):
    """Enforce strict-schema required/extra fields in addition to Pydantic types."""
    if '$ref' in schema:
        target = root
        for key in schema['$ref'].removeprefix('#/').split('/'):
            target = target[key]
        return _required_schema_fields(value, target, root)
    if 'anyOf' in schema:
        for choice in schema['anyOf']:
            kind = choice.get('type')
            if kind == 'null' and value is not None:
                continue
            if kind == 'object' and not isinstance(value, dict):
                continue
            try:
                _required_schema_fields(value, choice, root)
                return
            except ValueError:
                pass
        raise ValueError('subscription_schema_fields_invalid')
    if isinstance(value, dict) and schema.get('type') == 'object':
        properties = schema.get('properties', {})
        if not set(schema.get('required', [])).issubset(value) or (
                schema.get('additionalProperties') is False and set(value) - set(properties)):
            raise ValueError('subscription_schema_fields_invalid')
        for key, item in value.items():
            if key in properties:
                _required_schema_fields(item, properties[key], root)
    if isinstance(value, list) and schema.get('type') == 'array':
        for item in value:
            _required_schema_fields(item, schema.get('items', {}), root)
