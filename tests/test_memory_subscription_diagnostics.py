"""Offline fixed-code diagnostics preserve validation while redacting errors."""
import importlib
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from pydantic import BaseModel, ValidationError
from openai import AsyncOpenAI, DefaultAsyncHttpxClient

CODE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(CODE / 'scripts'), str(CODE / 'tools/memory-adapter')]
from graphiti_core.llm_client import LLMConfig
from graphiti_core.prompts.models import Message
from javis_memory_adapter.openai_memory_client import (
    MemorySubscriptionClient, memory_validation_error_code,
)


class Answer(BaseModel):
    answer: str


class SubscriptionDiagnosticsTests(unittest.IsolatedAsyncioTestCase):
    async def error_from_response(self, error):
        client = MemorySubscriptionClient(config=LLMConfig(model='gpt-fixture'),
            client=SimpleNamespace(), root=Path('/synthetic-not-used'), account_id='synthetic-account')
        with patch.object(client, '_create_structured_completion', AsyncMock(side_effect=error)), \
                patch('javis_memory_adapter.runtime.held_error', return_value=None):
            with self.assertRaises(ValueError) as captured:
                await client._generate_response([Message(role='user', content='synthetic fixture')],
                                                response_model=Answer)
        return captured.exception

    async def test_model_mismatch_remains_a_rejected_response_with_specific_code(self):
        error = await self.error_from_response(ValueError('subscription_response_model_mismatch'))
        self.assertEqual(str(error), 'subscription_response_model_mismatch')
        self.assertEqual(memory_validation_error_code(error), 'subscription_response_model_mismatch')

    async def test_schema_failure_remains_a_rejected_response_with_specific_code(self):
        error = await self.error_from_response(ValueError('subscription_schema_fields_invalid'))
        self.assertEqual(str(error), 'subscription_schema_fields_invalid')

    async def test_arbitrary_provider_text_is_not_exposed(self):
        private = 'PRIVATE_PROVIDER_TEXT_WITH_FAKE_CREDENTIAL'
        error = await self.error_from_response(ValueError(private))
        self.assertEqual(str(error), 'openai_memory_ValueError')
        self.assertNotIn(private, str(error))
        self.assertIsNone(memory_validation_error_code(error))

    async def test_nonvalidation_exception_cannot_claim_a_validation_code(self):
        error = await self.error_from_response(RuntimeError('subscription_response_model_mismatch'))
        self.assertEqual(str(error), 'openai_memory_RuntimeError')
        self.assertIsNone(memory_validation_error_code(error))

    async def test_pydantic_error_reports_class_without_input_or_location_details(self):
        try:
            Answer.model_validate({'answer': {'PRIVATE_FIELD': 'PRIVATE_VALUE'}}, strict=True)
        except ValidationError as original:
            error = await self.error_from_response(original)
        self.assertEqual(str(error), 'openai_memory_ValidationError')
        self.assertNotIn('PRIVATE', str(error))

    def test_multi_argument_or_subclass_errors_are_not_echoed(self):
        class ProviderValueError(ValueError):
            pass
        for error in (ValueError('subscription_schema_fields_invalid', 'PRIVATE_SECOND_ARGUMENT'),
                      ProviderValueError('subscription_schema_fields_invalid')):
            self.assertIsNone(memory_validation_error_code(error))


class CompletedOutputAssemblyTests(unittest.IsolatedAsyncioTestCase):
    model = 'gpt-fixture'

    def message(self, text='{"answer":"ok"}', **changes):
        return {'id': 'msg_fixture', 'type': 'message', 'status': 'completed', 'role': 'assistant',
                'content': [{'type': 'output_text', 'text': text, 'annotations': []}], **changes}

    def done(self, item, index):
        return {'type': 'response.output_item.done', 'output_index': index, 'item': item}

    def completed(self, output):
        return {'type': 'response.completed', 'response': {'id': 'resp_fixture', 'object': 'response',
            'created_at': 1, 'model': self.model, 'status': 'completed', 'output': output,
            'usage': {'input_tokens': 12, 'output_tokens': 3, 'total_tokens': 15},
            'parallel_tool_calls': False, 'tool_choice': 'auto', 'tools': []}}

    async def call(self, events):
        httpx = importlib.import_module(DefaultAsyncHttpxClient.__mro__[1].__module__.split('.')[0])
        content = ''.join('data: ' + json.dumps(event) + '\n\n' for event in events).encode()
        calls = []

        def handler(request):
            calls.append(request)
            return httpx.Response(200, content=content, headers={'content-type': 'text/event-stream'})

        http = DefaultAsyncHttpxClient(transport=httpx.MockTransport(handler), trust_env=False)
        sdk = AsyncOpenAI(api_key='SYNTHETIC_ONLY', base_url='https://api.openai.com/v1',
                          http_client=http, max_retries=0)
        client = MemorySubscriptionClient(config=LLMConfig(model=self.model), client=sdk,
            root=Path('/synthetic-not-used'), account_id='synthetic-account')
        try:
            return await client._generate_response([Message(role='user', content='synthetic fixture')],
                                                   response_model=Answer)
        finally:
            self.assertEqual(len(calls), 1)
            await sdk.close()

    async def test_empty_or_omitted_terminal_output_uses_finalized_reasoning_and_message(self):
        reasoning = {'id': 'rs_fixture', 'type': 'reasoning', 'summary': []}
        for terminal_output in (None, []):
            with self.subTest(terminal_output=terminal_output):
                events = [self.done(reasoning, 0), self.done(self.message(), 1), self.completed(terminal_output)]
                self.assertEqual(await self.call(events), ({'answer': 'ok'}, 12, 3))

    async def test_nonempty_terminal_without_done_remains_supported(self):
        self.assertEqual(await self.call([self.completed([self.message()])]), ({'answer': 'ok'}, 12, 3))

    async def test_added_and_done_identity_and_terminal_values_must_agree(self):
        added = {'type': 'response.output_item.added', 'output_index': 0,
                 'item': self.message(status='in_progress', content=[])}
        events = [added, self.done(self.message(), 0), self.completed([self.message()])]
        self.assertEqual(await self.call(events), ({'answer': 'ok'}, 12, 3))
        for last in (self.completed([self.message('{"answer":"different"}')]),
                     self.completed([self.message(id='msg_other')])):
            with self.subTest(conflict=last['response']['output'][0]['id']):
                with self.assertRaisesRegex(ValueError, '^subscription_output_item_conflict$'):
                    await self.call([added, self.done(self.message(), 0), last])

    async def test_duplicate_indices_ids_gaps_and_missing_done_are_rejected(self):
        message = self.message()
        added = {'type': 'response.output_item.added', 'output_index': 1,
                 'item': self.message(id='msg_other', status='in_progress', content=[])}
        cases = [
            ([self.done(message, 0), self.done(message, 0)], 'subscription_output_item_duplicate'),
            ([self.done(message, 0), self.done(message, 1)], 'subscription_output_item_duplicate'),
            ([self.done(message, 1)], 'subscription_output_items_incomplete'),
            ([added, self.done(message, 0)], 'subscription_output_items_incomplete'),
        ]
        for events, code in cases:
            with self.subTest(code=code, events=len(events)):
                with self.assertRaisesRegex(ValueError, '^' + code + '$'):
                    await self.call(events + [self.completed([])])

    async def test_changed_item_identity_incomplete_or_refused_done_never_becomes_success(self):
        added = {'type': 'response.output_item.added', 'output_index': 0,
                 'item': self.message(id='msg_other', status='in_progress', content=[])}
        cases = [
            ([added, self.done(self.message(), 0)], 'subscription_output_item_conflict'),
            ([self.done(self.message(status='in_progress'), 0)], 'subscription_message_incomplete'),
            ([self.done(self.message(content=[{'type':'refusal','refusal':'synthetic refusal'}]), 0)],
             'subscription_response_refused'),
        ]
        for events, code in cases:
            with self.subTest(code=code):
                with self.assertRaisesRegex(ValueError, '^' + code + '$'):
                    await self.call(events + [self.completed([])])

    async def test_deltas_alone_and_done_without_successful_terminal_are_rejected(self):
        delta = {'type': 'response.output_text.delta', 'output_index': 0, 'content_index': 0,
                 'item_id': 'msg_fixture', 'delta': '{"answer":"ok"}', 'sequence_number': 0}
        with self.assertRaisesRegex(ValueError, '^subscription_output_missing$'):
            await self.call([delta, self.completed([])])
        with self.assertRaisesRegex(ValueError, '^subscription_stream_truncated$'):
            await self.call([self.done(self.message(), 0)])

    async def test_finalized_items_do_not_relax_schema_model_or_terminal_checks(self):
        cases = [
            ([self.done(self.message('{"answer":5}'), 0), self.completed([])], 'openai_memory_ValidationError'),
            ([self.done(self.message('{"answer":"ok","extra":1}'), 0), self.completed([])],
             'subscription_schema_fields_invalid'),
            ([self.done(self.message(), 0), self.completed([]), self.completed([])],
             'subscription_duplicate_completion'),
            ([self.completed([self.message()]), self.done(self.message(), 0)],
             'subscription_event_after_completion'),
        ]
        mismatched = self.completed([])
        mismatched['response']['model'] = 'gpt-other'
        cases.append(([self.done(self.message(), 0), mismatched], 'subscription_response_model_mismatch'))
        for events, code in cases:
            with self.subTest(code=code):
                with self.assertRaisesRegex(ValueError, '^' + code + '$'):
                    await self.call(events)


if __name__ == '__main__':
    unittest.main()
