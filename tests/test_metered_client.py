"""No-network HTTP-attempt metering tests, including SDK and Graphiti retries."""
import asyncio
import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE / 'tools/memory-adapter'))
from openai import AsyncOpenAI, DefaultAsyncHttpxClient, APIStatusError, APITimeoutError, APIConnectionError
from javis_memory_adapter.metered_client import MeteredAsyncHttpClient, UsageMeterWriteError

# The installed SDK may use httpx2; using a different HTTPX family's transport
# silently bypasses or breaks the SDK's expected response/client types.
httpx = importlib.import_module(DefaultAsyncHttpxClient.__mro__[1].__module__.split('.')[0])


class RecordingMeter:
    def __init__(self, fail_start=False, fail_finish=False):
        self.starts = []; self.finishes = []
        self.start_calls = 0; self.fail_start = fail_start; self.fail_finish = fail_finish

    def start(self, stage, model, provider_host, **kwargs):
        self.start_calls += 1
        if self.fail_start:
            raise OSError('DO_NOT_LOG_START_SECRET')
        attempt = 'attempt-' + str(self.start_calls)
        kwargs.pop('attempt_id', None)
        self.starts.append({'attempt_id': attempt, 'stage': stage, 'model': model,
                            'provider_host': provider_host, **kwargs})
        return attempt

    def finish(self, attempt, **kwargs):
        if self.fail_finish:
            raise OSError('DO_NOT_LOG_FINISH_SECRET')
        self.finishes.append({'attempt_id': attempt, **kwargs})


def completion(content='{"ok":true}', usage=True):
    value = {'id': 'synthetic-response', 'object': 'chat.completion', 'created': 1,
             'model': 'returned-model',
             'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': content},
                          'finish_reason': 'stop'}]}
    if usage:
        value['usage'] = {'prompt_tokens': 12, 'completion_tokens': 3, 'total_tokens': 15}
    return value


class MeteredClientTests(unittest.IsolatedAsyncioTestCase):
    async def sdk(self, handler, meter=None, stage='graphiti', retries=0):
        meter = meter or RecordingMeter()
        http = MeteredAsyncHttpClient(meter=meter, stage=stage, model='configured-model',
            request_guard=lambda **kw: None,
            run_id='synthetic-run', scope='invest', transport=httpx.MockTransport(handler), trust_env=False)
        sdk = AsyncOpenAI(api_key='SYNTHETIC_API_SECRET', base_url='https://meter.invalid/v1',
                          max_retries=retries, http_client=http)
        self.addAsyncCleanup(sdk.close)
        return sdk, meter

    async def test_sdk_429_retry_is_two_actual_attempts(self):
        meter = RecordingMeter(); calls = []
        async def handler(request):
            calls.append(1)
            self.assertEqual(len(meter.starts), len(calls))
            if len(calls) == 1:
                return httpx.Response(429, json={'error': {'message': 'synthetic throttle'}},
                                      headers={'retry-after-ms': '1'})
            return httpx.Response(200, json=completion(), headers={'x-request-id': 'request-2'})
        sdk, _ = await self.sdk(handler, meter, retries=1)
        result = await sdk.chat.completions.create(model='request-model', messages=[{'role':'user','content':'PRIVATE_BODY_SECRET'}])
        self.assertEqual(result.model, 'returned-model')
        self.assertEqual(len(meter.starts), 2)
        self.assertEqual([r['status'] for r in meter.finishes], ['http_error', 'success'])
        self.assertEqual([r['usage'] for r in meter.finishes], [None, {'prompt_tokens':12,'completion_tokens':3,'total_tokens':15}])
        self.assertEqual(meter.finishes[1]['provider_request_id'], 'request-2')
        self.assertEqual(meter.starts[0]['model'], 'request-model')
        self.assertNotIn('SECRET', json.dumps(meter.starts + meter.finishes))

    async def test_success_without_usage_is_explicit_unknown(self):
        sdk, meter = await self.sdk(lambda request: httpx.Response(200, json=completion(usage=False)))
        await sdk.chat.completions.create(model='request-model', messages=[])
        self.assertIsNone(meter.finishes[0]['usage'])
        self.assertEqual(meter.finishes[0]['status'], 'success')
        self.assertEqual(meter.finishes[0]['http_status'], 200)

    async def test_invalid_http_json_keeps_attempt_unknown(self):
        sdk, meter = await self.sdk(lambda request: httpx.Response(200, content=b'broken envelope'))
        # Using the HTTP client directly isolates SDK-version-specific handling
        # of successful non-JSON responses; the provider attempt is still real.
        request = sdk._client.build_request('POST', 'https://meter.invalid/v1/chat/completions', json={'model':'m'})
        response = await sdk._client.send(request, stream=True)
        self.assertEqual(response.content, b'broken envelope')
        self.assertEqual(meter.finishes[0]['status'], 'invalid_response')
        self.assertIsNone(meter.finishes[0]['usage'])

    async def test_graphiti_json_retry_keeps_both_paid_usages(self):
        from graphiti_core.llm_client import LLMConfig
        from graphiti_core.llm_client.openai_generic_client import OpenAIGenericClient
        from graphiti_core.prompts.models import Message
        from tenacity import wait_none
        calls = []
        def handler(request):
            calls.append(1)
            return httpx.Response(200, json=completion('broken model JSON' if len(calls)==1 else '{"ok":true}'))
        sdk, meter = await self.sdk(handler)
        llm = OpenAIGenericClient(config=LLMConfig(api_key='synthetic', model='m'), client=sdk)
        with patch.object(llm._generate_response_with_retry.retry, 'wait', wait_none()):
            result = await llm.generate_response([Message(role='system',content='Return JSON'),Message(role='user',content='synthetic')])
        self.assertTrue(result['ok'])
        self.assertEqual(len(meter.starts), 2)
        self.assertEqual(sum(row['usage']['total_tokens'] for row in meter.finishes), 30)
        self.assertTrue(all(row['status']=='success' for row in meter.finishes))

    async def test_http_error_status_and_body_not_persisted(self):
        sdk, meter = await self.sdk(lambda request: httpx.Response(400, json={'error':{'message':'PRIVATE_ERROR_SECRET'}}))
        with self.assertRaises(APIStatusError):
            await sdk.chat.completions.create(model='m',messages=[])
        self.assertEqual(meter.finishes[0]['status'], 'http_error')
        self.assertEqual(meter.finishes[0]['http_status'], 400)
        self.assertNotIn('SECRET', json.dumps(meter.starts + meter.finishes))

    async def test_start_failure_prevents_every_network_attempt(self):
        meter = RecordingMeter(fail_start=True); network = []
        def handler(request):
            network.append(1)
            return httpx.Response(200,json=completion())
        sdk, _ = await self.sdk(handler, meter, retries=1)
        with self.assertRaises((APIConnectionError, UsageMeterWriteError)):
            await sdk.chat.completions.create(model='m',messages=[])
        self.assertGreaterEqual(meter.start_calls, 1)
        self.assertEqual(network, [])

    async def test_finish_failure_preserves_response_and_does_not_retry(self):
        meter = RecordingMeter(fail_finish=True); network = []
        def handler(request):
            network.append(1)
            return httpx.Response(200,json=completion())
        sdk, _ = await self.sdk(handler, meter, retries=2)
        with self.assertLogs('javis_memory_adapter.metered_client', level='WARNING') as captured:
            result = await sdk.chat.completions.create(model='m',messages=[])
        self.assertEqual(result.model, 'returned-model')
        self.assertEqual(len(network), 1)
        self.assertEqual(len(meter.starts), 1)
        self.assertEqual(meter.finishes, [])
        self.assertNotIn('SECRET', ''.join(captured.output))

    async def test_timeout_is_recorded_without_error_message(self):
        def handler(request):
            raise httpx.ReadTimeout('PRIVATE_TIMEOUT_SECRET', request=request)
        sdk, meter = await self.sdk(handler)
        with self.assertRaises(APITimeoutError):
            await sdk.chat.completions.create(model='m',messages=[])
        self.assertEqual(meter.finishes[0]['status'], 'transport_error')
        self.assertEqual(meter.finishes[0]['error_type'], 'ReadTimeout')
        self.assertIsNone(meter.finishes[0]['usage'])
        self.assertNotIn('SECRET', json.dumps(meter.starts + meter.finishes))

    async def test_cancellation_finishes_attempt_without_retry(self):
        entered = asyncio.Event()
        async def handler(request):
            entered.set()
            await asyncio.Event().wait()
        sdk, meter = await self.sdk(handler, retries=2)
        task = asyncio.create_task(sdk.chat.completions.create(model='m',messages=[]))
        await asyncio.wait_for(entered.wait(), 2)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(len(meter.starts), 1)
        self.assertEqual(meter.finishes[0]['status'], 'cancelled')
        self.assertIsNone(meter.finishes[0]['usage'])

    async def test_large_embedding_payload_keeps_usage_and_batch_metadata(self):
        vectors = [0.125] * 200000
        def handler(request):
            return httpx.Response(200,json={'model':'embedding-returned','data':[{'embedding':vectors}],
                                          'usage':{'prompt_tokens':150,'total_tokens':150}})
        sdk, meter = await self.sdk(handler, stage='embedding')
        request = sdk._client.build_request('POST','https://meter.invalid/v1/embeddings',
            json={'model':'emb','input':['PRIVATE_INPUT_SECRET']*10})
        response = await sdk._client.send(request,stream=True)
        self.assertGreater(len(response.content), 1024*1024)
        self.assertEqual(meter.finishes[0]['usage']['total_tokens'],150)
        self.assertEqual(meter.starts[0]['request_meta'],{'request_type':'embedding','batch_size':10})
        self.assertNotIn('SECRET',json.dumps(meter.starts+meter.finishes))

    async def test_only_actual_request_thinking_flag_is_recorded(self):
        sdk,meter = await self.sdk(lambda request: httpx.Response(200,json=completion()))
        await sdk.chat.completions.create(model='m',messages=[],extra_body={'enable_thinking':False,'secret':'PRIVATE_EXTRA_SECRET'})
        self.assertEqual(meter.starts[0]['request_meta'],{'request_type':'chat','enable_thinking':False})
        self.assertNotIn('SECRET',json.dumps(meter.starts+meter.finishes))

    async def test_adapter_batches_each_request_and_closes_both_sdks(self):
        from javis_memory_adapter.adapter import MemoryAdapter
        meter = RecordingMeter(); batch_sizes=[]
        def handler(request):
            payload=json.loads(request.content)
            batch_sizes.append(len(payload['input']))
            return httpx.Response(200,json={'model':'emb','object':'list',
                'data':[{'index':i,'object':'embedding','embedding':[0.1,0.2]} for i in range(len(payload['input']))],
                'usage':{'prompt_tokens':len(payload['input']),'total_tokens':len(payload['input'])}})
        class Graph:
            def __init__(self,*args,llm_client,embedder,cross_encoder):
                self.llm_client=llm_client;self.embedder=embedder;self.driver=object();self.closed=False
                self.cross_encoder=cross_encoder
            async def close(self):self.closed=True
        def metered(**kwargs):
            return MeteredAsyncHttpClient(**kwargs, request_guard=lambda **kw: None,
                transport=httpx.MockTransport(handler),trust_env=False)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            sys.path.insert(0, str(CODE / 'scripts'))
            import memory_controls
            memory_controls.update(root, expected_revision=0, global_enabled=True, command_id='test-enable')
            adapter=MemoryAdapter('synthetic-meter',meta_dir=root/'memory/screen/graph/test',
                env_path=root/'missing.env',usage_root=root,usage_run_id='synthetic-run',usage_scope='invest')
            with patch.dict(os.environ,{'OPENAI_MEMORY_API_KEY':'SYNTHETIC_API_SECRET_LONG',
                    'OPENAI_MEMORY_MODEL':'gpt-test-2026-01-01',
                    'NEO4J_URI':'bolt://invalid','NEO4J_USER':'synthetic','NEO4J_PASSWORD':'SYNTHETIC_DB_SECRET'},clear=True), \
                 patch('javis_memory_adapter.usage_meter.UsageMeter',return_value=meter), \
                 patch('javis_memory_adapter.metered_client.MeteredAsyncHttpClient',side_effect=metered), \
                 patch('graphiti_core.Graphiti',Graph):
                await adapter._ensure()
                graph=adapter._g;sdk_clients=list(adapter._sdk_clients)
                self.assertEqual(type(graph.cross_encoder).__name__, 'LocalMemoryReranker')
                self.assertFalse(hasattr(graph.cross_encoder,'client'))
                vectors=await graph.embedder.create_batch(['SYNTHETIC_TEXT']*25)
                await adapter.close()
            self.assertEqual(len(vectors),25)
            self.assertEqual(batch_sizes,[10,10,5])
            self.assertEqual(len(meter.starts),3)
            self.assertTrue(all(row['stage']=='embedding' for row in meter.starts))
            self.assertEqual(sum(row['usage']['total_tokens'] for row in meter.finishes),25)
            self.assertTrue(graph.closed)
            self.assertTrue(all(client.is_closed() for client in sdk_clients))
            self.assertEqual(adapter._sdk_clients,[])

    async def test_usage_root_inference_never_uses_production_fallback(self):
        from javis_memory_adapter.adapter import MemoryAdapter
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            adapter=MemoryAdapter('synthetic-meter',meta_dir=root/'other-meta')
            self.assertIsNone(adapter.usage_root)
            self.assertEqual(adapter.usage_metering,'unscoped_not_recorded')
            candidate=MemoryAdapter('synthetic-meter',meta_dir=root/'memory/screen/graph/run')
            self.assertEqual(candidate.usage_root,root.resolve())


if __name__=='__main__':
    unittest.main()
