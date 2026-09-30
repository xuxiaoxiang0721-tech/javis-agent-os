"""Offline-only subscription protocol, independent embedding and accounting fixtures."""
import asyncio
import importlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch, AsyncMock

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE/'scripts'))
sys.path.insert(0, str(CODE/'tools/memory-adapter'))
import memory_model_config as config
import memory_controls
from javis_memory_adapter.metered_client import MeteredAsyncHttpClient
from javis_memory_adapter.usage_meter import UsageMeter, recent, summary
from javis_memory_adapter.openai_memory_client import MemorySubscriptionClient
from graphiti_core.llm_client import LLMConfig
from graphiti_core.prompts.models import Message
from openai import AsyncOpenAI, DefaultAsyncHttpxClient
from pydantic import BaseModel
httpx = importlib.import_module(DefaultAsyncHttpxClient.__mro__[1].__module__.split('.')[0])

MODEL='gpt-5.4-mini-2026-03-17'


def subscription_stub():
    class SubscriptionError(ValueError):
        def __init__(self, code): self.code=code; super().__init__(code)
    state={'account_id':'acct_fixture','connected':True,'requires_login':False,'plan_usage':True,
           'availability_code':None,'retry_at':None}
    def failure(root, expected_account_id, code, retry_after_seconds=None):
        if expected_account_id != state['account_id']:
            raise SubscriptionError('chatgpt_subscription_account_changed')
        state['availability_code']=code
    return types.SimpleNamespace(status=Mock(side_effect=lambda root:dict(state)),
        access_token=Mock(return_value='SYNTHETIC_SUBSCRIPTION_ACCESS_TOKEN'),
        record_inference_failure=Mock(side_effect=failure), SubscriptionError=SubscriptionError),state


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup); self.root=Path(self.tmp.name)
        self.env=patch.dict(os.environ,{},clear=True); self.env.start(); self.addCleanup(self.env.stop)
        self.sub,self.state=subscription_stub()
        p=patch.dict(sys.modules,{'chatgpt_subscription':self.sub}); p.start(); self.addCleanup(p.stop)

    def configure(self, **kwargs):
        return config.configure(self.root,expected_revision=0,auth_mode='chatgpt_subscription',
            account_id='acct_fixture',model=MODEL,**kwargs)

    def test_subscription_ready_does_not_make_embedding_ready_or_share_token(self):
        result=self.configure()
        self.assertEqual(result['llm_status'],'ready')
        self.assertEqual(result['status'],'waiting_for_embedding_key')
        self.assertEqual(config.runtime_config(self.root)['api_key'],'SYNTHETIC_SUBSCRIPTION_ACCESS_TOKEN')
        with self.assertRaisesRegex(config.MemoryModelUnavailable,'waiting_for_embedding_key'):
            config.runtime_embedding_config(self.root)
        self.assertNotIn('TOKEN',json.dumps(result))
        self.assertFalse((self.root/config.SECRET).exists())

    def test_independent_dashscope_credential_never_reaches_llm(self):
        result=self.configure(embedding_provider='dashscope',embedding_model='text-embedding-v3',
            embedding_api_key='SYNTHETIC_EMBEDDING_API_KEY')
        self.assertEqual(result['status'],'ready')
        llm=config.runtime_config(self.root); emb=config.runtime_embedding_config(self.root)
        self.assertEqual(llm['base_url'],config.BASE_URL)
        self.assertEqual(emb['base_url'],config.DASHSCOPE_BASE_URL)
        self.assertEqual(emb['api_key'],'SYNTHETIC_EMBEDDING_API_KEY')
        self.assertEqual(emb['embedding_dimensions'],1024)
        self.assertNotEqual(llm['api_key'],emb['api_key'])
        self.assertFalse((self.root/'state/memory-controls').exists())

    def test_legacy_embedding_is_explicit_host_model_dimension_bound(self):
        path=self.root/'tools/graphiti/.env'; path.parent.mkdir(parents=True)
        path.write_text('OPENAI_API_KEY=SYNTHETIC_LEGACY_EMBED_KEY\nOPENAI_BASE_URL='+config.DASHSCOPE_BASE_URL+
            '\nEMBEDDING_MODEL=text-embedding-v3\nEMBEDDING_DIMS=1024\nLLM_MODEL=qwen-turbo\n')
        result=self.configure(embedding_provider='dashscope')
        self.assertEqual(result['embedding_status'],'waiting_for_embedding_key')
        result=config.configure(self.root,expected_revision=1,use_legacy_embedding=True)
        self.assertEqual(result['status'],'ready')
        self.assertEqual(config.runtime_embedding_config(self.root)['api_key'],'SYNTHETIC_LEGACY_EMBED_KEY')
        path.write_text(path.read_text().replace('1024','1536'))
        with self.assertRaisesRegex(config.MemoryModelUnavailable,'waiting_for_embedding_configuration'):
            config.runtime_embedding_config(self.root)

    def test_switch_account_blocks_old_pins_and_does_not_return_token(self):
        self.configure()
        self.state['account_id']='acct_different'
        self.assertEqual(config.status(self.root)['status'],'chatgpt_subscription_account_changed')
        with self.assertRaisesRegex(config.MemoryModelUnavailable,'account_changed'):
            config.runtime_config(self.root)
        self.sub.access_token.assert_not_called()

    def test_persistent_quota_wait_propagates_without_new_token_request(self):
        self.configure()
        self.state.update(availability_code='usage_limit_exceeded',retry_at='2099-01-01T00:00:00Z')
        result=config.status(self.root)
        self.assertEqual(result['status'],'chatgpt_subscription_usage_limit_exceeded')
        self.assertEqual(result['retry_at'],'2099-01-01T00:00:00Z')
        with self.assertRaisesRegex(config.MemoryModelUnavailable,'usage_limit_exceeded'):
            config.runtime_config(self.root)
        self.sub.access_token.assert_not_called()

    def test_requires_login_overrides_connected_old_token(self):
        self.configure()
        self.state['requires_login']=True
        self.assertEqual(config.status(self.root)['llm_status'],'chatgpt_subscription_login_required')
        with self.assertRaisesRegex(config.MemoryModelUnavailable,'login_required'):
            config.runtime_config(self.root)
        self.sub.access_token.assert_not_called()

    def test_legacy_api_configuration_remains_ready(self):
        result=config.configure(self.root,expected_revision=0,model=MODEL,api_key='SYNTHETIC_API_KEY_COMPATIBLE')
        self.assertEqual(result['auth_mode'],'api_key');self.assertEqual(result['status'],'ready')
        self.assertEqual(config.runtime_embedding_config(self.root)['api_key'],'SYNTHETIC_API_KEY_COMPATIBLE')
        self.sub.access_token.assert_not_called()


def response(output='{"answer":"ok"}', status='completed', error=None):
    return {'id':'resp_fixture','object':'response','created_at':1,'model':MODEL,'status':status,
        'output':[{'id':'msg_fixture','type':'message','role':'assistant','status':'completed',
            'content':[{'type':'output_text','text':output,'annotations':[]}]}],
        'usage':{'input_tokens':12,'output_tokens':3,'total_tokens':15},'error':error,
        'parallel_tool_calls':False,'tool_choice':'auto','tools':[]}


def sse(*events):
    return ''.join('data: '+json.dumps(event)+'\n\n' for event in events).encode()


class Answer(BaseModel):
    answer:str


class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.sub,self.state=subscription_stub()
        p=patch.dict(sys.modules,{'chatgpt_subscription':self.sub});p.start();self.addCleanup(p.stop)
        memory_controls.update(self.root,expected_revision=0,global_enabled=True,daily_call_limit=20,command_id='fixture')
        path=self.root/'config/memory-pricing.json';path.parent.mkdir(exist_ok=True)
        shutil.copyfile(CODE/'config/memory-pricing.json',path)

    async def client(self, handler, billing_mode='subscription'):
        http=MeteredAsyncHttpClient(meter=UsageMeter(self.root),stage='graphiti',model=MODEL,
            scope='cards-master',billing_mode=billing_mode,transport=httpx.MockTransport(handler),trust_env=False)
        sdk=AsyncOpenAI(api_key='SYNTHETIC_SUBSCRIPTION_ACCESS_TOKEN',base_url=config.BASE_URL,
            max_retries=0,http_client=http)
        self.addAsyncCleanup(sdk.close)
        return MemorySubscriptionClient(config=LLMConfig(model=MODEL),client=sdk,
            root=self.root,account_id='acct_fixture'),http

    async def call(self, client):
        return await client._generate_response([Message(role='system',content='strict fixture'),
            Message(role='user',content='PRIVATE_TEXT')],response_model=Answer)

    async def test_complete_sse_strict_protocol_usage_and_no_api_dollar_price(self):
        calls=[]
        def handler(request):
            calls.append(request)
            self.assertEqual(str(request.url),config.BASE_URL+'/responses')
            body=json.loads(request.content)
            self.assertEqual(set(body),{'model','input','store','stream','text'})
            self.assertFalse(body['store']);self.assertTrue(body['stream'])
            self.assertEqual(body['input'][0]['role'],'developer')
            self.assertTrue(body['text']['format']['strict'])
            return httpx.Response(200,content=sse({'type':'response.completed','response':response()}),
                headers={'content-type':'text/event-stream','x-request-id':'fixture-request'})
        client,_=await self.client(handler)
        self.assertEqual(await self.call(client),({'answer':'ok'},12,3))
        row=recent(self.root)[0]
        self.assertEqual(row['billing_mode'],'subscription');self.assertEqual(row['status'],'success')
        self.assertEqual(row['tokens']['total'],15);self.assertIsNone(row['estimated_cost']['amount'])
        self.assertIsNone(row['estimated_cost']['currency'])
        self.assertEqual(row['estimated_cost']['reason'],'subscription_plan_usage')
        ledger=(self.root/'memory/usage/requests.jsonl').read_text()
        self.assertNotIn('PRIVATE_TEXT',ledger);self.assertNotIn('ACCESS_TOKEN',ledger)
        self.assertEqual(len(calls),1)

    async def test_subscription_sse_uses_request_protocol_with_missing_or_mislabelled_mime(self):
        cases=[[], [('content-type','application/json')],
            [('content-type','application/octet-stream')],
            [('content-type','application/json'),('content-type','text/event-stream')],
            [('content-type','text/event-stream; charset=utf-8')],
            [('content-type','application/json; charset=utf-8')]]
        for headers in cases:
            with self.subTest(headers=headers):
                calls=[]
                def handler(request):
                    calls.append(request)
                    body=json.loads(request.content)
                    self.assertEqual(str(request.url),config.BASE_URL+'/responses')
                    self.assertIs(body['stream'],True);self.assertIs(body['store'],False)
                    return httpx.Response(200,content=sse(
                        {'type':'response.output_text.delta','delta':'PRIVATE_OUTPUT'},
                        {'type':'response.completed','response':response()}),headers=headers)
                client,_=await self.client(handler)
                self.assertEqual(await self.call(client),({'answer':'ok'},12,3))
                row=recent(self.root)[0]
                self.assertEqual(row['status'],'success');self.assertTrue(row['usage_known'])
                self.assertEqual(row['tokens']['total'],15)
                self.assertEqual(row['actual_model'],MODEL)
                self.assertEqual(row['billing_mode'],'subscription')
                self.assertIsNone(row['estimated_cost']['amount'])
                self.assertEqual(row['estimated_cost']['reason'],'subscription_plan_usage')
                self.assertEqual(len(calls),1)
        ledger=(self.root/'memory/usage/requests.jsonl').read_text()
        for private in ('PRIVATE_TEXT','PRIVATE_OUTPUT','ACCESS_TOKEN'):
            self.assertNotIn(private,ledger)

    async def test_subscription_wrong_mime_cannot_accept_json_truncated_or_duplicate_sse(self):
        complete={'type':'response.completed','response':response()}
        failed={'type':'response.failed','response':response(status='failed',
            error={'message':'PRIVATE_PROVIDER_ERROR'})}
        cases=[json.dumps(response()).encode(), json.dumps(complete).encode(),
            b'data: {PRIVATE_INVALID_JSON}\n\n',
            sse({'type':'response.output_text.delta','delta':'PRIVATE_OUTPUT'}),
            sse(complete,complete), sse(complete,failed), b'data: \xff\n\n']
        for index,content in enumerate(cases):
            with self.subTest(index=index):
                calls=[]
                def handler(request):
                    calls.append(request)
                    return httpx.Response(200,content=content,headers={'content-type':'application/json'})
                client,_=await self.client(handler)
                with self.assertRaises(ValueError) as caught: await self.call(client)
                self.assertNotIn('PRIVATE',str(caught.exception))
                row=recent(self.root)[0]
                self.assertEqual(row['status'],'invalid_response')
                self.assertFalse(row['usage_known'])
                self.assertEqual(len(calls),1)
        ledger=(self.root/'memory/usage/requests.jsonl').read_text()
        for private in ('PRIVATE_TEXT','PRIVATE_OUTPUT','PRIVATE_PROVIDER_ERROR','PRIVATE_INVALID_JSON','ACCESS_TOKEN'):
            self.assertNotIn(private,ledger)

    async def test_api_billing_keeps_content_type_based_usage_parser(self):
        content=json.dumps(response()).encode()
        def handler(request):
            return httpx.Response(200,content=content,headers={'content-type':'application/json'})
        _,http=await self.client(handler,billing_mode='api')
        await http.send(http.build_request('POST',config.BASE_URL+'/responses',json={'model':MODEL}))
        row=recent(self.root)[0]
        self.assertEqual(row['status'],'success');self.assertTrue(row['usage_known'])
        self.assertEqual(row['tokens']['total'],15);self.assertEqual(row['billing_mode'],'api')
        content=sse({'type':'response.completed','response':response()})
        await http.send(http.build_request('POST',config.BASE_URL+'/responses',json={'model':MODEL}))
        row=recent(self.root)[0]
        self.assertEqual(row['status'],'invalid_response');self.assertFalse(row['usage_known'])
        self.assertEqual(row['error_type'],'UsageResponseUnparseable')

    async def test_subscription_does_not_obscure_known_api_cost_totals(self):
        meter=UsageMeter(self.root)
        for billing in ['subscription','api']:
            attempt=meter.start('graphiti',MODEL,'api.openai.com',scope='cards-master',
                request_meta={'billing_mode':billing})
            meter.finish(attempt,actual_model=MODEL,usage={'input_tokens':100,'output_tokens':10,'total_tokens':110})
        totals=summary(self.root)['all']
        self.assertEqual(totals['subscription_requests'],1)
        self.assertEqual(totals['tokens']['total'],220)
        self.assertEqual(totals['unknown_price'],0)
        self.assertEqual(totals['unpriced_requests'],0)
        self.assertEqual(totals['unknown_currency_requests'],0)
        self.assertEqual(float(totals['estimated_cost']['amount']),.00012)
        self.assertEqual(totals['pricing_coverage']['completed_requests'],1)
        self.assertEqual(totals['pricing_coverage']['priced_requests'],1)

    async def test_subscription_transport_rejects_embeddings_before_reservation(self):
        handler=Mock(side_effect=AssertionError('no network'))
        _,http=await self.client(handler)
        with self.assertRaisesRegex(ValueError,'subscription_request_not_allowed'):
            await http.send(http.build_request('POST',config.BASE_URL+'/embeddings',json={'model':'text-embedding-3-small'}))
        self.assertEqual(recent(self.root),[]);handler.assert_not_called()

    async def test_truncated_stream_not_success_and_usage_remains_unknown(self):
        client,_=await self.client(lambda request:httpx.Response(200,
            content=sse({'type':'response.output_text.delta','delta':'{"answer":"ok"}'}),
            headers={'content-type':'text/event-stream'}))
        with self.assertRaises(ValueError): await self.call(client)
        row=recent(self.root)[0]
        self.assertEqual(row['status'],'invalid_response');self.assertFalse(row['usage_known'])
        self.assertEqual(row['error_type'],'SubscriptionStreamTruncated')

    async def test_sse_usage_limit_persists_wait_and_partial_usage_without_fallback(self):
        calls=[]
        def handler(request):
            calls.append(request)
            return httpx.Response(200,content=sse({'type':'response.failed','response':response(status='failed',
                error={'code':'subscription_sharing_usage_limit_exceeded','message':'PRIVATE_ERROR'})}),
                headers={'content-type':'text/event-stream'})
        client,_=await self.client(handler)
        with self.assertRaisesRegex(config.MemoryModelUnavailable,'usage_limit_exceeded'): await self.call(client)
        self.assertEqual(self.state['availability_code'],'usage_limit_exceeded')
        self.assertEqual(len(calls),1)
        row=recent(self.root)[0]
        self.assertEqual(row['status'],'invalid_response');self.assertTrue(row['usage_known'])
        self.assertNotIn('PRIVATE_ERROR',(self.root/'memory/usage/requests.jsonl').read_text())

    async def test_http_auth_and_rate_limit_wait_without_retry(self):
        for code,reason in [(401,'login_required'),(403,'access_denied'),(429,'usage_limit_exceeded')]:
            with self.subTest(code=code):
                calls=[]
                def handler(request):
                    calls.append(request)
                    return httpx.Response(code,json={'error':{'message':'PRIVATE_PROVIDER_ERROR'}},headers={'retry-after':'30'})
                client,_=await self.client(handler)
                with self.assertRaisesRegex(config.MemoryModelUnavailable,reason): await self.call(client)
                self.assertEqual(len(calls),1);self.assertEqual(self.state['availability_code'],reason)

    async def test_completed_wrong_schema_or_refusal_rejected(self):
        for output in ['{"answer":5}','{"answer":"ok","extra":1}','{}']:
            with self.subTest(output=output):
                client,_=await self.client(lambda request:httpx.Response(200,
                    content=sse({'type':'response.completed','response':response(output)}),
                    headers={'content-type':'text/event-stream'}))
                with self.assertRaises(ValueError): await self.call(client)

    async def test_incomplete_refusal_or_changed_model_cannot_be_accepted(self):
        refused=response()
        refused['output'][0]['content']=[{'type':'refusal','refusal':'fixture refusal'}]
        changed={**response(),'model':'different-model'}
        cases=[{'type':'response.completed','response':refused},
               {'type':'response.completed','response':changed},
               {'type':'response.incomplete','response':response(status='incomplete')}]
        for event in cases:
            with self.subTest(kind=event['type']):
                client,_=await self.client(lambda request:httpx.Response(200,content=sse(event),
                    headers={'content-type':'text/event-stream'}))
                with self.assertRaises(ValueError): await self.call(client)

    async def test_no_schema_cannot_fallback_to_chat(self):
        handler=Mock(side_effect=AssertionError('no network'))
        client,_=await self.client(handler)
        with self.assertRaises(ValueError): await client._generate_response([],response_model=None)
        handler.assert_not_called();self.assertEqual(recent(self.root),[])


class RealSessionIntegrationTests(unittest.TestCase):
    def test_local_session_hold_propagates_and_expires_without_model_or_refresh_call(self):
        import chatgpt_subscription as sub
        with tempfile.TemporaryDirectory() as temporary,patch.dict(os.environ,{},clear=True):
            root=Path(temporary)
            value=sub._empty();cid='fixture-client';aid=sub._account_id(cid)
            value.update(host_id='urn:uuid:00000000-0000-4000-8000-000000000000',selected=aid)
            value['accounts'][aid]={'client_id':cid,'subject':'fixture-subject',
                'access_token':'SYNTHETIC_SESSION_TOKEN','scopes':sorted(sub.PLAN_SCOPES),
                'expires_at':sub._now()+3600,'earliest_refresh_at':0,
                'availability_code':None,'retry_at':None}
            with sub._locked(root):sub._write(root,value)
            config.configure(root,expected_revision=0,auth_mode='chatgpt_subscription',account_id=aid,model=MODEL,
                embedding_provider='dashscope',embedding_api_key='SYNTHETIC_EMBEDDING_KEY')
            with patch.object(sub,'_request',side_effect=AssertionError('no provider requests')):
                self.assertEqual(config.runtime_config(root)['api_key'],'SYNTHETIC_SESSION_TOKEN')
                sub.record_inference_failure(root,aid,'usage_limit_exceeded',retry_after_seconds=30)
                held=config.status(root)
                self.assertEqual(held['status'],'chatgpt_subscription_usage_limit_exceeded')
                with self.assertRaisesRegex(config.MemoryModelUnavailable,'usage_limit_exceeded'):
                    config.runtime_config(root)
                now=sub._now()
                with patch.object(sub,'_now',return_value=now+31):
                    self.assertEqual(config.status(root)['status'],'ready')
                    self.assertEqual(config.runtime_config(root)['api_key'],'SYNTHETIC_SESSION_TOKEN')


class AdapterAssemblyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        p=patch.dict(os.environ,{},clear=True);p.start();self.addCleanup(p.stop)
        self.sub,self.state=subscription_stub()
        p=patch.dict(sys.modules,{'chatgpt_subscription':self.sub});p.start();self.addCleanup(p.stop)
        config.configure(self.root,expected_revision=0,auth_mode='chatgpt_subscription',account_id='acct_fixture',
            model=MODEL,embedding_provider='dashscope',embedding_api_key='SYNTHETIC_EMBEDDING_API_KEY')
        memory_controls.update(self.root,expected_revision=0,global_enabled=True,daily_call_limit=20,command_id='fixture')
        self.envpath=self.root/'fixture.env'
        self.envpath.write_text('NEO4J_URI=bolt://fixture.invalid:7687\nNEO4J_USER=fixture\nNEO4J_PASSWORD=fixture\n')
        self.calls=[];self.parts={}
        def handler(request):
            self.calls.append(request)
            if request.url.path.endswith('/embeddings'):
                return httpx.Response(200,json={'object':'list','model':'text-embedding-v3',
                    'data':[{'index':0,'object':'embedding','embedding':[1.0]+[0.0]*1023}],
                    'usage':{'prompt_tokens':3,'total_tokens':3}})
            return httpx.Response(200,content=sse({'type':'response.completed','response':response()}),
                headers={'content-type':'text/event-stream'})
        def http_factory(**kwargs):
            return MeteredAsyncHttpClient(**kwargs,transport=httpx.MockTransport(handler),trust_env=False)
        def graphiti(*args,**kwargs):
            self.parts.update(kwargs)
            return types.SimpleNamespace(driver=AsyncMock(),close=AsyncMock())
        from javis_memory_adapter.adapter import MemoryAdapter
        self.adapter=MemoryAdapter('javis-screen-subscription-fixture',env_path=self.envpath,
            meta_dir=self.root/'memory/screen/graph/test',usage_root=self.root,usage_scope='cards-master')
        with patch('javis_memory_adapter.metered_client.MeteredAsyncHttpClient',side_effect=http_factory),\
                patch('graphiti_core.Graphiti',side_effect=graphiti):
            await self.adapter._ensure()
        self.addAsyncCleanup(self.adapter.close)

    async def call(self):
        return await self.parts['llm_client']._generate_response([Message(role='user',content='fixture')],response_model=Answer)

    async def test_actual_assembled_clients_use_separate_credentials_and_complete_pins(self):
        self.assertEqual(self.adapter.extraction_auth_mode,'chatgpt_subscription')
        self.assertEqual(self.adapter.extraction_account_id,'acct_fixture')
        self.assertEqual(self.adapter.extraction_embedding_provider,'dashscope')
        self.assertEqual(self.adapter.extraction_embedding_model,'text-embedding-v3')
        self.assertEqual(self.adapter.extraction_embedding_dimensions,1024)
        self.assertIsInstance(self.parts['llm_client'],MemorySubscriptionClient)
        await self.call()
        await self.parts['embedder'].client.embeddings.create(model='text-embedding-v3',input=['fixture'])
        self.assertEqual([r.url.host for r in self.calls],['api.openai.com','dashscope.aliyuncs.com'])
        self.assertEqual(self.calls[0].headers['authorization'],'Bearer SYNTHETIC_SUBSCRIPTION_ACCESS_TOKEN')
        self.assertEqual(self.calls[1].headers['authorization'],'Bearer SYNTHETIC_EMBEDDING_API_KEY')
        self.assertEqual({r['billing_mode'] for r in recent(self.root)},{'api','subscription'})

    async def test_config_revision_changed_before_http_sends_nothing(self):
        config.configure(self.root,expected_revision=1,model=MODEL)
        with self.assertRaisesRegex(config.MemoryModelUnavailable,'waiting_for_configuration'):
            await self.call()
        self.assertEqual(self.calls,[]);self.assertEqual(recent(self.root),[])

    async def test_account_switch_before_http_sends_nothing(self):
        self.state['account_id']='acct_other'
        with self.assertRaisesRegex(config.MemoryModelUnavailable,'account_changed'):
            await self.call()
        self.assertEqual(self.calls,[]);self.assertEqual(recent(self.root),[])

    async def test_global_pause_still_blocks_subscription_http(self):
        memory_controls.update(self.root,expected_revision=1,global_enabled=False,command_id='pause')
        with self.assertRaises(memory_controls.MemoryProcessingHeld):
            await self.call()
        self.assertEqual(self.calls,[]);self.assertEqual(recent(self.root),[])


class EmbeddingCacheTests(unittest.TestCase):
    def test_provider_model_dimensions_isolate_cache(self):
        from test_memory_v3_backend import HybridTests
        fixture=HybridTests(methodName='runTest');fixture.setUp();self.addCleanup(fixture.doCleanups)
        fixture.fact('one','偏好','中文日报')
        first=fixture.query('日报',vectorizer=lambda texts:[fixture.vector() for _ in texts])
        config.configure(fixture.root,expected_revision=1,embedding_provider='dashscope',
            embedding_api_key='SYNTHETIC_EMBEDDING_API_KEY')
        calls=[]
        def vectors(texts):
            calls.append(texts);return [[1.0]+[0.0]*1023 for _ in texts]
        second=fixture.query('日报',vectorizer=vectors)
        self.assertEqual(first['retrieval']['vector_provider'],'openai')
        self.assertEqual(second['retrieval']['vector_provider'],'dashscope')
        self.assertEqual(second['retrieval']['cached_fact_vectors'],0)
        self.assertEqual(len(calls),2)
        self.assertEqual(len(list((fixture.root/'memory/retrieval/openai').rglob('*.json'))),1)
        self.assertEqual(len(list((fixture.root/'memory/retrieval/dashscope').rglob('*.json'))),1)


if __name__=='__main__':unittest.main()
