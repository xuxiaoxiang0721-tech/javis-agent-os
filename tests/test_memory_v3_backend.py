"""Synthetic-only regression tests: never read production credentials or use a network."""
import asyncio
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch, AsyncMock

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE / 'scripts'))
sys.path.insert(0, str(CODE / 'tools/memory-adapter'))
import memory_controls
import memory_model_config as config
from javis_memory_adapter.normalization import normalize_verified_fact, metadata
from javis_memory_adapter.hybrid_retrieval import retrieve
from javis_memory_adapter.metered_client import MeteredAsyncHttpClient
from javis_memory_adapter.usage_meter import UsageMeter
from javis_memory_adapter.review_policy import ReviewBlocked
from openai import AsyncOpenAI, DefaultAsyncHttpxClient
httpx = importlib.import_module(DefaultAsyncHttpxClient.__mro__[1].__module__.split('.')[0])


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = patch.dict(os.environ, {}, clear=True); self.env.start(); self.addCleanup(self.env.stop)

    def test_qwen_compatible_environment_never_read_as_openai(self):
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'DO_NOT_USE_QWEN_KEY', 'LLM_MODEL': 'qwen-turbo',
                'OPENAI_BASE_URL': 'https://dashscope.aliyuncs.com/compatible-mode/v1'}):
            state = config.status(self.root)
            self.assertEqual(state['status'], 'waiting_for_configuration')
            self.assertFalse(state['key_configured'])
            self.assertEqual(list(self.root.iterdir()), [])

    def test_readiness_cas_secret_permissions_and_no_key_echo(self):
        state = config.configure(self.root, expected_revision=0, model='gpt-5.4-mini-2026-03-17')
        self.assertEqual(state['status'], 'waiting_for_key')
        state = config.configure(self.root, expected_revision=1, api_key='SYNTHETIC_OPENAI_SECRET_ONLY')
        self.assertEqual(state['status'], 'ready'); self.assertFalse(state['verified'])
        self.assertNotIn('SECRET', json.dumps(state))
        self.assertEqual((self.root / config.SECRET).stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(ReviewBlocked, 'revision_changed'):
            config.configure(self.root, expected_revision=1, model='gpt-4.1-mini-2025-04-14')
        self.assertEqual(config.runtime_config(self.root)['base_url'], 'https://api.openai.com/v1')

    def test_symlink_secret_parent_rejected(self):
        outside = self.root / 'outside'; outside.mkdir()
        (self.root / 'secrets').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ReviewBlocked):
            config.configure(self.root, expected_revision=0, model='gpt-test', api_key='SYNTHETIC_OPENAI_SECRET_ONLY')
        self.assertEqual(list(outside.iterdir()), [])

    def test_invalid_key_error_is_redacted(self):
        with self.assertRaisesRegex(ReviewBlocked, '^memory_key_invalid$'):
            config.configure(self.root, expected_revision=0, model='gpt-test', api_key='bad\nSECRET')


class NormalizationTests(unittest.TestCase):
    def edge(self):
        return {'subject_label':'PSA 12345678 card', 'subject_id':'graph-123',
            'predicate':'PREFERS', 'object_label':'中文日报'}

    def test_exact_span_and_fragment_roundtrip(self):
        source = '开头。用户偏好中文日报。结尾。'; quote = '用户偏好中文日报'
        row = normalize_verified_fact(self.edge(), text=source, evidence=quote, scope='invest', source_event_id='ev-test')
        self.assertTrue(all(len(x) <= 200 for x in row['notes']))
        row['notes'] = sorted(row['notes'])
        meta = metadata(row); span = meta['evidence']
        self.assertEqual(source[span['start']:span['end']], quote)
        self.assertNotIn('quote', span)
        self.assertEqual(row['predicate'], 'prefers')

    def test_different_physical_certificate_or_source_not_merged(self):
        a = self.edge(); b = {**a, 'subject_label':'PSA 87654321 card'}
        def norm(edge, event):
            return normalize_verified_fact(edge, text='evidence', evidence='evidence', scope='cards-master', source_event_id=event)
        self.assertNotEqual(norm(a,'ev1')['subject_id'], norm(b,'ev1')['subject_id'])
        self.assertNotEqual(norm(a,'ev1')['subject_id'], norm(a,'ev2')['subject_id'])

    def test_fragment_mutation_or_missing_evidence_rejected(self):
        row = normalize_verified_fact(self.edge(), text='evidence', evidence='evidence', scope='invest', source_event_id='ev1')
        row['notes'][0] += 'x'; self.assertEqual(metadata(row), {})
        with self.assertRaisesRegex(ValueError, 'evidence_not_exact'):
            normalize_verified_fact(self.edge(), text='real', evidence='invented', scope='invest', source_event_id='ev1')

    def test_psa_identity_across_sources_and_explicit_alias_registry(self):
        from raw_storage import append_event
        from javis_memory_adapter.entity_registry import register_alias, resolve_entity
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def raw(eid, text):
                append_event(root, {'event_id':eid,'event_type':'user_input','agent':'cards-master',
                    'payload':{'text':text,'is_original_user_input':True}})
            raw('ev1','PSA 12345678 card has grade 10'); raw('ev2','PSA 12345678 card was listed')
            one = normalize_verified_fact(self.edge(), text='PSA 12345678 card has grade 10',
                evidence='PSA 12345678 card has grade 10', scope='cards-master', source_event_id='ev1', root=root)
            two = normalize_verified_fact(self.edge(), text='PSA 12345678 card was listed',
                evidence='PSA 12345678 card was listed', scope='cards-master', source_event_id='ev2', root=root)
            self.assertEqual(one['subject_id'], two['subject_id'])
            self.assertEqual(one['subject_id'], 'entity:psa:12345678')
            raw('ev3','项目 Javis 也叫 Jarvis。'); raw('ev4','Jarvis 支持归档。')
            alias = register_alias(root,'cards-master',canonical_name='Javis',alias='Jarvis',source_event_id='ev3',
                text='项目 Javis 也叫 Jarvis。',evidence='项目 Javis 也叫 Jarvis。')
            resolved = resolve_entity(root,'cards-master',label='Jarvis',source_event_id='ev4',
                text='Jarvis 支持归档。',evidence='Jarvis 支持归档。')
            self.assertEqual(alias['canonical_id'], resolved['canonical_id'])
            with self.assertRaisesRegex(ReviewBlocked,'explicit_statement_required'):
                register_alias(root,'cards-master',canonical_name='Javis',alias='Unknown',source_event_id='ev4',
                    text='Jarvis 支持归档。',evidence='Jarvis 支持归档。')


class HybridTests(unittest.TestCase):
    def setUp(self):
        import test_ai_memory_adapter as fixtures
        self.fixture = fixtures.AIAdapterTests(methodName='runTest')
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.env = patch.dict(os.environ, {}, clear=True); self.env.start(); self.addCleanup(self.env.stop)
        config.configure(self.root, expected_revision=0, model='gpt-5.4-mini-2026-03-17', api_key='SYNTHETIC_OPENAI_SECRET_ONLY')
        memory_controls.update(self.root, expected_revision=0, global_enabled=True, command_id='enable-test')

    def fact(self, fid, subject, value, notes=None):
        return self.fixture.accept(fid, valid=None, subject_id='subject-' + fid, subject_label=subject,
            predicate='note', value=value, notes=notes or [])[0]

    def query(self, query, **kwargs):
        return retrieve(self.root, 'cards-master', query, **kwargs)

    @staticmethod
    def vector(a=1, b=0):
        return [a,b] + [0]*1534

    def test_semantic_match_without_keyword_is_returned(self):
        self.fact('one', '餐饮偏好', '偏好素食')
        result = self.query('vegetarian', vectorizer=lambda texts:[self.vector() for t in texts])
        self.assertEqual(result['facts'][0]['fact_id'], 'one')
        self.assertEqual(result['facts'][0]['retrieval_channels'], ['vector'])
        self.assertEqual(result['retrieval']['mode'], 'hybrid')

    def test_cache_reused_but_query_still_embedded(self):
        self.fact('one', '偏好', '中文日报'); calls=[]
        def embed(texts):
            calls.append(texts); return [self.vector() for _ in texts]
        self.query('日报', vectorizer=embed); self.query('日报', vectorizer=embed)
        self.assertEqual(len(calls), 3)
        self.assertEqual(len(list((self.root/'memory/retrieval/openai').rglob('*.json'))),1)

    def test_pause_preserves_keyword_and_no_vector_call(self):
        self.fact('one', '偏好', '中文日报')
        memory_controls.update(self.root, expected_revision=1, global_enabled=False, command_id='pause-test')
        vectorizer = unittest.mock.Mock(side_effect=AssertionError('must not send'))
        result = self.query('日报', vectorizer=vectorizer)
        self.assertEqual(result['retrieval']['reason'], 'global_paused')
        self.assertEqual(len(result['facts']),1); vectorizer.assert_not_called()

    def test_provider_failure_keeps_local_recall(self):
        self.fact('one', '偏好', '中文日报')
        result = self.query('日报', vectorizer=lambda texts: (_ for _ in ()).throw(ValueError('DO_NOT_EXPOSE_SECRET')))
        self.assertEqual(result['retrieval']['reason'], 'provider_unavailable')
        self.assertNotIn('SECRET', json.dumps(result)); self.assertEqual(len(result['facts']), 1)

    def test_relationship_neighbor_and_scope_isolation(self):
        norm = normalize_verified_fact({'subject_label':'用户', 'subject_id':'g1', 'predicate':'LIKES', 'object_label':'咖啡'},
            text='用户喜欢咖啡', evidence='用户喜欢咖啡', scope='cards-master', source_event_id='ev1')
        self.fact('one', '用户', '用户喜欢咖啡', norm['notes'])
        self.fact('two', '咖啡', '每周采购十包')
        result = self.query('用户', allow_provider=False)
        neighbor = next(row for row in result['facts'] if row['fact_id']=='two')
        self.assertIn('relationship', neighbor['retrieval_channels'])
        with self.assertRaisesRegex(ValueError, 'scope_not_authorized'):
            self.query('用户', scopes=['invest'])

    def test_revoked_ai_cache_is_never_recalled(self):
        fact = self.fact('one', '偏好', '中文日报')
        self.query('日报', vectorizer=lambda texts:[self.vector() for _ in texts])
        self.fixture.revoke(fact)
        result = self.query('日报', vectorizer=lambda texts:[self.vector() for _ in texts])
        self.assertEqual(result['facts'], [])

    def test_query_secret_blocks_provider_not_local_read(self):
        self.fact('one', '偏好', '中文日报')
        result = self.query('L4: 日报', vectorizer=lambda _: (_ for _ in ()).throw(AssertionError()))
        self.assertEqual(result['retrieval']['reason'], 'query_privacy_blocked')

    def test_unknown_role_or_shared_cannot_bill_provider(self):
        for role in ['shared', 'unknown', None]:
            with self.assertRaisesRegex(ValueError, 'role_required'):
                retrieve(self.root, role, '日报')

    def test_source_notes_do_not_form_generic_relationship_hub(self):
        self.fixture.accept('one', valid=None, subject_id='src1', subject_label='原文记录',
            predicate='source_attributed_memory', value='红色卡片')
        self.fixture.accept('two', valid=None, subject_id='src2', subject_label='原文记录',
            predicate='source_attributed_memory', value='蓝色汽车')
        result = self.query('卡片', allow_provider=False)
        self.assertEqual([row['fact_id'] for row in result['facts']], ['one'])

    def test_multi_value_preferences_are_not_conflicts(self):
        from javis_memory_adapter.ledger_query import query_semantic_memory
        for fid,value in [('one','中文日报'),('two','图表日报')]:
            notes = normalize_verified_fact({'subject_label':'Javis','subject_id':'g','predicate':'PREFERS'},
                text=value,evidence=value,scope='cards-master',source_event_id='input-one')['notes']
            self.fixture.accept(fid,valid=None,subject_id='same-entity',subject_label='Javis',
                predicate='prefers',value=value,notes=notes)
        result = query_semantic_memory(self.fixture.store)
        self.assertEqual(len(result['facts']), 2); self.assertEqual(result['conflicts'], [])

    def test_new_catalog_cached_input_cost_and_old_prices_preserved(self):
        import shutil
        path=self.root/'config/memory-pricing.json'; path.parent.mkdir(exist_ok=True)
        shutil.copyfile(CODE/'config/memory-pricing.json',path)
        meter=UsageMeter(self.root)
        attempt=meter.start('graphiti','gpt-5.4-mini-2026-03-17','api.openai.com',scope='cards-master')
        result=meter.finish(attempt,actual_model='gpt-5.4-mini-2026-03-17',usage={
            'input_tokens':1000,'output_tokens':100,'total_tokens':1100,'input_tokens_details':{'cached_tokens':500}})
        self.assertEqual(result['estimated_cost']['currency'],'USD')
        self.assertEqual(float(result['estimated_cost']['amount']), .0008625)
        catalog=json.loads(path.read_text())
        old=[p for p in catalog['prices'] if p['model']=='qwen-turbo'][0]
        self.assertEqual(old['input_per_million'],'0.3')

    def test_type_b_entity_endpoint_evidence_and_legacy_literal_compatibility(self):
        from javis_memory_adapter.type_b import rebuild_group_from_store, relation_target
        from javis_memory_adapter.review_policy import official_group
        normalized = normalize_verified_fact({'subject_label':'user','subject_id':'g','predicate':'LIKES','object_label':'blue'},
            text='remember blue',evidence='remember blue',scope='cards-master',source_event_id='input-one',root=self.root)
        fact, _ = self.fixture.accept('relation',valid=None,value='remember blue',**normalized)
        legacy = self.fact('old-note','原文记录','旧事实正文')
        calls=[]
        class Result:
            async def consume(self): pass
        class Session:
            async def __aenter__(self): return self
            async def __aexit__(self,*args): pass
            async def run(self,query,**kwargs): calls.append((query,kwargs)); return Result()
        class Driver:
            def session(self): return Session()
            async def close(self): pass
        with patch('neo4j.AsyncGraphDatabase.driver',return_value=Driver()):
            result=asyncio.run(rebuild_group_from_store(store=self.fixture.store,
                target_group_id=official_group(self.root,'cards-master'),neo4j_uri='mock',neo4j_user='mock',neo4j_password='mock'))
        self.assertEqual(result['errors'],[])
        row=next(kwargs for query,kwargs in calls if kwargs.get('fid')=='relation')
        self.assertEqual(row['oid'],metadata(fact.to_dict())['target_id'])
        self.assertEqual(row['olabel'],'blue'); self.assertNotIn('remember',row['oid'])
        self.assertEqual(json.loads(row['value_json']),'remember blue')
        self.assertEqual(row['evidence_start'],0); self.assertEqual(row['evidence_end'],13)
        self.assertEqual(row['evidence_offset_unit'],'unicode_codepoints')
        self.assertTrue(row['structure_version'])
        self.assertTrue(relation_target(legacy)[0].startswith('val:'))
        self.fixture.revoke(fact)
        recalled=self.query('blue',allow_provider=False)
        self.assertNotIn('relation',[row['fact_id'] for row in recalled['facts']])

    def test_unsupported_target_is_never_projected_as_an_entity(self):
        from javis_memory_adapter.type_b import relation_target
        normalized=normalize_verified_fact({'subject_label':'user','subject_id':'g','predicate':'LIKES','object_label':'invented'},
            text='remember blue',evidence='remember blue',scope='cards-master',source_event_id='input-one')
        fact,_=self.fixture.accept('no-target',valid=None,value='remember blue',**normalized)
        self.assertIsNone(metadata(fact.to_dict())['target_id'])
        self.assertTrue(relation_target(fact)[0].startswith('val:'))

    def alias_fact(self):
        from raw_storage import append_event
        from javis_memory_adapter.entity_registry import register_alias
        for eid, text in [('alias-source', '项目 Cedar 也叫 Pine。'), ('fact-source', 'Pine supports reports。')]:
            append_event(self.root, {'event_id':eid,'event_type':'user_input','agent':'cards-master',
                'payload':{'text':text,'is_original_user_input':True}})
        register_alias(self.root,'cards-master',canonical_name='Cedar',alias='Pine',source_event_id='alias-source',
            text='项目 Cedar 也叫 Pine。',evidence='项目 Cedar 也叫 Pine。')
        return normalize_verified_fact({'subject_label':'Pine','subject_id':'g','predicate':'SUPPORTS','object_label':'reports'},
            text='Pine supports reports。',evidence='Pine supports reports。',scope='cards-master',
            source_event_id='fact-source',root=self.root)

    def change_alias_source(self):
        for path in (self.root/'raw/events').glob('*.jsonl'):
            rows=[json.loads(line) for line in path.read_text().split('\n') if line]
            for row in rows:
                if row['event_id']=='alias-source':
                    row['payload']['text']='项目 Cedar 与 Pine 是不同的项目。'
            path.write_text(''.join(json.dumps(row,ensure_ascii=False)+'\n' for row in rows))

    def test_alias_source_scope_is_enforced(self):
        from raw_storage import append_event
        from javis_memory_adapter.entity_registry import register_alias
        append_event(self.root,{'event_id':'cross-scope','event_type':'user_input','agent':'invest',
            'payload':{'text':'项目 Cedar 也叫 Pine。'}})
        with self.assertRaisesRegex(ReviewBlocked,'source_scope_mismatch'):
            register_alias(self.root,'cards-master',canonical_name='Cedar',alias='Pine',source_event_id='cross-scope',
                text='项目 Cedar 也叫 Pine。',evidence='项目 Cedar 也叫 Pine。')

    def test_alias_dependency_change_excludes_existing_fact_from_all_recall(self):
        from javis_memory_adapter.review_policy import usable_facts
        normalized=self.alias_fact()
        self.assertEqual(set(normalized['raw_refs']),{'alias-source','fact-source'})
        self.fixture.accept('alias-fact',valid=None,value='Pine supports reports。',source_event_id='fact-source',**normalized)
        self.assertEqual(len(usable_facts(self.fixture.store)),1)
        self.change_alias_source()
        self.assertEqual(usable_facts(self.fixture.store),[])
        result=self.query('Pine',vectorizer=lambda texts:[self.vector() for _ in texts])
        self.assertEqual(result['facts'],[])
        from javis_memory_adapter.type_b import rebuild_group_from_store
        from javis_memory_adapter.review_policy import official_group
        session=AsyncMock(); session.__aenter__.return_value=session
        driver=types.SimpleNamespace(session=lambda:session,close=AsyncMock())
        with patch('neo4j.AsyncGraphDatabase.driver',return_value=driver):
            projection=asyncio.run(rebuild_group_from_store(store=self.fixture.store,
                target_group_id=official_group(self.root,'cards-master'),neo4j_uri='mock',neo4j_user='mock',neo4j_password='mock'))
        self.assertEqual(projection['planned'],0); self.assertEqual(projection['written'],[])
        self.assertEqual(session.run.call_args.kwargs['active_ai_reviews'],[])

    def test_alias_change_between_normalize_and_propose_cannot_repin_old_identity(self):
        normalized=self.alias_fact()
        self.change_alias_source()
        # This fixture deliberately takes fresh source_digests AFTER the source
        # changed, reproducing the stale-normalization/fresh-proposal race.
        with self.assertRaises(ReviewBlocked):
            self.fixture.accept('stale-alias-fact',valid=None,value='Pine supports reports。',
                source_event_id='fact-source',**normalized)
        self.assertIsNone(self.fixture.store.get_fact('stale-alias-fact'))

    def test_local_source_snapshot_is_per_request_and_released_before_provider(self):
        from javis_memory_adapter import review_policy as policy
        normalized=self.alias_fact()
        self.fixture.accept('alias-fact',valid=None,value='Pine supports reports。',source_event_id='fact-source',**normalized)
        self.fact('another','日报','中文日报')
        vector_calls=[]
        def vectors(texts):
            self.assertIsNone(policy._SOURCE_BATCH.get())
            vector_calls.append(texts)
            return [self.vector() for _ in texts]
        with patch.object(policy,'_read_raw_snapshot',wraps=policy._read_raw_snapshot) as read:
            self.query('Pine',vectorizer=vectors)
            self.assertEqual(read.call_count,1)
            self.query('Pine',vectorizer=vectors)
            self.assertEqual(read.call_count,2)
        self.assertTrue(vector_calls)
        self.assertIsNone(policy._SOURCE_BATCH.get())

    def test_source_hash_changed_at_snapshot_exit_blocks_provider_and_clears_cache(self):
        from javis_memory_adapter import review_policy as policy
        self.fact('one','日报','中文日报')
        path=next((self.root/'raw/events').glob('*.jsonl'))
        initial_signature=policy._raw_signature(self.root)
        def change_after_validation(row):
            path.write_bytes(path.read_bytes()+b'\n')
            return True
        vectors=unittest.mock.Mock(side_effect=AssertionError('provider must not run'))
        # Hide metadata changes to prove the final content hash is checked.
        with patch.object(policy,'_raw_signature',return_value=initial_signature):
            with self.assertRaisesRegex(ReviewBlocked,'raw_snapshot_changed'):
                self.query('日报',safe_filter=change_after_validation,vectorizer=vectors)
        vectors.assert_not_called()
        self.assertIsNone(policy._SOURCE_BATCH.get())


class ProviderTests(unittest.IsolatedAsyncioTestCase):
    async def test_each_http_retry_reserves_budget_and_meter_attempt_matches(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            memory_controls.update(root, expected_revision=0, global_enabled=True, daily_call_limit=2, command_id='test')
            calls=[]
            async def handler(request):
                calls.append(1)
                if len(calls)==1:
                    return httpx.Response(429,json={'error':{'message':'fixture'}},headers={'retry-after-ms':'1'})
                return httpx.Response(200,json={'object':'list','data':[{'index':0,'object':'embedding','embedding':[1,0]}],
                    'model':'text-embedding-3-small','usage':{'prompt_tokens':4,'total_tokens':4}})
            http=MeteredAsyncHttpClient(meter=UsageMeter(root), stage='embedding', model='text-embedding-3-small',
                scope='cards-master', transport=httpx.MockTransport(handler),trust_env=False)
            async with AsyncOpenAI(api_key='synthetic',base_url='https://api.openai.com/v1',http_client=http,max_retries=1) as client:
                await client.embeddings.create(model='text-embedding-3-small',input=['fixture'])
            rows=[json.loads(line) for line in (root/'memory/usage/requests.jsonl').read_text().splitlines()]
            starts={row['attempt_id'] for row in rows if row['event']=='started'}
            reservations=json.loads(next((root/'state/memory-controls/budget').glob('*.json')).read_text())['reservations']
            self.assertEqual(set(reservations),starts); self.assertEqual(len(starts),2)

    async def test_paused_http_has_no_network_or_meter_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); calls=[]
            async def handler(request): calls.append(1); return httpx.Response(200,json={})
            http=MeteredAsyncHttpClient(meter=UsageMeter(root),stage='embedding',model='x',scope='cards-master',
                transport=httpx.MockTransport(handler),trust_env=False)
            async with http:
                with self.assertRaises(memory_controls.MemoryProcessingHeld):
                    await http.send(http.build_request('POST','https://api.openai.com/v1/embeddings',json={'input':['x']}))
            self.assertEqual(calls,[]); self.assertFalse((root/'memory/usage/requests.jsonl').exists())

    async def test_official_structured_request_no_temperature_or_provider_alias(self):
        from javis_memory_adapter.openai_memory_client import MemoryOpenAIClient
        from graphiti_core.llm_client import LLMConfig
        from pydantic import BaseModel
        class Parsed(BaseModel): answer:str
        sdk=types.SimpleNamespace(responses=types.SimpleNamespace(parse=AsyncMock(return_value=types.SimpleNamespace(
            status='completed',output_parsed=Parsed(answer='ok')))))
        client=MemoryOpenAIClient(config=LLMConfig(model='gpt-5.4-mini-2026-03-17'),client=sdk)
        await client._create_structured_completion('gpt-5.4-mini-2026-03-17',[],.5,1024,Parsed)
        kwargs=sdk.responses.parse.call_args.kwargs
        self.assertEqual(kwargs['model'],'gpt-5.4-mini-2026-03-17')
        self.assertIs(kwargs['text_format'],Parsed); self.assertFalse(kwargs['store'])
        self.assertNotIn('temperature',kwargs)
        sdk.responses.parse.return_value=types.SimpleNamespace(status='incomplete',output_parsed=None)
        with self.assertRaisesRegex(ValueError,'incomplete_or_refused'):
            await client._create_structured_completion('gpt-5.4-mini-2026-03-17',[],.5,1024,Parsed)


if __name__=='__main__': unittest.main()
