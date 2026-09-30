import json
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from raw_storage import append_event
from memory_screen import load_source
from memory_interactions import supplement, status
from memory_triage import record_pending
from jev_policy import POLICY_VERSION, POLICY_DIGEST
from javis_memory_adapter.review_policy import digest


class SupplementTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        config=self.root/'config/memory-pipeline.json';config.parent.mkdir()
        config.write_text(json.dumps({'enabled':True,'provider':'typesafe','model':'jev-1.13.0'}))
        append_event(self.root, {'event_id':'source-unclear','event_type':'user_input','agent':'invest',
            'occurred_at':None,'payload':{'text':'这个账户按之前的方法处理。','is_original_user_input':True}})
        original=load_source(self.root,'source-unclear'); self.original_digest=digest(original)
        self.item=record_pending(self.root,event_id='source-unclear',scope='invest',source_digest=digest(original),
            run_id='test-unclear',policy_version=POLICY_VERSION,policy_digest=POLICY_DIGEST,
            stage='screening',reason_code='screen_needs_evidence',content_digest=digest(original['payload']['text']))
        path=self.root/'memory/triage/items'/(self.item['triage_id']+'.json')
        self.triage_bytes=path.read_bytes();self.triage=json.loads(self.triage_bytes)
        self.req={'target_id':self.item['triage_id'],'expected_version':self.triage['record_digest'],
            'scope':'invest','text':'这里的账户是测试账户A；请每周展示余额变化。','command_id':'answer-one'}

    def test_paused_reply_persists_raw_and_queue_without_confirming_or_overwriting(self):
        result=supplement(self.root,self.req)
        self.assertEqual(result['authority'],'local_user_supplement')
        source=load_source(self.root,result['event_id'])
        self.assertEqual(source['payload']['text'],self.req['text'])
        self.assertEqual(source['parent_event_id'],'source-unclear')
        self.assertEqual(digest(load_source(self.root,'source-unclear')),self.original_digest)
        self.assertEqual((self.root/'memory/triage/items'/(self.item['triage_id']+'.json')).read_bytes(),self.triage_bytes)
        self.assertTrue(list((self.root/'state/memory-pipeline/queue').glob('*.json')))
        self.assertEqual(status(self.root)['closed_targets'],{})
        self.assertTrue(supplement(self.root,self.req)['replayed'])
        self.assertEqual(len(list((self.root/'memory/supplements/items').glob('*.json'))),1)

    def test_changed_version_scope_command_or_injected_authority_are_rejected(self):
        for changes in ({'expected_version':'0'*64},{'scope':'cards-master'},{'owner_proof':True}):
            with self.assertRaises(ValueError):supplement(self.root,{**self.req,**changes})
        supplement(self.root,self.req)
        with self.assertRaises(ValueError):supplement(self.root,{**self.req,'text':'另外一条事实'})

    def test_accepted_unrelated_fact_cannot_resolve_the_original_question(self):
        # The reply is a valid durable preference but does not identify the
        # account mentioned by the original question.
        request = {**self.req, 'text': '我偏好每周报告使用中文。'}
        reply = supplement(self.root, request)
        fact = SimpleNamespace(fact_id='valid-unrelated-preference', source_event_id=reply['event_id'])
        with patch('javis_memory_adapter.review_policy.usable_facts', return_value=[fact]):
            projected = status(self.root)
            self.assertEqual(projected['closed_targets'], {})
            self.assertEqual(projected['items'][0]['state'], 'accepted_pending_resolution')
            self.assertEqual(projected['items'][0]['accepted_fact_ids'], [fact.fact_id])
            self.assertEqual(projected['items'][0]['message_zh'], '补充已形成记忆，原问题仍待核验')
            from memory_triage import pending_view
            pending = pending_view(self.root)['items']
            old = next(row for row in pending if row['triage_id'] == self.item['triage_id'])
            self.assertEqual(old['status'], 'needs_review')
        path = self.root/'memory/triage/items'/(self.item['triage_id']+'.json')
        self.assertEqual(path.read_bytes(), self.triage_bytes)


if __name__=='__main__':unittest.main()
