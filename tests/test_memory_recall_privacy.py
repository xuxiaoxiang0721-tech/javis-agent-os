"""All facts, RAW, owner proofs and files are synthetic and confined to TemporaryDirectory."""
import copy,hashlib,json,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
LIVE=Path('/home/user/javis')
STAGE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(LIVE/'tools/memory-adapter'))
sys.path.insert(0,str(LIVE/'scripts'))
sys.path.insert(0,str(STAGE/'scripts'))
import task_memory as tm
from memory_review import MemoryReview
from javis_memory_adapter.review_policy import digest,owner_confirmed
from javis_memory_adapter.structured_store import StructuredFact,StructuredStore

class RecallPrivacy(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='javis-recall-privacy-')
        self.root=Path(self.temp.name);self.seq=0;self.proofs={};self.principal=object()
        auth=types.ModuleType('owner_auth')
        def principal(root,value):
            self.assertEqual(root,self.root);self.assertIs(value,self.principal)
            return {'actor_id':'synthetic-test-owner'}
        def verify(root,assertion,binding):
            self.assertEqual(root,self.root);self.assertEqual(assertion,'test-only-assertion')
            pid='synthetic-proof-'+str(len(self.proofs)+1)
            proof={'actor_id':'synthetic-test-owner','proof_id':pid,'binding_hash':digest(binding)}
            self.proofs[pid]=(copy.deepcopy(binding),proof);return proof
        def recorded(root,pid,binding):
            self.assertEqual(root,self.root);old,proof=self.proofs[pid];self.assertEqual(old,binding)
            return copy.deepcopy(proof)
        auth.verify_principal=principal;auth.verify_decision=verify;auth.verify_recorded_decision=recorded
        self.auth=patch.dict(sys.modules,{'owner_auth':auth});self.auth.start()
        self.graph=patch.object(tm,'_graph',return_value={'status':'pending','scopes':{},'reason':'synthetic_offline'});self.graph_mock=self.graph.start()
        self.review=MemoryReview(self.root)
    def tearDown(self):self.graph.stop();self.auth.stop();self.temp.cleanup()
    def source(self,eid,text,**extra):
        event={'event_id':eid,'task_id':'synthetic-source-task','agent':'cards-master','event_type':'user_input','payload':{'text':text,'is_original_user_input':True},**extra}
        p=self.root/'raw/events/fixture.jsonl';p.parent.mkdir(parents=True,exist_ok=True)
        with p.open('a') as f:f.write(json.dumps(event,ensure_ascii=False)+'\n')
        return event
    def fact(self,value='BLUE',scope='cards-master',subject='project',predicate='color',source_extra=None,source_text=None,refs=None,confirm=True,notes=None):
        self.seq+=1;fid='fact-'+str(self.seq);eid='source-'+str(self.seq)
        self.source(eid,source_text or 'project color '+str(value),**(source_extra or {}))
        fact=StructuredFact(fact_id=fid,subject_id=subject,subject_label=subject,predicate=predicate,value=value,unit=None,valid_from='2026-01-01T00:00:00+00:00',valid_to=None,recorded_at='2026-01-01T00:00:00+00:00',source_event_id=eid,raw_refs=refs or [eid],status='extracted',notes=notes or [])
        c=self.review.propose(scope,fact)
        if confirm:
            req={'action':'confirm','candidate_id':c['candidate_id'],'version_digest':c['version_digest'],'scope':scope,'command_id':'confirm-'+fid}
            self.review.review(self.principal,req,'test-only-assertion')
            store=StructuredStore(self.root/'memory/structured'/scope)
            self.assertTrue(owner_confirmed(store,store.get_fact(fid)))
        return fid,scope
    def tag(self,fid,scope,**metadata):
        store=StructuredStore(self.root/'memory/structured'/scope)
        row=store.get_fact(fid).to_dict();row.update(metadata)
        with store.facts_path.open('a') as f:f.write(json.dumps(row)+'\n')
        self.assertTrue(owner_confirmed(store,store.get_fact(fid)))
    def prepare(self,text='project color',role='cards-master'):
        self.seq+=1;tid='synthetic-query-'+str(self.seq);eid='query-'+str(self.seq)
        event=self.source(eid,text)
        # Make the synthetic event refer to this new query task before any proof is created for it.
        p=self.root/'raw/events/fixture.jsonl';lines=p.read_text().splitlines();event['task_id']=tid;event['agent']=role;lines[-1]=json.dumps(event);p.write_text('\n'.join(lines)+'\n')
        task=self.root/'tasks'/tid;task.mkdir(parents=True)
        return tm.prepare(self.root,task,{'task_id':tid,'role_id':role,'goal':text,'original_user_input':text},1,eid)
    def assert_no_recall(self,result,*values):
        self.assertEqual(result['read_refs'],[]);self.assertEqual(result['conflicts'],[])
        for value in values:self.assertNotIn(value,result['prompt'])
    def test_normal_confirmed_relevant_unclassified_is_recalled(self):
        fid,_=self.fact();r=self.prepare();self.assertEqual([x['fact_id'] for x in r['read_refs']],[fid]);self.assertIn('BLUE',r['prompt'])
    def test_zero_relevance_does_not_inject_any_confirmed_fact(self):
        self.fact();self.assert_no_recall(self.prepare('37*19+11'),'BLUE')
    def test_fact_metadata_survives_model_field_projection(self):
        for metadata in ({'classification':'L4'},{'privacy_level':'strict-L4'},{'metadata':{'data_classification':'严格L4'}},{'sensitivity':' L4 '},{'classification':'L4 (strict private)'}):
            with self.subTest(metadata=metadata):
                fid,scope=self.fact(value='CLASSIFIED_'+str(self.seq));self.tag(fid,scope,**metadata)
        self.assert_no_recall(self.prepare(),'CLASSIFIED_')
    def test_fact_prefixes_and_notes_are_excluded(self):
        for text in ('L4: PREFIX_SECRET','严格L4：PREFIX_SECRET','隐私等级：L4: PREFIX_SECRET','classification=L4: PREFIX_SECRET','L4 confidential PREFIX_SECRET'):
            self.fact(value=text)
        self.fact(value='NOTE_SECRET',notes=['L4: private-note'])
        self.assert_no_recall(self.prepare(),'PREFIX_SECRET','NOTE_SECRET')
    def test_source_event_metadata_blocks_safe_looking_fact(self):
        self.fact(value='SOURCE_LABEL_SECRET',source_extra={'metadata':{'privacy_level':'L4'}})
        self.assert_no_recall(self.prepare(),'SOURCE_LABEL_SECRET')
    def test_source_event_text_prefix_blocks_safe_looking_fact(self):
        self.fact(value='SOURCE_PREFIX_SECRET',source_text='L4: source classified')
        self.assert_no_recall(self.prepare(),'SOURCE_PREFIX_SECRET')
    def test_additional_raw_ref_source_is_checked(self):
        self.source('extra-source','ordinary',classification='L4')
        self.fact(value='RAW_REF_SECRET',refs=['extra-source'])
        self.assert_no_recall(self.prepare(),'RAW_REF_SECRET')
    def test_source_credentials_are_excluded_without_emitting_them(self):
        self.fact(value='CREDENTIAL_SOURCE',source_extra={'payload':{'text':'project color','password':'synthetic-only-password'}})
        self.assert_no_recall(self.prepare(),'CREDENTIAL_SOURCE','synthetic-only-password')
    def test_fact_credentials_are_excluded(self):
        fid,scope=self.fact(value='CREDENTIAL_FACT')
        self.tag(fid,scope,password='synthetic-only-password')
        self.assert_no_recall(self.prepare(),'CREDENTIAL_FACT','synthetic-only-password')
    def test_unconfirmed_candidate_not_recalled(self):
        self.fact(value='CANDIDATE_SECRET',confirm=False)
        self.assert_no_recall(self.prepare(),'CANDIDATE_SECRET')
    def test_irrelevant_conflict_does_not_leak(self):
        self.fact(value='CONFLICT_ONE');self.fact(value='CONFLICT_TWO')
        self.assert_no_recall(self.prepare('37*19+11'),'CONFLICT_ONE','CONFLICT_TWO')
    def test_relevant_conflict_reports_ids_without_values(self):
        f1,_=self.fact(value='CONFLICT_ONE');f2,_=self.fact(value='CONFLICT_TWO');r=self.prepare()
        self.assertEqual(r['read_refs'],[]);self.assertEqual(set(r['conflicts'][0]['fact_ids']),{f1,f2})
        self.assertNotIn('values',r['conflicts'][0]);self.assertNotIn('slot',r['conflicts'][0]);self.assertNotIn('CONFLICT_ONE',r['prompt']);self.assertNotIn('CONFLICT_TWO',r['prompt'])
    def test_l4_conflict_member_suppresses_entire_hint(self):
        self.fact(value='SAFE_CONFLICT_VALUE');fid,scope=self.fact(value='L4_CONFLICT_VALUE');self.tag(fid,scope,privacy_level='L4')
        self.assert_no_recall(self.prepare(),'SAFE_CONFLICT_VALUE','L4_CONFLICT_VALUE')
    def test_l4_source_conflict_does_not_reenter_via_hint(self):
        self.fact(value='SAFE_CONFLICT_VALUE');self.fact(value='L4_SOURCE_CONFLICT',source_extra={'classification':'L4'})
        self.assert_no_recall(self.prepare(),'SAFE_CONFLICT_VALUE','L4_SOURCE_CONFLICT')
    def test_safe_ref_helper_never_opens_arbitrary_raw_ref_path(self):
        p=self.root/'not-an-event';p.write_text('L4: not an event')
        row={'source_event_id':'missing','raw_refs':[str(p)],'value':'ordinary'}
        with patch.object(Path,'read_text',side_effect=AssertionError('must not open referenced path')):
            self.assertTrue(tm._cloud_recall_safe(row,{}))
    def test_scope_and_graph_filter_remain_enforced(self):
        fid,_=self.fact();self.assert_no_recall(self.prepare(role='invest'),'BLUE')
        self.graph_mock.return_value={'status':'ok','scopes':{'cards-master':{'status':'ok','fact_ids':[]}}}
        self.assert_no_recall(self.prepare(),'BLUE')
        self.graph_mock.return_value['scopes']['cards-master']['fact_ids']=[fid]
        self.assertEqual(len(self.prepare()['read_refs']),1)
    def test_non_l4_labels_do_not_require_migration(self):
        fid,scope=self.fact();self.tag(fid,scope,privacy_level='L2')
        self.assertEqual([x['fact_id'] for x in self.prepare()['read_refs']],[fid])
    def test_source_and_fact_files_not_modified_by_prepare(self):
        self.fact();query=self.prepare();before={p:p.read_bytes() for d in ('raw','memory') for p in (self.root/d).rglob('*.jsonl')}
        # Reuse the already committed query without creating another input event.
        tasks=sorted((self.root/'tasks').iterdir());task=tasks[-1];eid=task.name.replace('synthetic-query-','query-')
        tm.prepare(self.root,task,{'task_id':task.name,'role_id':'cards-master','goal':'project color','original_user_input':'project color'},1,eid)
        self.assertEqual(before,{p:p.read_bytes() for p in before})
    def test_proposal_path_and_missing_file_fallback_unchanged(self):
        r=self.prepare('请记住：测试颜色是 BLUE');proposal=Path(r['proposal_path'])
        self.assertEqual(proposal.name,'memory-proposals.json');self.assertEqual(proposal.parent.name,'1');self.assertFalse(proposal.exists())
        task=proposal.parents[2];items=tm._proposal_items(task,1,'请记住：测试颜色是 BLUE')
        self.assertTrue(items);self.assertIn('BLUE',items[0]['value'])

if __name__=='__main__':unittest.main(verbosity=2)