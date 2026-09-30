"""Opt-in real model/Neo4j acceptance, synthetic data and authenticator only."""
import asyncio,hashlib,json,os,subprocess,sys,shutil
from pathlib import Path
from datetime import datetime,timezone
CODE=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(CODE/'scripts'),str(CODE/'tools/memory-adapter'),str(CODE/'tests')]
from memory_screen import screen,load_source,source_digest
from memory_review import MemoryReview
from raw_storage import append_event
from javis_memory_adapter.review_policy import official_group
from javis_memory_adapter.structured_store import StructuredStore,StructuredFact
from javis_memory_adapter.adapter import MemoryAdapter
from javis_memory_adapter.usage_meter import summary as usage_summary, recent as usage_recent
from test_owner_auth import OwnerTests
import task_memory

async def query(root):
    a=MemoryAdapter(official_group(root,'invest'),meta_dir=Path(root)/'memory/structured/invest',
        env_path=Path.home()/'javis/tools/graphiti/.env')
    try:return (await a.query_current()).to_dict()
    finally:await a.close()

async def main(outdir):
    from jev_client import credentials_status, _credentials
    production = Path.home() / 'javis'
    if not credentials_status(production)['configured']:
        print(json.dumps({'status':'NOT_RUN','reason':'typesafe_key_required','real_jev_calls':False}))
        return
    # Process-local only: the synthetic root has no copy of the production secret.
    os.environ['TYPESAFE_API_KEY'] = _credentials(production)
    outdir=Path(outdir);outdir.mkdir(parents=True,exist_ok=True)
    helper=OwnerTests();helper.setUp();root=helper.root
    assert str(root).startswith('/tmp/javis-owner-auth-test-')
    (root/'config').mkdir(exist_ok=True)
    shutil.copyfile(CODE/'config/memory-pricing.json',root/'config/memory-pricing.json')
    report={'schema':'javis-memory-upgrade-live-1','synthetic_data':True,
        'owner_authenticator':'synthetic cryptographic authenticator, not Owner acceptance',
        'root':str(root),'started_at':datetime.now(timezone.utc).isoformat(),'checks':{}}
    groups=[]
    def record():
        (outdir/'live-acceptance.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
    try:
        text='Alice manages the Orion project as of 2026-09-24. This is a synthetic test fixture.'
        append_event(root,{'event_id':'live-source-one','event_type':'user_input','agent':'invest',
            'task_id':'live-task','occurred_at':'2026-09-24T08:00:00Z','completeness':'complete',
            'payload':{'text':text,'is_original_user_input':True}},relative_path='events/live-fixture/input.jsonl')
        args=dict(event_id='live-source-one',scope='invest',text=text,
            source_digest=source_digest(load_source(root,'live-source-one')),model='jev-1.13.0')
        result=await screen(root,**args)
        groups.append(result['group_id'])
        report['screen']={k:result.get(k) for k in ['run_id','status','stage','actual_model','verification_model','outcome','error']}
        report['screen']['candidate_count']=len(result.get('candidates',[]));record()
        assert result['status']=='complete' and result.get('candidates'),report['screen']
        assert not (root/'memory/structured/invest/facts.jsonl').exists()
        report['checks']['unconfirmed_isolation']=True
        usage_before_replay=usage_summary(root)['all']
        assert usage_before_replay['calls'] >= 4, usage_before_replay
        assert {r['stage'] for r in usage_recent(root,limit=500)} == {'screening','graphiti','verification','embedding'}
        assert usage_before_replay['pending']==0 and usage_before_replay['unknown_usage']==0
        assert usage_before_replay['unpriced_requests']==0
        assert usage_before_replay['tokens']['total']>0
        report['checks']['all_four_stages_metered']=True
        class NoCalls:
            async def evaluate(self,*a,**k):raise AssertionError('replay called model')
            async def extract(self,*a,**k):raise AssertionError('replay called graph extraction')
        replay=await screen(root,**args,model_client=NoCalls(),graph_client=NoCalls())
        assert replay['candidates']==result['candidates'];report['checks']['replay_without_model']=True
        assert usage_summary(root)['all']==usage_before_replay
        report['checks']['replay_does_not_increment_meter']=True
        review=MemoryReview(root);helper.enroll()
        pending=review.list_pending(helper.principal)
        selected=next(c for c in pending if 'Orion' in str(c['payload']['effects'][-1]['value']))
        ref=next(c for c in result['candidates'] if c['candidate_id']==selected['candidate_id'])
        request={k:ref[k] for k in ['candidate_id','version_digest','scope']}
        request.update(action='confirm',command_id='synthetic-confirm-one')
        helper.binding=review.binding_for(helper.principal,request)
        _,assertion=helper.decision()
        confirmation=review.review(helper.principal,request,assertion)
        assert confirmation['status']=='confirmed';report['checks']['signed_exact_confirmation']=True
        projection=await task_memory._graph_sync(root,['invest'])
        report['projection']=projection;record();assert projection['status']=='ok'
        formal_group=official_group(root,'invest');groups.append(formal_group)
        initial=await query(root);assert any('Orion' in str(f['value']) for f in initial['facts'])
        report['checks']['formal_graph_recall']=True
        # A real cryptographic correction is tied to the exact old ledger version.
        old=StructuredStore(root/'memory/structured/invest').get_fact(ref['fact_id'])
        assert old.subject_label=='Alice', 'fixture expects Alice as the stable relationship subject'
        correction_text='Correction to the synthetic fixture: Alice manages the Vega project, not the Orion project, effective 2026-09-24.'
        append_event(root,{'event_id':'live-source-correction','event_type':'user_input','agent':'invest',
            'occurred_at':'2026-09-24T09:00:00Z','payload':{'text':correction_text,'is_original_user_input':True}})
        fixed=StructuredFact('fact_live_corrected',old.subject_id,old.subject_label,old.predicate,
            old.value.replace('Orion','Vega'),old.unit,old.valid_from,old.valid_to,
            '2026-09-24T09:00:00Z','live-source-correction',['live-source-correction'],'extracted')
        corrected=review.propose('invest',fixed,operation='historical_correction',target_fact_id=old.fact_id)
        req={k:corrected[k] for k in ['candidate_id','version_digest','scope']};req.update(action='confirm',command_id='synthetic-correct-two')
        helper.binding=review.binding_for(helper.principal,req);_,a=helper.decision();review.review(helper.principal,req,a)
        assert (await task_memory._graph_sync(root,['invest']))['status']=='ok'
        now=await query(root)
        assert now['facts'] and all('Orion' not in str(f['value']) for f in now['facts'])
        assert any('Vega' in str(f['value']) for f in now['facts']);report['checks']['historical_correction']=True
        # Only this freshly-created synthetic root's protected group is removed.
        from neo4j import AsyncGraphDatabase
        d=AsyncGraphDatabase.driver(os.environ['NEO4J_URI'],auth=(os.environ['NEO4J_USER'],os.environ['NEO4J_PASSWORD']))
        try:await d.execute_query('MATCH (n {group_id:$g}) DETACH DELETE n',g=formal_group)
        finally:await d.close()
        assert (await task_memory._graph_sync(root,['invest']))['status']=='ok'
        rebuilt=await query(root);assert {f['fact_id'] for f in now['facts']}=={f['fact_id'] for f in rebuilt['facts']}
        report['checks']['type_b_rebuild_stable_ids']=True
        p=subprocess.run([sys.executable,'-B',__file__,'--query',str(root)],capture_output=True,text=True,timeout=60)
        assert p.returncode==0
        fresh=json.loads(p.stdout);assert any('Vega' in str(f['value']) for f in fresh['facts'])
        assert all('Orion' not in str(f['value']) for f in fresh['facts']);report['checks']['fresh_process_signed_recall']=True
        assert usage_summary(root)['all']==usage_before_replay
        report['checks']['formal_projection_and_recall_make_no_model_calls']=True
        ledger=(root/'memory/usage/requests.jsonl').read_text()
        assert 'Alice' not in ledger and 'Orion' not in ledger and 'messages' not in ledger
        report['checks']['meter_omits_content']=True
        report['status']='PASS'
    except Exception as exc:
        report.update(status='FAIL',error_type=type(exc).__name__)
        raise
    finally:
        report['usage']={'summary':usage_summary(root),'recent':usage_recent(root,limit=500)}
        report['finished_at']=datetime.now(timezone.utc).isoformat();record()
        # Deterministic cleanup only for the groups returned by this synthetic run.
        if groups and os.environ.get('NEO4J_URI'):
            from neo4j import AsyncGraphDatabase
            d=AsyncGraphDatabase.driver(os.environ['NEO4J_URI'],auth=(os.environ['NEO4J_USER'],os.environ['NEO4J_PASSWORD']))
            try:
                for group in groups:
                    assert group.startswith('javis-screen-') or group==official_group(root,'invest')
                    await d.execute_query('MATCH (n {group_id:$g}) DETACH DELETE n',g=group)
                report['isolated_graph_cleanup']=True
            finally:await d.close()
        helper.doCleanups();record()
    print(json.dumps(report,ensure_ascii=False))

if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--query':
        print(json.dumps(asyncio.run(query(Path(sys.argv[2]))),ensure_ascii=False))
    elif len(sys.argv)==3 and sys.argv[1]=='--live':
        asyncio.run(main(sys.argv[2]))
    else:
        print('Live acceptance requires --live OUTPUT_DIRECTORY and a configured TypeSafe key.')
        raise SystemExit(2)
