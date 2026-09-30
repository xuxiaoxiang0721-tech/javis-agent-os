import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'tools/memory-adapter')]
from memory_corpus import CorpusReader, adapt_record, build_event, inventory, load_text, policy_flags, text_fields, selected_time, verify_canonical


class CorpusTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.events=self.root/'raw/events/day.jsonl';self.events.parent.mkdir(parents=True)
    def tearDown(self):self.tmp.cleanup()
    def rows(self,*rows):
        self.events.write_text(''.join(json.dumps(x)+'\n' for x in rows))
    def row(self,**kw):
        return dict(event_id='ev-one',event_type='user_input',agent='invest',occurred_at=None,
                    payload={'text':'Synthetic rule: retain exact provenance.','is_original_user_input':True},**kw)
    def candidates(self):return [x for x in inventory(self.root)['items'] if x['route']=='candidate']
    def test_tool_result_exact_and_not_owner(self):
        row=self.row();row['event_type']='tool_result';row['payload']={'result':'Synthetic observed balance: 7.'}
        self.rows(row);item=self.candidates()[0]
        self.assertEqual(item['source_nature'],'tool_observation');self.assertFalse(item['authorship_verified'])
        self.assertEqual(load_text(self.root,item),row['payload']['result'])
    def test_native_completed_not_started_or_reasoning(self):
        for kind in ['item.started','item.completed']:
            row={'event_type':'codex_stream_event','payload':{'event':{'type':kind,'item':{'type':'agent_message','text':'Synthetic'}}}}
            self.assertEqual(len(text_fields(row)),int(kind=='item.completed'))
        self.assertEqual(text_fields({'type':'reasoning','content':'hidden'}),[])
    def test_full_parent_policy_before_selector(self):
        for patch in [{'cloud_eligible':False},{'sensitivity':'L4'},{'ignored':{'api_key':'syntheticsecret'}}]:
            row=self.row();row.update(patch);self.rows(row)
            items=inventory(self.root)['items'];self.assertTrue(items);self.assertTrue(all(x['route']=='local_only' for x in items))
    def test_audit_cloud_false_not_called_sensitive(self):
        self.assertEqual(policy_flags({'event_type':'source_coverage','cloud_eligible':False}),['explicit_cloud_false'])
    def test_old_mail_without_id_has_stable_locator_not_owner(self):
        self.rows({'agent':'invest','message_id':'synthetic','body_full':'Synthetic mail body','summary':'Synthetic derived summary'})
        a=inventory(self.root);b=inventory(self.root)
        self.assertEqual(a['manifest_digest'],b['manifest_digest'])
        self.assertEqual({x['source_nature'] for x in a['items']},{'mail_body','derived_summary'})
        self.assertTrue(all(x['event_id'] is None and not x['authorship_verified'] for x in a['items']))
    def test_scope_unknown_and_conflict_not_inferred(self):
        self.rows({'agent':'grok-star','body_full':'Synthetic'},dict(self.row(),scope='cards-master'))
        self.assertTrue(all(x['route']=='recoverable' and x['scope'] is None for x in inventory(self.root)['items']))
    def test_exact_duplicates_keep_bindings_only_within_scope(self):
        a=self.row();b=dict(a,event_id='ev-two');c=dict(a,event_id='ev-three',agent='cards-master')
        self.rows(a,b,c);items=inventory(self.root)['items']
        self.assertEqual([x['route'] for x in items],['candidate','duplicate','candidate'])
        self.assertEqual(items[1]['duplicate_of'],items[0]['item_id'])
        self.assertNotEqual(items[0]['source']['line'],items[1]['source']['line'])
    def test_source_mutation_blocks_load(self):
        self.rows(self.row());item=self.candidates()[0]
        self.rows(dict(self.row(),agent='cards-master'))
        with self.assertRaisesRegex(ValueError,'file_changed'):load_text(self.root,item)
    def test_metadata_tampering_blocks(self):
        self.rows(self.row());item=self.candidates()[0];item['scope']='cards-master'
        with self.assertRaisesRegex(ValueError,'binding_changed'):load_text(self.root,item)
    def test_metadata_contains_no_body_and_no_model_processing_claim(self):
        self.rows(self.row());report=inventory(self.root)
        self.assertNotIn('Synthetic rule',json.dumps(report))
        self.assertEqual(report['summary']['model_calls'],0)
        self.assertTrue(all(not x['external_send_authorized'] for x in report['items']))
    def test_oversize_no_lossy_slice(self):
        row=self.row();row['payload']['text']='x'*17000;self.rows(row)
        item=inventory(self.root)['items'][0]
        self.assertEqual(item['route'],'recoverable');self.assertEqual(item['utf8_bytes'],17000)
        with self.assertRaisesRegex(ValueError,'not_candidate'):load_text(self.root,item)
    def test_build_is_stable_preserves_unknown_time_never_confirms(self):
        self.rows(self.row());item=self.candidates()[0];before=self.events.read_bytes()
        event=build_event(self.root,item)
        self.assertEqual(event,build_event(self.root,item));self.assertEqual(before,self.events.read_bytes())
        self.assertIsNone(event['occurred_at']);self.assertFalse(event['payload']['is_original_user_input'])
        self.assertFalse(event['payload']['confirmation_authority'])
        self.assertEqual(event['payload']['text'],self.row()['payload']['text'])
        self.assertEqual(event['payload']['source_reference']['selector'],['payload','text'])
    def test_hardlink_fails_closed(self):
        self.rows(self.row());os.link(self.events,self.root/'copy')
        with self.assertRaises(Exception):inventory(self.root)
    def test_symlink_not_followed_and_exclusion_visible(self):
        outside=self.root/'secret';outside.write_text('Never read synthetic secret')
        (self.events.parent/'link.jsonl').symlink_to(outside)
        report=inventory(self.root)
        self.assertEqual(len(report['excluded_entries']),1);self.assertEqual(report['items'],[])
    def test_partial_mail_excerpt_not_full_message(self):
        self.rows({'agent':'invest','body_preview':'Synthetic truncated preview'})
        item=inventory(self.root)['items'][0]
        self.assertEqual(item['reason'],'incomplete_source_fragment')
    def test_import_cannot_claim_authenticated_user(self):
        path=self.root/'memory/imports/test.jsonl';path.parent.mkdir(parents=True);path.write_text(json.dumps(self.row())+'\n')
        item=self.candidates()[0]
        self.assertFalse(item['authorship_verified'])
    def test_native_rollout_and_chatgpt_mapping_are_not_noncontent(self):
        rows=[{'type':'event_msg','payload':{'type':'user_message','message':'Synthetic native input'}},
              {'type':'response_item','payload':{'type':'message','role':'assistant','content':[{'type':'output_text','text':'Synthetic native reply'}]}},
              {'mapping':{'node-a':{'message':{'author':{'role':'user'},'content':{'parts':['Synthetic mapping input']}}}}}]
        for row in rows:self.assertEqual(len(text_fields(row)),1)
    def test_import_tool_result_and_assistant_completed_are_adapted(self):
        for row in [{'type':'tool.result','data':{'output':'Synthetic tool output'}},
                    {'type':'model.completed','data':{'assistantTexts':['Synthetic assistant result']}}]:
            self.assertEqual(len(text_fields(row)),1)
    def test_unrecognized_import_is_gap_not_silently_noncontent(self):
        item=adapt_record({'unrecognized_body':{'message':'Synthetic'}},{'path':'memory/imports/unknown.json'},layer='memory/imports')[0]
        self.assertEqual(item['route'],'recoverable')
        self.assertEqual(item['reason'],'unadapted_import_schema_requires_review')
    def test_legacy_confirmed_is_claim_and_formal_ledger_is_preserved(self):
        for rel in ['memory/confirmed/invest/facts.jsonl','memory/structured/invest/facts.jsonl']:
            p=self.root/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps({'role':'invest','fact':'Synthetic legacy claim','tier':'confirmed'})+'\n')
        report=inventory(self.root)
        old=next(x for x in report['items'] if x['layer']=='memory/confirmed')
        formal=next(x for x in report['items'] if x['layer']=='memory/structured')
        self.assertEqual(old['route'],'candidate');self.assertEqual(old['source_nature'],'legacy_claim')
        self.assertFalse(old['authorship_verified']);self.assertEqual(formal['route'],'local_only')
    def object_fixture(self,*,text=b'Synthetic immutable final output',**extra):
        from memory_corpus import sha
        data=text;h=sha(data)
        obj=self.root/'raw/objects'/h;obj.parent.mkdir(parents=True);obj.write_bytes(data)
        man=self.root/'raw/manifests/objects.jsonl';man.parent.mkdir(parents=True)
        man.write_text(json.dumps({'sha256':h,'object_path':str(obj.relative_to(self.root)),**extra})+'\n')
        self.rows({'event_id':'ev-object','event_type':'native_final_output','agent':'invest','occurred_at':None,
                   'payload':{'native_final_output_sha256':h}})
        return obj,man
    def test_object_uses_manifest_and_parent_exact_scope(self):
        obj,man=self.object_fixture();item=next(x for x in self.candidates() if x.get('event_type')=='bound_object')
        self.assertEqual(load_text(self.root,item),obj.read_text())
        event=build_event(self.root,item);self.assertEqual(event['agent'],'invest');self.assertEqual(event['payload']['source_kind'],'model_derived')
        altered=copy.deepcopy(item);altered['source_nature']='recorded_user_input'
        with self.assertRaisesRegex(ValueError,'provenance_changed'):load_text(self.root,altered)
        man.write_text(man.read_text()+'\n')
        with self.assertRaisesRegex(ValueError,'file_changed'):load_text(self.root,item)
    def test_object_parent_or_manifest_cloud_false_cannot_be_bypassed(self):
        self.object_fixture(cloud_eligible=False)
        items=inventory(self.root)['items'];bound=next(x for x in items if x.get('event_type')=='bound_object')
        self.assertEqual(bound['route'],'local_only')
        bound['route']='candidate'
        with self.assertRaisesRegex(ValueError,'manifest_changed_or_excluded'):load_text(self.root,bound)
    def test_structured_tool_value_is_whole_explicit_serialization(self):
        self.rows({'agent':'invest','role':'tool','message':{'content':[{'type':'tool_result','result':{'negated':True,'amount':7}}]}})
        item=self.candidates()[0]
        self.assertEqual(item['text_encoding'],'canonical_json_value')
        self.assertEqual(json.loads(load_text(self.root,item)),{'negated':True,'amount':7})
        self.assertEqual(build_event(self.root,item)['payload']['text_encoding'],'canonical_json_value')
        item['text_encoding']='verbatim_field'
        with self.assertRaisesRegex(ValueError,'binding_changed'):load_text(self.root,item)
    def test_multipart_does_not_drop_neighboring_conditions(self):
        self.rows({'agent':'invest','role':'user','content':[{'type':'text','text':'Synthetic do this.'},{'type':'text','text':'Only when condition holds.'}]})
        items=inventory(self.root)['items']
        self.assertEqual(len(items),2);self.assertTrue(all(x['reason']=='multipart_message_requires_whole_context_adapter' for x in items))
    def test_traversal_source_path_rejected(self):
        self.rows(self.row());item=self.candidates()[0]
        item['source']['path']='raw/../../outside.jsonl'
        with self.assertRaisesRegex(ValueError,'outside_root'):load_text(self.root,item)
    def test_nested_message_time_never_falls_back_to_container(self):
        row={'occurred_at':'2026-09-25T00:00:00Z','payload':{'messages':[{'text':'Synthetic unknown time'}]}}
        self.assertIsNone(selected_time(row,['payload','messages',0,'text'])['occurred_at'])
        row['payload']['messages'][0]['timestamp']='2026-09-24T12:34:56.123456789Z'
        stamp=selected_time(row,['payload','messages',0,'text'])
        self.assertEqual(stamp['occurred_at'],'2026-09-24T12:34:56.123456789Z')
        self.assertEqual(stamp['source_time_field'],['payload','messages',0,'timestamp'])
    def test_chatgpt_create_time_epoch_and_invalid_preserved_unknown(self):
        row={'mapping':{'a':{'message':{'create_time':1780000000.125,'content':{'parts':['Synthetic']}}}}}
        selector=['mapping','a','message','content','parts',0]
        stamp=selected_time(row,selector)
        self.assertTrue(stamp['occurred_at'].endswith('.125Z'))
        row['mapping']['a']['message']['create_time']=True
        self.assertIsNone(selected_time(row,selector)['occurred_at'])
    def test_verify_canonical_reloads_sources_and_rejects_tampering(self):
        self.rows(self.row());item=self.candidates()[0];event=build_event(self.root,item)
        self.assertTrue(verify_canonical(self.root,event,event['payload']['text'])['verified'])
        event['payload']['is_original_user_input']=True
        with self.assertRaisesRegex(ValueError,'canonical_changed'):verify_canonical(self.root,event)
        event=build_event(self.root,item);self.events.write_text(self.events.read_text()+'\n')
        with self.assertRaisesRegex(ValueError,'file_changed'):verify_canonical(self.root,event)
    def test_conflicting_declared_scopes_cannot_be_replaced_by_binding(self):
        row=dict(self.row(),scope='cards-master')
        item=adapt_record(row,{'path':'test'},scope_binding={'scope':'operations'})[0]
        self.assertIsNone(item['scope']);self.assertEqual(item['reason'],'scope_binding_conflict')
    def test_same_text_different_source_time_not_duplicate(self):
        a=self.row();a['occurred_at']='2026-01-01T00:00:00Z'
        b=dict(a,event_id='ev-two',occurred_at='2026-09-25T00:00:00Z')
        self.rows(a,b);self.assertEqual(len(self.candidates()),2)
    def test_nested_message_timestamp_beats_container_native_clock(self):
        row={'timestamp':'2026-09-25T00:00:00Z','message':{'role':'user','timestamp':'2020-01-01T00:00:00Z','content':'Synthetic'}}
        self.assertEqual(selected_time(row,['message','content'])['occurred_at'],'2020-01-01T00:00:00Z')
    def test_unknown_schema_all_layers_remains_recoverable(self):
        for layer in ['memory/root','life_notebook','memory/imports']:
            self.assertEqual(adapt_record({'unknown':'Synthetic'},{'path':'test'},layer=layer)[0]['route'],'recoverable')
    def test_reader_same_strict_result_pinned_items_and_closed_guard(self):
        self.rows(self.row());item=self.candidates()[0]
        with CorpusReader(self.root,[item]) as reader:
            self.assertEqual(reader.load_text(item),load_text(self.root,item))
            event=reader.build_event(item)
            self.assertTrue(reader.verify_canonical(event)['verified'])
            self.assertTrue(verify_canonical(self.root,event)['verified'])
            bad=copy.deepcopy(item);bad['scope']='cards-master'
            with self.assertRaisesRegex(ValueError,'not_pinned'):reader.load_text(bad)
        with self.assertRaisesRegex(ValueError,'not_open'):reader.load_text(item)
    def test_reader_exit_full_hash_catches_same_size_mtime_tampering(self):
        self.rows(self.row());item=self.candidates()[0];s=self.events.stat()
        with self.assertRaisesRegex(ValueError,'before_commit'):
            with CorpusReader(self.root,[item]) as reader:
                reader.build_event(item)
                self.events.write_bytes(self.events.read_bytes().replace(b'Synthetic',b'Altered!!'))
                os.utime(self.events,ns=(s.st_atime_ns,s.st_mtime_ns))
    def test_oversize_line_continues_at_exact_next_record(self):
        from memory_corpus import MAX_RECORD_BYTES,_records,sha
        large=b'x'*(MAX_RECORD_BYTES+99)+b'\n'
        self.events.write_bytes(large+json.dumps(self.row()).encode()+b'\n')
        rows=list(_records(self.events))
        self.assertEqual(rows[0][2],'oversize_record');self.assertEqual(rows[0][1]['record_bytes_sha256'],sha(large))
        self.assertEqual(rows[1][1]['byte_start'],len(large));self.assertEqual(rows[1][1]['line'],2)
    def test_trace_content_items_preserve_body_and_full_parent_policy(self):
        row={'type':'tool.result','agent':'invest','data':{'contentItems':[{'type':'inputText','text':'Synthetic exact tool body'}]}}
        self.rows(row);item=self.candidates()[0]
        self.assertEqual(item['source_nature'],'tool_observation')
        self.assertEqual(item['text_selector'],['data','contentItems',0,'text'])
        self.assertEqual(load_text(self.root,item),'Synthetic exact tool body')
        event=build_event(self.root,item);self.assertTrue(verify_canonical(self.root,event)['verified'])
        row['data']['cloud_eligible']=False;self.rows(row)
        self.assertEqual(inventory(self.root)['items'][0]['route'],'local_only')
    def test_known_export_gaps_and_assembled_prompts_are_explicit(self):
        cases=[({'kind':'tool_result','note':'Synthetic omitted placeholder','pos':1},'recoverable','exported_content_omitted'),
               ({'type':'model.completed','data':{'truncated':True,'originalBytes':90000,'limitBytes':100}},'recoverable','original_content_truncated_in_export'),
               ({'runtimeFile':'runtime.jsonl','schemaVersion':1,'sessionId':'synthetic','traceSchema':'trace'},'recoverable','index_only_requires_original_runtime_file'),
               ({'type':'context.compiled','data':{'prompt':'Synthetic business instruction','systemPrompt':'Synthetic system'}},'local_only','derived_prompt_context')]
        for row,route,reason in cases:
            item=adapt_record(row,{'path':'memory/imports/test.jsonl'},layer='memory/imports')[0]
            self.assertEqual((item['route'],item['reason']),(route,reason))
    def test_implicit_reader_unpinned_dependency_gets_full_verification(self):
        a=self.row();b=dict(self.row(),event_id='ev-two',agent='cards-master')
        self.rows(a,b);items=self.candidates();other=build_event(self.root,items[1])
        with CorpusReader(self.root,[items[0]]) as reader:
            self.assertTrue(verify_canonical(self.root,other)['verified'])
            with self.assertRaisesRegex(ValueError,'not_pinned'):reader.verify_canonical(other)
            other['payload']['text']='Tampered synthetic dependency'
            with self.assertRaisesRegex(ValueError,'canonical_changed'):verify_canonical(self.root,other)
    def test_bound_object_receipt_clock_never_anchors_relative_date(self):
        from memory_screen import _source_context
        from jev_policy import _source_state,_local_checks
        obj,_=self.object_fixture(text=b'Alice joins Orion tomorrow.')
        row=json.loads(self.events.read_text());stamp='2026-09-25T12:00:00.123Z'
        for kind in ['native_final_output','file_snapshot']:
            row.update(event_type=kind,occurred_at=stamp,captured_at=stamp,time_basis='source_timestamp')
            row['payload']={('native_final_output_sha256' if kind=='native_final_output' else 'sha256'):obj.name}
            self.rows(row);item=next(x for x in self.candidates() if x.get('event_type')=='bound_object')
            event=build_event(self.root,item)
            self.assertIsNone(event['occurred_at']);self.assertEqual(event['time_basis'],'capture_only')
            self.assertIsNone(event['source_time_field'])
            self.assertEqual(event['payload']['artifact_receipt']['parent_event_occurred_at'],stamp)
            self.assertFalse(event['payload']['artifact_receipt']['semantic_anchor'])
            context=_source_context(event,event['payload']['text'])
            base=_source_state(event['payload']['text'],'invest',context,event['occurred_at'])
            result=_local_checks(base,{'value':'Alice joins Orion tomorrow.','valid_from':'2026-09-26T00:00:00Z','valid_to':None})
            self.assertEqual(result[2:],('review','relative_time_unanchored'))
    def test_bound_object_new_id_rejects_old_canonical_and_keeps_source_binding(self):
        from memory_corpus import digest,BOUND_OBJECT_TIME_POLICY
        self.object_fixture();row=json.loads(self.events.read_text());row['occurred_at']='2026-09-25T12:00:00Z';self.rows(row)
        item=next(x for x in self.candidates() if x.get('event_type')=='bound_object')
        event=build_event(self.root,item)
        old=copy.deepcopy(event);old['event_id']='ev-corpus-'+digest([item['item_id'],item['source_digest'],item['content_sha256']])[:32]
        old.update(occurred_at=row['occurred_at'],time_basis='source_timestamp',source_time_field=['occurred_at'])
        old['payload'].pop('artifact_receipt')
        self.assertNotEqual(old['event_id'],event['event_id'])
        self.assertEqual(event['payload']['artifact_receipt']['time_policy'],BOUND_OBJECT_TIME_POLICY)
        self.assertEqual(event['payload']['corpus_item'],item)
        with self.assertRaisesRegex(ValueError,'canonical_changed'):verify_canonical(self.root,old)
        self.assertTrue(verify_canonical(self.root,event)['verified'])
        self.assertEqual(event,build_event(self.root,item))
    def test_non_object_canonical_identity_formula_is_unchanged(self):
        from memory_corpus import digest
        self.rows(self.row());item=self.candidates()[0];event=build_event(self.root,item)
        self.assertEqual(event['event_id'],'ev-corpus-'+digest([item['item_id'],item['source_digest'],item['content_sha256']])[:32])
        self.assertNotIn('artifact_receipt',event['payload'])
    def legacy_clock_fixture(self):
        from memory_corpus import _selected_time_v1
        row=self.row();row.update(event_type='tool_result',occurred_at='2026-09-25T12:00:00.123Z',captured_at='2026-09-25T12:00:00.123Z')
        row['payload']={'result':'Alice joins Orion tomorrow.','record_source':'codex_log_parse'}
        self.rows(row);item=self.candidates()[0]
        # A pre-fix manifest is immutable: retain its exact old time metadata.
        item['source_time']=_selected_time_v1(row,item['text_selector']);item['has_original_time']=True
        return row,item
    def test_legacy_clock_old_descriptor_preserved_new_event_unanchored(self):
        from memory_screen import _source_context
        from jev_policy import _source_state,_local_checks
        row,item=self.legacy_clock_fixture();original=copy.deepcopy(item)
        with CorpusReader(self.root,[item]) as reader:event=reader.build_event(item)
        self.assertEqual(item,original);self.assertEqual(event['payload']['corpus_item'],original)
        self.assertIsNone(event['occurred_at']);self.assertEqual(event['time_basis'],'capture_only')
        self.assertIsNone(event['source_time_field'])
        receipt=event['payload']['legacy_time_receipt']
        self.assertEqual(receipt['declared_occurred_at'],row['occurred_at']);self.assertFalse(receipt['semantic_anchor'])
        context=_source_context(event,event['payload']['text'])
        base=_source_state(event['payload']['text'],'invest',context,event['occurred_at'])
        result=_local_checks(base,{'value':'Alice joins Orion tomorrow.','valid_from':'2026-09-26T00:00:00Z','valid_to':None})
        self.assertEqual(result[2:],('review','relative_time_unanchored'))
    def test_legacy_time_new_id_rejects_old_canonical(self):
        from memory_corpus import digest,LEGACY_SOURCE_TIME_POLICY
        row,item=self.legacy_clock_fixture();event=build_event(self.root,item)
        identity=[item['item_id'],item['source_digest'],item['content_sha256']]
        self.assertEqual(event['event_id'],'ev-corpus-'+digest(identity+[LEGACY_SOURCE_TIME_POLICY,digest(item)])[:32])
        old=copy.deepcopy(event);old.update(event_id='ev-corpus-'+digest(identity)[:32],**item['source_time'])
        old['payload'].pop('legacy_time_receipt')
        with self.assertRaisesRegex(ValueError,'canonical_changed'):verify_canonical(self.root,old)
        self.assertTrue(verify_canonical(self.root,event)['verified'])
        self.assertEqual(event,build_event(self.root,item))
    def test_legacy_old_and_new_inventory_descriptors_cannot_collide(self):
        _,old_item=self.legacy_clock_fixture();new_item=self.candidates()[0]
        self.assertEqual(old_item['item_id'],new_item['item_id'])
        self.assertIsNotNone(old_item['source_time']['occurred_at'])
        self.assertIsNone(new_item['source_time']['occurred_at'])
        with CorpusReader(self.root,[old_item,new_item]) as reader:
            old_manifest_event=reader.build_event(old_item);new_manifest_event=reader.build_event(new_item)
            self.assertNotEqual(old_manifest_event['event_id'],new_manifest_event['event_id'])
            self.assertEqual(old_manifest_event['payload']['text'],new_manifest_event['payload']['text'])
            for event,item in [(old_manifest_event,old_item),(new_manifest_event,new_item)]:
                self.assertEqual(event['payload']['corpus_item'],item)
                self.assertIsNone(event['occurred_at'])
                self.assertTrue(reader.verify_canonical(event)['verified'])
                self.assertEqual(event,reader.build_event(item))
    def test_legacy_descriptor_compatibility_rejects_forged_clock_or_provenance(self):
        _,item=self.legacy_clock_fixture()
        for key,value in [('source_time',{'occurred_at':'2001-01-01T00:00:00Z','time_basis':'source_timestamp','source_time_field':['occurred_at']}),
                          ('source_time',{'occurred_at':None,'time_basis':'capture_only','source_time_field':['occurred_at']}),
                          ('scope','cards-master'),('authorship_verified',True),('provenance',{'speaker':'user'})]:
            forged=copy.deepcopy(item);forged[key]=value
            with self.subTest(key=key,value=value),self.assertRaisesRegex(ValueError,'binding_changed'):
                build_event(self.root,forged)
    def test_legacy_semantics_do_not_override_native_timestamp(self):
        from memory_corpus import digest
        row,_=self.legacy_clock_fixture();row['timestamp']='2026-09-22T10:00:00.123456789Z';self.rows(row)
        item=self.candidates()[0];event=build_event(self.root,item)
        self.assertEqual(event['occurred_at'],row['timestamp']);self.assertEqual(event['source_time_field'],['timestamp'])
        self.assertNotIn('legacy_time_receipt',event['payload'])
        self.assertEqual(event['event_id'],'ev-corpus-'+digest([item['item_id'],item['source_digest'],item['content_sha256']])[:32])
    def test_legacy_time_rejection_applies_to_selected_message_only(self):
        stamp='2026-09-25T12:00:00Z'
        row={'agent':'invest','occurred_at':stamp,'missing_reason':'occurred_at_defaulted_to_captured_at',
             'payload':{'record_source':'codex_log_parse','messages':[{'speaker':'user','text':'Synthetic plan.','occurred_at':stamp}]}}
        selector=['payload','messages',0,'text']
        self.assertEqual(selected_time(row,selector)['occurred_at'],stamp)
        row['payload']['messages'][0]['missing_reason']='occurred_at_defaulted_to_captured_at'
        self.assertIsNone(selected_time(row,selector)['occurred_at'])
    def test_explicit_source_basis_and_unknown_or_invalid_time_remain_stable(self):
        from memory_corpus import digest
        row,_=self.legacy_clock_fixture()
        for patch in [{'time_basis':'source_timestamp'}, {'occurred_at':None}, {'occurred_at':'invalid'}]:
            current=copy.deepcopy(row);current.update(patch);self.rows(current)
            item=self.candidates()[0];event=build_event(self.root,item)
            self.assertNotIn('legacy_time_receipt',event['payload'])
            self.assertEqual(event['event_id'],'ev-corpus-'+digest([item['item_id'],item['source_digest'],item['content_sha256']])[:32])
    def test_bound_object_time_v2_identity_not_changed_by_legacy_policy(self):
        from memory_corpus import digest,BOUND_OBJECT_TIME_POLICY
        self.object_fixture();row=json.loads(self.events.read_text());row['occurred_at']='2026-09-25T12:00:00Z'
        row['payload']['record_source']='codex_log_parse';self.rows(row)
        item=next(x for x in self.candidates() if x.get('event_type')=='bound_object');event=build_event(self.root,item)
        self.assertEqual(event['event_id'],'ev-corpus-'+digest([item['item_id'],item['source_digest'],item['content_sha256'],BOUND_OBJECT_TIME_POLICY])[:32])
        self.assertIn('artifact_receipt',event['payload']);self.assertNotIn('legacy_time_receipt',event['payload'])

if __name__=='__main__':unittest.main()
