import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import memory_sources as sources
import raw_storage as raw


class SourceContextV3Tests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def source(self,eid='source1',scope='invest',text='Long-term synthetic preference.',**extra):
        event={'event_id':eid,'event_type':'user_input','agent':scope,'task_id':'task1',
               'payload':{'text':text,'is_original_user_input':True},**extra}
        raw.append_event(self.root,event);return eid
    def file(self,name='input.txt',data=b'Original attachment'):
        p=self.root/name;p.write_bytes(data);return p
    def attachment(self,name='input.txt',data=b'Original attachment',**extra):
        return raw.snapshot_file(self.root,self.file(name,data),'task1',relation='input',capture_key=name,
            source_locator={'event_id':'source1','page':1},**extra)
    def test_exact_text_time_unknown_and_no_authorship_upgrade(self):
        self.source(text='第一行\r\nsecond\u2028line')
        view=sources.source_context(self.root,'source1','invest')
        self.assertEqual(view['texts'][0]['text'],'第一行\r\nsecond\u2028line')
        self.assertEqual(view['texts'][0]['utf8_bytes'],len('第一行\r\nsecond\u2028line'.encode()))
        self.assertIsNone(view['times']['occurred_at']);self.assertFalse(view['confirmation_authority'])
        self.source('other',text='Assistant suggestion',event_type='model_output',payload={'text':'Assistant suggestion'})
        self.assertFalse(sources.source_context(self.root,'other','invest')['texts'][0]['authorship_verified'])
    def test_scope_conflict_and_cross_scope_denied(self):
        self.source()
        with self.assertRaisesRegex(ValueError,'scope'):sources.source_context(self.root,'source1','cards-master')
        self.source('conflict',scope='invest',role_id='cards-master')
        with self.assertRaisesRegex(ValueError,'scope'):sources.source_context(self.root,'conflict','invest')
    def test_safe_view_redacts_legacy_credentials_without_writing(self):
        p=self.root/'raw/events/legacy.jsonl';p.parent.mkdir(parents=True)
        p.write_text(json.dumps({'event_id':'legacy','event_type':'user_input','agent':'invest','payload':{'text':'api_key=sk-synthetic-example-123456789'}})+'\n')
        before=p.read_bytes();view=sources.source_context(self.root,'legacy','invest')
        self.assertNotIn('sk-synthetic-example',json.dumps(view));self.assertEqual(p.read_bytes(),before)
    def test_local_event_view_metadata_only_and_original_local_gate(self):
        self.source(text='Private source',risk='L4')
        view=sources.source_context(self.root,'source1','invest');self.assertEqual(view['texts'],[])
        with self.assertRaisesRegex(ValueError,'local_access'):sources.resolve_original(self.root,'source1','invest')
        result=sources.resolve_original(self.root,'source1','invest',allow_sensitive=True)
        self.assertEqual(json.loads(result['bytes'])['payload']['text'],'Private source')
    def test_attachment_binding_and_exact_original_bytes(self):
        snap=self.attachment(data=b'\x00\xffbinary original');self.source()
        view=sources.source_context(self.root,'source1','invest');self.assertEqual(len(view['attachments']),1)
        result=sources.resolve_original(self.root,'source1','invest',snap['snapshot_id'])
        self.assertEqual(result['bytes'],b'\x00\xffbinary original');self.assertTrue(result['local_only'])
    def test_ordinary_attachment_not_poisoned_by_original_cloud_metadata(self):
        snap=self.attachment();self.source()
        event=next(r for r in raw._read_rows((self.root/'raw/events').glob('*.jsonl')) if r.get('event_type')=='file_snapshot')
        from memory_corpus import policy_flags
        self.assertEqual(policy_flags(event),[])
    def test_unbound_other_task_snapshot_cannot_be_downloaded(self):
        snap=raw.snapshot_file(self.root,self.file(),'task-other',relation='input',capture_key='c')
        self.source()
        with self.assertRaisesRegex(ValueError,'not_bound'):sources.resolve_original(self.root,'source1','invest',snap['snapshot_id'])
    def test_explicit_cross_task_ref_rejected(self):
        snap=raw.snapshot_file(self.root,self.file(),'task-other',relation='input',capture_key='c')
        self.source(evidence_refs=[{'snapshot_id':snap['snapshot_id']}])
        with self.assertRaises(ValueError):sources.source_context(self.root,'source1','invest')
    def test_sensitive_attachment_default_download_never_returns_safe_as_original(self):
        snap=self.attachment(data=b'password=synthetic-sensitive');self.source()
        view=sources.source_context(self.root,'source1','invest');self.assertEqual(view['attachments'][0]['original']['storage'],'local_encrypted')
        with self.assertRaisesRegex(ValueError,'local_access'):sources.resolve_original(self.root,'source1','invest',snap['snapshot_id'])
        original=sources.resolve_original(self.root,'source1','invest',snap['snapshot_id'],allow_sensitive=True)
        self.assertEqual(original['bytes'],b'password=synthetic-sensitive')
    def test_source_local_policy_cannot_be_bypassed_through_ordinary_attachment(self):
        snap=self.attachment();self.source(cloud_eligible=False)
        with self.assertRaisesRegex(ValueError,'local_access'):sources.resolve_original(self.root,'source1','invest',snap['snapshot_id'])
    def test_attachment_hash_tamper_and_links_rejected(self):
        snap=self.attachment();self.source();obj=self.root/'raw/objects'/snap['sha256'];obj.write_bytes(b'tampered')
        with self.assertRaises(ValueError):sources.source_context(self.root,'source1','invest')
        obj.unlink();obj.symlink_to(self.file('alternate.txt',b'Original attachment'))
        with self.assertRaises(ValueError):sources.resolve_original(self.root,'source1','invest',snap['snapshot_id'])
    def test_pdf_or_image_never_claims_ocr_done(self):
        self.attachment('scan.pdf',b'%PDF synthetic');self.source()
        self.assertIn('ocr_or_document_text_derivative_not_recorded',sources.source_context(self.root,'source1','invest')['gaps'])
    def test_old_safe_copy_is_not_claimed_original(self):
        snap=self.attachment();self.source();manifest=next((self.root/'raw/manifests').glob('objects-*.jsonl'))
        row=json.loads(manifest.read_text());row.pop('original');row['content_form']='credential_redacted_copy';manifest.write_text(json.dumps(row)+'\n')
        with self.assertRaisesRegex(ValueError,'receipt_mismatch|unproven'):sources.resolve_original(self.root,'source1','invest',snap['snapshot_id'])
    def test_segments_bind_unicode_offsets_and_cover_full_text(self):
        text='甲🙂abc\r\n'*17;parts=sources.segment_text(text,max_chars=19,overlap=3)
        covered=set()
        for p in parts:
            self.assertEqual(p['text'],text[p['char_start']:p['char_end']]);self.assertEqual(p['text'].encode(),text.encode()[p['byte_start']:p['byte_end']])
            self.assertEqual(p['source_sha256'],hashlib.sha256(text.encode()).hexdigest());covered.update(range(p['char_start'],p['char_end']))
        self.assertEqual(covered,set(range(len(text))))
        with self.assertRaises(ValueError):sources.segment_text(text,10,10)
    def test_coverage_missing_ids_not_duplicates_and_no_model_queue(self):
        self.source();p=self.root/'raw/events/legacy.jsonl';p.write_text('{"legacy":1}\n{"legacy":2}\n')
        imp=self.root/'memory/imports/new/plain.txt';imp.parent.mkdir(parents=True);imp.write_text('Imported body')
        before={x.relative_to(self.root):x.read_bytes() for x in self.root.rglob('*') if x.is_file()}
        result=sources.coverage_reconcile(self.root,{'files':[]})
        self.assertEqual(result['raw']['missing_event_id'],2);self.assertEqual(result['raw']['duplicate_nonempty_event_ids'],0)
        self.assertEqual(result['imports']['by_inventory_state'],{'not_previously_inventoried':1});self.assertEqual(result['model_calls'],0)
        self.assertEqual(before,{x.relative_to(self.root):x.read_bytes() for x in self.root.rglob('*') if x.is_file()})
    def test_coverage_scope_counts_remain_when_processing_paused(self):
        self.source();self.source('cards','cards-master');p=self.root/'config/memory-pipeline.json';p.parent.mkdir();p.write_text('{"enabled":false}')
        result=sources.coverage_reconcile(self.root)
        self.assertEqual(result['raw']['by_role'],{'invest':1,'cards-master':1});self.assertEqual(result['processing']['queue'],{})
    def test_corpus_view_revalidates_original_and_retains_original_locator(self):
        import memory_corpus as corpus
        self.source();inventory=corpus.inventory(self.root)
        item=next(i for i in inventory['items'] if i.get('event_id')=='source1' and i.get('route')=='candidate')
        event=corpus.build_event(self.root,item);raw.append_event(self.root,event,relative_path='events/corpus/derived.jsonl')
        view=sources.source_context(self.root,event['event_id'],'invest')
        self.assertEqual(view['texts'][0]['text'],'Long-term synthetic preference.')
        self.assertEqual(view['source_locator']['path'],item['source']['path'])
        path=self.root/item['source']['path'];path.write_text(path.read_text().replace('Long-term synthetic preference.','Changed original text.'))
        with self.assertRaisesRegex(ValueError,'corpus_original_source_changed'):sources.source_context(self.root,event['event_id'],'invest')
    def test_derivative_download_explicitly_is_not_original_source_document(self):
        snap=self.attachment(data=b'OCR-derived text',derived_from={'snapshot_id':'scan1','sha256':'1'*64,'method':'ocr','page':1});self.source()
        result=sources.resolve_original(self.root,'source1','invest',snap['snapshot_id'])
        self.assertEqual(result['fidelity'],'exact_captured_derived_bytes_not_source_document')
    def test_coverage_held_and_configuration_wait_are_not_corrupt(self):
        folder=self.root/'state/memory-pipeline/queue';folder.mkdir(parents=True)
        for status in ('held','waiting_for_configuration'):(folder/(status+'.json')).write_text(json.dumps({'status':status}))
        self.assertEqual(sources.coverage_reconcile(self.root)['processing']['queue'],{'held':1,'waiting_for_configuration':1})


if __name__=='__main__':unittest.main()
