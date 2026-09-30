import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

STAGE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(STAGE/'scripts'))
import raw_storage as raw
from role_registry import ROLE_IDS


class RawPreservationV3Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
    def tearDown(self):self.temp.cleanup()
    def file(self,name='source.txt',data=b'Ordinary original\r\nexact bytes.\x00'):
        p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);return p
    def events(self):return list(raw._read_rows(sorted((self.root/'raw/events').glob('*.jsonl'))))
    def snapshot(self,data=b'Ordinary original\r\nexact bytes.',**kwargs):
        return raw.snapshot_file(self.root,self.file(data=data),'task1',capture_key='c1',**kwargs)
    def test_ordinary_binary_and_text_are_exact_and_versioned(self):
        for name,data in [('plain.txt','汉字\r\n保全'.encode()),('image.bin',b'\x00\xff\x01\x88')]:
            p=self.file(name,data);one=raw.snapshot_file(self.root,p,'task1',capture_key=name)
            two=raw.snapshot_file(self.root,p,'task1',capture_key=name)
            self.assertEqual(one,two);self.assertEqual(raw.read_preserved_original(self.root,one['original']),data)
            self.assertEqual(one['original']['storage'],'raw_object')
            p.write_bytes(data+b'new');three=raw.snapshot_file(self.root,p,'task1',capture_key=name)
            self.assertEqual(three['version'],2);self.assertEqual(three['previous_snapshot_id'],one['snapshot_id'])
    def test_sensitive_text_original_encrypted_safe_copy_separate(self):
        original=b'Preference detail\napi_key=sk-private-synthetic-123456789\n'
        row=self.snapshot(original)
        self.assertNotIn(b'sk-private-synthetic', (self.root/'raw/objects'/row['sha256']).read_bytes())
        self.assertEqual(row['content_form'],'credential_redacted_copy')
        self.assertEqual(row['original']['storage'],'local_encrypted')
        ciphertext=(self.root/row['original']['path']).read_bytes();self.assertNotIn(original,ciphertext)
        with self.assertRaisesRegex(ValueError,'local_access'):raw.read_preserved_original(self.root,row['original'])
        self.assertEqual(raw.read_preserved_original(self.root,row['original'],allow_sensitive=True),original)
        key=self.root/'state/.auth-raw-originals/key'
        self.assertEqual(key.stat().st_mode&0o777,0o600);self.assertEqual(key.parent.stat().st_mode&0o777,0o700)
    def test_redaction_same_safe_bytes_but_changed_secret_is_new_version(self):
        p=self.file(data=b'password=first-value');one=raw.snapshot_file(self.root,p,'task1',capture_key='same')
        p.write_bytes(b'password=second-value');two=raw.snapshot_file(self.root,p,'task1',capture_key='same')
        self.assertEqual(one['sha256'],two['sha256']);self.assertNotEqual(one['snapshot_id'],two['snapshot_id']);self.assertEqual(two['version'],2)
    def test_opaque_sensitive_binary_is_local_only_not_discarded(self):
        data=b'\x00\xffapi_key=sk-sensitive-synthetic-123456789\x00'
        row=self.snapshot(data);self.assertEqual(row['content_form'],'local_only_safe_placeholder')
        self.assertEqual(raw.read_preserved_original(self.root,row['original'],allow_sensitive=True),data)
    def test_explicit_local_file_has_no_ordinary_body_copy(self):
        data=b'Private synthetic business narrative';row=self.snapshot(data,sensitivity='L4')
        self.assertNotIn(data,(self.root/'raw/objects'/row['sha256']).read_bytes())
        self.assertEqual(raw.read_preserved_original(self.root,row['original'],allow_sensitive=True),data)
    def test_sensitive_event_seals_before_redaction_exact_text(self):
        event={'event_id':'event1','event_type':'user_input','agent':'invest','payload':{'text':'line1\r\npassword=synthetic-value\n尾'}}
        raw.append_event(self.root,event);saved=self.events()[0]
        restored=json.loads(raw.read_preserved_original(self.root,saved['raw_preservation']['original'],allow_sensitive=True))
        self.assertEqual(restored,event);self.assertNotIn('synthetic-value',json.dumps(saved))
    def test_explicit_local_event_extra_body_not_leaked(self):
        event={'event_id':'event1','event_type':'user_input','agent':'invest','risk':'L4','payload':{'text':'private narrative'},'body':'secret extra narrative'}
        raw.append_event(self.root,event);saved=self.events()[0]
        self.assertNotIn('private narrative',json.dumps(saved));self.assertNotIn('secret extra',json.dumps(saved))
        self.assertFalse(saved['cloud_eligible']);self.assertFalse(saved['payload']['text_available'])
        self.assertEqual(json.loads(raw.read_preserved_original(self.root,saved['raw_preservation']['original'],allow_sensitive=True)),event)
    def test_all_roles_capture_while_structured_disabled(self):
        p=self.root/'config/memory-pipeline.json';p.parent.mkdir();p.write_text('{"enabled":false}')
        for role in ROLE_IDS:raw.append_event(self.root,{'event_id':'event-'+role,'event_type':'user_input','agent':role,'payload':{'text':'ordinary source'}})
        self.assertEqual({r['agent'] for r in self.events()},set(ROLE_IDS));self.assertFalse((self.root/'state/memory-pipeline').exists())
    def test_missing_or_wrong_key_never_returns_original_or_rekeys(self):
        row=self.snapshot(b'password=synthetic-secret');key=self.root/'state/.auth-raw-originals/key';key.unlink()
        with self.assertRaisesRegex(ValueError,'key_missing'):raw.read_preserved_original(self.root,row['original'],allow_sensitive=True)
        with self.assertRaisesRegex(ValueError,'key_missing'):self.snapshot(b'password=new-secret')
        self.assertFalse(key.exists());key.write_bytes(b'x'*32);key.chmod(0o600)
        with self.assertRaisesRegex(ValueError,'decryption_failed'):raw.read_preserved_original(self.root,row['original'],allow_sensitive=True)
    def test_wrong_ciphertext_and_unsafe_permissions_rejected(self):
        row=self.snapshot(b'password=synthetic-secret');p=self.root/row['original']['path'];p.write_bytes(p.read_bytes()[:-1]+b'!')
        with self.assertRaisesRegex(ValueError,'ciphertext_hash'):raw.read_preserved_original(self.root,row['original'],allow_sensitive=True)
        key=self.root/'state/.auth-raw-originals/key';key.chmod(0o644)
        with self.assertRaisesRegex(ValueError,'permissions'):self.snapshot(b'password=different-secret')
    def test_vault_and_key_files_excluded_with_gap(self):
        for name,data in [('vault.kdbx',b'ordinary'),('credentials.json',b'{}'),('renamed.bin',bytes.fromhex('03d9a29a67fb4bb5')+b'data')]:
            with self.assertRaises(raw.CredentialFileBlocked):raw.snapshot_file(self.root,self.file(name,data),'task1',capture_key=name)
        self.assertFalse((self.root/'raw/private-originals').exists());self.assertEqual(len(self.events()),3)
        self.assertTrue(all('dedicated_credential_store_not_captured' in e['missing_reason'] for e in self.events()))
    def test_source_and_destination_links_rejected(self):
        p=self.file();link=self.root/'linked.txt';link.symlink_to(p)
        with self.assertRaises(ValueError):raw.snapshot_file(self.root,link,'task1')
        with self.assertRaises(ValueError):raw.snapshot_file(self.root,link,'task1',captured_bytes=b'captured')
        hard=self.root/'hard.txt';os.link(p,hard)
        with self.assertRaises(ValueError):raw.snapshot_file(self.root,p,'task1')
        rawdir=self.root/'raw';rawdir.mkdir();(rawdir/'objects').symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(ValueError):raw.snapshot_file(self.root,self.file('fresh.txt',b'new'),'task1')
    def test_snapshot_receipt_keeps_attachment_reference_without_private_body(self):
        row=self.snapshot(b'password=synthetic-secret');events=self.events()
        self.assertEqual(events[-1]['payload']['snapshot_id'],row['snapshot_id'])
        self.assertNotIn('synthetic-secret',json.dumps(events))
    def test_derived_receipt_does_not_claim_original_document(self):
        row=self.snapshot(b'OCR text',derived_from={'snapshot_id':'snapshot-a','sha256':'a'*64,'method':'ocr','page':3},source_locator={'page':3,'byte_start':0,'byte_end':8})
        self.assertEqual(row['content_form'],'derived_bytes');self.assertEqual(row['fidelity'],'derived');self.assertEqual(row['source_locator']['page'],3)
    def test_backup_fixture_restores_raw_ledger_ciphertext_not_key(self):
        row=self.snapshot(b'password=synthetic-secret')
        ledger=self.root/'memory/structured/invest/facts.jsonl';ledger.parent.mkdir(parents=True);ledger.write_text('{"fact_id":"synthetic"}\n')
        spec=importlib.util.spec_from_file_location('backup_v3_fixture',STAGE/'scripts/javis-backup.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as dest, tempfile.TemporaryDirectory() as restored:
            result=module.create_backup(self.root,Path(dest),restore_check=True);self.assertEqual(result['status'],'success')
            module.verify(Path(result['archive']),Path(restored));restored=Path(restored)
            self.assertEqual((restored/ledger.relative_to(self.root)).read_bytes(),ledger.read_bytes())
            self.assertTrue((restored/row['original']['path']).exists());self.assertFalse((restored/'state/.auth-raw-originals/key').exists())
            with self.assertRaisesRegex(ValueError,'key_missing'):raw.read_preserved_original(restored,row['original'],allow_sensitive=True)


if __name__=='__main__':unittest.main()
