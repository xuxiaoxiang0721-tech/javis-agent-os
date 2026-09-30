import contextlib,hashlib,importlib.util,json,pathlib,sys,tempfile,unittest
here=pathlib.Path(__file__).resolve().parent
backup_path=here/'javis-backup.py'
if not backup_path.exists():backup_path=here.parent/'scripts/javis-backup.py'
sys.path.insert(0,str(backup_path.parent));sys.path.insert(0,str(backup_path.parent/'orchestration'))
from restore_prepare import restore_prepare
from fixed_work import JOB_ID
spec=importlib.util.spec_from_file_location('patched_backup',backup_path);backup=importlib.util.module_from_spec(spec);spec.loader.exec_module(backup)

class BackupRestoreTest(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.base=pathlib.Path(self.temp.name);self.root=self.base/'source';self.root.mkdir()
  self.put('tools/control-panel/web/index.html','<title>fixture</title>');self.put('tools/control-panel/requirements.txt','fixture==1\n');self.put('tools/control-panel/.venv/secret.txt','must-exclude')
  self.put('tools/flowise/package.json','{"private":true}');self.put('tools/flowise/package-lock.json','{"lockfileVersion":3}');self.put('tools/flowise/package-review/tmp.log','must-exclude');self.put('tools/flowise/node_modules/unused/a.js','must-exclude')
  self.put('state/owner-auth/public-signatures.json','{"public":true}');self.put('state/owner-auth/private.key','must-exclude')
  self.put('state/locks/memory-review.lock','');self.put('state/fixed-work/'+JOB_ID+'.json',json.dumps({'job_id':JOB_ID,'enabled':True,'version':7}))
  self.put('state/fixed-work/runs/fw-'+('1'*24)+'.json',json.dumps({'run_id':'fw-'+('1'*24),'state':'running'}))
  self.put('state/fixed-work/runs/fw-'+('2'*24)+'.json',json.dumps({'run_id':'fw-'+('2'*24),'state':'completed','task_id':'preserved'}))
  self.put('raw/events/fixture.jsonl','{"original":"unaltered fixture"}\n');self.put('memory/roles/invest/facts.jsonl','')
  self.put('config/systemd-user/javis-invest-fixed-review.timer','[Timer]\nOnCalendar=daily\n')
  self.new_covered=['tests/'+name for name in ('test_control_http.py','test_owner_auth.py','test_review_projection.py','test_owner_memory_review.py','test_control_ui_fixes.js','test_control_ui_fixes.py')]+['tools/control-panel/requirements.lock']
  for name in self.new_covered:self.put(name,'non-sensitive fixture for '+name+'\n')
  self.excluded_locks=['state/arbitrary.lock','state/.lock','tools/control-panel/arbitrary.lock','tools/control-panel/nested/requirements.lock','tests/requirements.lock']
  for name in self.excluded_locks:self.put(name,'runtime-lock-must-stay-excluded')
  self.put('tools/control-panel/.env','must-exclude');self.put('tools/control-panel/requirements.lock.key','must-exclude')
 def tearDown(self):self.temp.cleanup()
 def put(self,name,text):
  p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text);return p
 def test_includes_minimal_code_public_material_and_excludes_runtime(self):
  names={n for _,n in backup.files(self.root)}
  self.assertIn('tools/control-panel/web/index.html',names);self.assertIn('tools/control-panel/requirements.txt',names)
  self.assertIn('tools/flowise/package.json',names);self.assertIn('tools/flowise/package-lock.json',names)
  self.assertIn('state/owner-auth/public-signatures.json',names);self.assertIn('config/systemd-user/javis-invest-fixed-review.timer',names)
  self.assertFalse(any('.venv/' in n or 'node_modules/' in n or 'package-review/' in n or n.endswith('.key') for n in names))
 def test_seven_source_files_and_exact_dependency_lock_exception(self):
  names={n for _,n in backup.files(self.root)}
  for name in self.new_covered:self.assertIn(name,names)
  for name in self.excluded_locks:self.assertNotIn(name,names)
  self.assertNotIn('tools/control-panel/.env',names);self.assertNotIn('tools/control-panel/requirements.lock.key',names)
 def test_consistent_archive_restore_pauses_without_mutating_raw_or_archive(self):
  acquired=[];original=backup.lock
  @contextlib.contextmanager
  def traced(path,*a,**kw):
   acquired.append(str(path.relative_to(self.root)) if path.is_relative_to(self.root) else str(path))
   with original(path,*a,**kw):yield
  backup.lock=traced
  try:record=backup.create_backup(self.root,self.base/'archives',restore_check=True)
  finally:backup.lock=original
  self.assertEqual(record['status'],'success',record)
  order=['state/maintenance.lock','state/locks/memory-review.lock','state/owner-auth/.lock','state/fixed-work/.lock','memory/roles/invest/.ledger.lock']
  self.assertEqual(sorted(order,key=acquired.index),order)
  archive=pathlib.Path(record['archive']);original_hash=hashlib.sha256(archive.read_bytes()).hexdigest()
  restored=self.base/'restored';manifest=backup.verify(archive,restored)
  archived={row['path'] for row in manifest['files']}
  for name in self.new_covered:
   self.assertIn(name,archived);self.assertEqual((restored/name).read_bytes(),(self.root/name).read_bytes())
  for name in self.excluded_locks:
   self.assertNotIn(name,archived);self.assertFalse((restored/name).exists())
  raw=restored/'raw/events/fixture.jsonl';raw_before=raw.read_bytes()
  done=restored/('state/fixed-work/runs/fw-'+('2'*24)+'.json');done_before=done.read_bytes()
  report=restore_prepare(restored,source_archive_sha256=original_hash)
  self.assertTrue(json.loads((restored/'state/recovery-hold.json').read_text())['hold'])
  job=json.loads((restored/('state/fixed-work/'+JOB_ID+'.json')).read_text());self.assertFalse(job['enabled']);self.assertEqual(job['version'],8)
  running=json.loads((restored/('state/fixed-work/runs/fw-'+('1'*24)+'.json')).read_text());self.assertEqual(running['state'],'needs_review')
  self.assertEqual(raw.read_bytes(),raw_before);self.assertEqual(done.read_bytes(),done_before)
  self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(),original_hash);self.assertFalse(report['services_installed_or_started'])
  self.assertEqual(len(report['changes']),3)
  again=restore_prepare(restored,source_archive_sha256=original_hash);self.assertEqual(again['changes'],[])
 def test_refuses_live_root(self):
  with self.assertRaises(ValueError):restore_prepare('/home/user/javis')

if __name__=='__main__':unittest.main(verbosity=2)
