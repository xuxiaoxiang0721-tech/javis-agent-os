import concurrent.futures,hashlib,json,pathlib,tempfile,types,unittest
from fixed_work import FixedWorkManager,JOB_ID,validate_submission,fixed_text

class TestFixedWork(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name);self.calls=[];self.launches=[];self.active=False
        def systemd(*args):
            self.calls.append(args)
            if args[0]=='is-active':return {'returncode':0 if self.active else 3,'stdout':'active' if self.active else 'inactive','stderr':''}
            self.active=args[0]=='enable';return {'returncode':0,'stdout':'','stderr':''}
        def launch(run_id):self.launches.append(run_id);return types.SimpleNamespace(pid=900001)
        self.m=FixedWorkManager(self.root,systemd=systemd,launcher=launch)
    def tearDown(self):self.tmp.cleanup()
    def test_default_disabled(self):
        status=self.m.status();self.assertFalse(status['job']['enabled']);self.assertEqual(status['job']['version'],1);self.assertEqual(status['runs'],[])
    def test_cas_stale(self):
        self.m.set_enabled(JOB_ID,True,1,'enable1')
        with self.assertRaisesRegex(ValueError,'version_conflict'):self.m.set_enabled(JOB_ID,False,1,'disable1')
        self.assertTrue(self.m.status()['job']['enabled'])
    def test_enable_replay_no_second_action(self):
        a=self.m.set_enabled(JOB_ID,True,1,'enable1');b=self.m.set_enabled(JOB_ID,True,1,'enable1')
        self.assertEqual(a['job'],b['job']);self.assertTrue(b['replayed']);self.assertEqual(len(self.calls),1)
    def test_command_id_rebinding_rejected(self):
        self.m.set_enabled(JOB_ID,True,1,'same')
        with self.assertRaisesRegex(ValueError,'command_id_conflict'):self.m.set_enabled(JOB_ID,False,2,'same')
    def test_disable_increments_version(self):
        self.m.set_enabled(JOB_ID,True,1,'enable');response=self.m.set_enabled(JOB_ID,False,2,'disable')
        self.assertFalse(response['job']['enabled']);self.assertEqual(response['job']['version'],3)
    def test_run_replay_no_second_process(self):
        a=self.m.run_once(JOB_ID,'run1');b=self.m.run_once(JOB_ID,'run1')
        self.assertEqual(a['run_id'],b['run_id']);self.assertEqual(len(self.launches),1);self.assertTrue(b['replayed'])
    def test_busy_refuses_new_command(self):
        self.m.run_once(JOB_ID,'run1')
        with self.assertRaisesRegex(ValueError,'busy'):self.m.run_once(JOB_ID,'run2')
        self.assertEqual(len(self.launches),1)
    def test_parallel_same_command(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(lambda _:self.m.run_once(JOB_ID,'parallel'),range(4)))
        self.assertEqual(len(self.launches),1);self.assertEqual(len({x['run_id'] for x in results}),1)
    def test_disabled_schedule_rejected(self):
        with self.assertRaisesRegex(ValueError,'schedule_disabled'):self.m.scheduled('2026-09-20T09:00:00+08:00')
        self.assertEqual(self.launches,[])
    def test_run_once_cas_and_cached_replay(self):
        self.m.set_enabled(JOB_ID,True,1,'enable')
        with self.assertRaisesRegex(ValueError,'version_conflict'):self.m.run_once(JOB_ID,'run1',expected_version=1)
        first=self.m.run_once(JOB_ID,'run1',expected_version=2)
        repeated=self.m.run_once(JOB_ID,'run1',expected_version=1)
        self.assertTrue(repeated['replayed']);self.assertEqual(first['run_id'],repeated['run_id'])
    def test_restore_hold_fails_closed(self):
        hold=self.root/'state/recovery-hold.json'
        for content in ('{"hold":true}','{}','malformed'):
            hold.write_text(content)
            with self.assertRaisesRegex(ValueError,'recovery_hold'):self.m.run_once(JOB_ID,'held')
            with self.assertRaisesRegex(ValueError,'recovery_hold'):self.m.set_enabled(JOB_ID,True,1,'heldenable')
        hold.write_text('{"hold":false}')
        self.assertTrue(self.m.run_once(JOB_ID,'released')['ok'])
    def test_scheduled_manual_replay_preserves_provenance(self):
        self.m.set_enabled(JOB_ID,True,1,'enable');a=self.m.scheduled('2026-09-20T09:00:00+08:00')
        b=self.m.run_once(JOB_ID,a['run']['command_id'])
        self.assertTrue(b['replayed']);self.assertEqual(a['run']['scheduled_at'],b['run']['scheduled_at']);self.assertEqual(len(self.launches),1)
    def test_failed_systemd_preserves_version(self):
        self.m.systemd=lambda *args:{'returncode':1,'stdout':'','stderr':'simulated'}
        a=self.m.set_enabled(JOB_ID,True,1,'failure');b=self.m.set_enabled(JOB_ID,True,1,'failure')
        self.assertFalse(a['ok']);self.assertTrue(b['replayed']);self.assertEqual(a['job']['version'],1)
    def test_launch_failure_not_auto_replayed(self):
        def fail(run):raise OSError('simulated')
        self.m.launcher=fail;a=self.m.run_once(JOB_ID,'failrun');b=self.m.run_once(JOB_ID,'failrun')
        self.assertFalse(a['ok']);self.assertFalse(b['ok']);self.assertEqual(b['run']['state'],'launch_failed')
    def test_validate_fixed_fixture(self):
        body={'command_id':'sample','role_id':'invest','original_text':fixed_text(),'source_line':3,'permission':'R1','workflow_id':JOB_ID}
        request=validate_submission(self.root,body);self.assertEqual(request['entry'],'flowise:'+JOB_ID);self.assertNotIn('workflow_id',request)
        for field,value in [('original_text',fixed_text()+'x'),('source_line','3'),('role_id','cards-master'),('permission','R3'),('workflow_id','other'),('actor','admin'),('source_event_id','fabricated')]:
            with self.subTest(field=field),self.assertRaises(ValueError):validate_submission(self.root,{**body,field:value})

if __name__=='__main__':unittest.main(verbosity=2)
