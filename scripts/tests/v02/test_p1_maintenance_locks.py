"""Backup maintenance exclusivity covers drop writes and dispatch reconciliation."""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
CODE=Path(os.environ['JAVIS_TEST_CODE_ROOT']);sys.path.insert(0,str(CODE/'scripts'))
spec=importlib.util.spec_from_file_location('drop_lock_fixture',CODE/'scripts/drop-bridge.py')
drop=importlib.util.module_from_spec(spec);spec.loader.exec_module(drop)
import task_dispatch
from task_control import Principal,ControlService
from task_service import load_control,save_control

class MaintenanceLocks(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='javis-maintenance-lock-');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'root';self.base=Path(self.tmp.name)/'drop';self.base.mkdir()
    def assert_shared_held(self):
        with (self.root/'state/maintenance.lock').open('a') as handle:
            with self.assertRaises(BlockingIOError):fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
    def watcher_case(self,error):
        stages=[];prepare=drop.Bridge.prepare;write=drop.write_json
        def checked_prepare(bridge):
            self.assert_shared_held();stages.append('prepare');return prepare(bridge)
        def checked_once(bridge):
            self.assert_shared_held();stages.append('intake')
            if error:raise OSError('synthetic isolated queue error')
            return 0
        def checked_write(path,value):
            if path.name=='health.json':self.assert_shared_held();stages.append('health')
            return write(path,value)
        with patch.object(sys,'argv',['drop-bridge.py','--root',str(self.root),'--base',str(self.base)]),patch.object(drop.Bridge,'prepare',checked_prepare),patch.object(drop.Bridge,'once',checked_once),patch.object(drop,'write_json',checked_write):
            if error:
                with self.assertRaises(OSError):drop.main()
            else:self.assertEqual(drop.main(),0)
        self.assertEqual(stages,['prepare','intake','health'])
        self.assertEqual(json.loads((self.root/'state/drop-bridge/health.json').read_text())['status'],'error' if error else 'ready')
    def test_success_health_and_entire_intake_hold_shared_maintenance(self):self.watcher_case(False)
    def test_error_health_also_holds_shared_maintenance(self):self.watcher_case(True)
    def test_dispatch_reconcile_projection_is_inside_maintenance_lock(self):
        principal=Principal('synthetic-owner','owner',frozenset({'cards-master'}),frozenset({'task:create','task:read','task:control'}))
        tid=ControlService(self.root).submit(principal,{'command_id':'create','role_id':'cards-master','original_text':'synthetic only'})['task_id']
        c=load_control(self.root,tid);c['dispatch'].update(status='claimed',dispatcher_pid=99999999,dispatcher_identity='synthetic-dead');save_control(self.root,c,'synthetic_claim')
        checks=[];original=task_dispatch.save_control
        def checked(root,control,phase,command_id=None):
            self.assert_shared_held();checks.append(phase);return original(root,control,phase,command_id)
        with patch.object(task_dispatch,'save_control',checked):task_dispatch.reconcile(self.root,tid)
        self.assertEqual(checks,['dispatch_interrupted']);self.assertEqual(load_control(self.root,tid)['dispatch']['status'],'needs_review')

if __name__=='__main__':unittest.main()
