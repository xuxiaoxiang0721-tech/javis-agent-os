"""Async drop acceptance and legacy receipt compatibility; fake native workers only."""
import importlib.util
import json
import os
from pathlib import Path
import time
import unittest
from unittest.mock import patch
import test_control_p1 as support
from task_control import Principal

spec=importlib.util.spec_from_file_location('drop_common_fixture',support.CODE/'scripts/drop-bridge.py')
drop=importlib.util.module_from_spec(spec);spec.loader.exec_module(drop)

class CommonDrop(unittest.TestCase):
    def setUp(self):
        support.ControlP1.setUp(self)
        self.base=Path(self.tmp.name)/'drop';self.base.mkdir()
        self.bridge=drop.Bridge(self.r,self.base);self.bridge.prepare()
        self.admin=Principal('synthetic-admin','owner',frozenset(drop.ROLES),frozenset({'task:read:any','task:control:any'}),'synthetic-proof')
    tearDown=support.ControlP1.tearDown
    launch=support.ControlP1.launch
    count=support.ControlP1.count
    def package(self,delivery,role='cards-master',sid='submission-1',data=b'original synthetic',mid=None):
        package=self.base/drop.ROLES[role]/'inbox'/(delivery+'.ready');package.mkdir()
        request={'schema_version':1,'submission_id':sid}
        if mid is not None:request['message_id']=mid
        (package/'request.json').write_text(json.dumps(request));(package/'message.txt').write_bytes(data)
        return package
    def accepted(self,delivery,role='cards-master'):
        return json.loads((self.base/drop.ROLES[role]/'processing'/(delivery+'.ready')/'accepted.json').read_text())
    def receipt(self,delivery,role='cards-master'):
        files=[self.base/drop.ROLES[role]/name/delivery/'receipt.json' for name in ('done','fail')]
        return json.loads(next(p for p in files if p.exists()).read_text())
    def command(self,tid,action,cid,**kw):
        st=self.svc.status(self.admin,tid)
        return self.svc.command(self.admin,tid,{'command_id':cid,'action':action,'expected_goal_revision':st['goal_revision'],'expected_attempt':st['attempt'],**kw})
    def test_new_package_accepts_without_model_and_duplicate_final_is_cached(self):
        self.package('first');self.bridge.once();accepted=self.accepted('first');tid=accepted['task_id']
        self.assertEqual(accepted['status'],'received');self.assertEqual(self.count(),0);self.assertTrue(tid.startswith('t-p1-'))
        self.launch(tid);self.bridge.once();first=self.receipt('first')
        self.assertEqual(first['status'],'succeeded');self.assertFalse(first['replayed']);self.assertEqual(self.count(),1)
        self.package('duplicate');self.bridge.once();again=self.receipt('duplicate')
        self.assertTrue(again['replayed']);self.assertEqual(again['result_sha256'],first['result_sha256']);self.assertEqual(self.count(),1)
    def test_busy_task_does_not_block_next_acceptance_and_pause_waits_for_resume(self):
        self.package('long',data=b'SLOW_P1');self.bridge.once();tid=self.accepted('long')['task_id'];process=self.launch(tid,False)
        for _ in range(200):
            if self.svc.status(self.admin,tid).get('session_id'):break
            time.sleep(.02)
        self.package('other',role='invest',sid='second');started=time.monotonic();self.bridge.once()
        self.assertLess(time.monotonic()-started,5);self.assertEqual(self.accepted('other','invest')['status'],'received')
        self.command(tid,'append','a1',original_text='follow appended constraint');self.command(tid,'pause','p1');process.communicate(timeout=15)
        self.bridge.once();self.assertTrue((self.base/'cards-drop/processing/long.ready').exists())
        self.assertFalse((self.base/'cards-drop/fail/long').exists())
        self.command(tid,'resume','r1');self.launch(tid);self.bridge.once()
        receipt=self.receipt('long');self.assertEqual(receipt['status'],'succeeded');self.assertEqual(receipt['attempt'],2)
    def test_same_identity_changed_bytes_rejected_and_transport_is_preserved(self):
        raw=b'\xef\xbb\xbf'+b'original\r\nsecond\rthird\r\n';self.package('bom',data=raw,mid='real-platform-id');self.bridge.once()
        accepted=self.accepted('bom');self.assertEqual(accepted['input_sha256'],drop.digest(raw))
        journals=list((self.bridge.state/'cards-master').glob('*.json'));record=json.loads(journals[0].read_text())
        self.assertEqual((self.r/'workspace/inbox/messages/drop/cards-master'/(journals[0].stem+'.txt')).read_bytes(),raw)
        self.assertEqual(record['input_snapshot']['sha256'],drop.digest(raw))
        control=__import__('task_service').load_control(self.r,accepted['task_id'])
        self.assertEqual(control['goals'][0]['text'],raw.decode('utf-8-sig'))
        rows=[json.loads(line) for p in (self.r/'raw/events').glob('*.jsonl') for line in p.read_text().splitlines()]
        original=next(row for row in rows if row['event_id']==control['goals'][0]['event_id'])
        self.assertEqual(original['payload']['text'],raw.decode('utf-8-sig'))
        self.package('changed',data=b'original\nsecond\n',mid='real-platform-id');self.bridge.once()
        self.assertEqual(self.receipt('changed')['status'],'rejected');self.assertEqual(self.count(),0)
    def test_cancel_before_worker_has_terminal_failure_receipt(self):
        self.package('cancel');self.bridge.once();tid=self.accepted('cancel')['task_id'];self.command(tid,'cancel','c1');self.bridge.once()
        receipt=self.receipt('cancel');self.assertEqual(receipt['failure_stage'],'cancelled');self.assertEqual(receipt['attempt'],0);self.assertEqual(self.count(),0)
    def test_crash_after_submit_commit_dedupes_without_new_task(self):
        self.package('crash');original=drop.write_json
        def fail_after_commit(path,value):
            if path.parent==self.bridge.state/'cards-master' and isinstance(value,dict) and value.get('phase')=='accepted':raise OSError('synthetic journal interruption')
            return original(path,value)
        with patch.object(drop,'write_json',fail_after_commit):self.bridge.once()
        self.assertEqual(len(list((self.r/'state/tasks').glob('*.json'))),1)
        self.bridge.once();self.assertEqual(self.accepted('crash')['status'],'received');self.assertEqual(self.count(),0)
        self.assertEqual(len(list((self.r/'state/tasks').glob('*.json'))),1)
    def test_old_terminal_journal_uses_original_cache_without_control_task(self):
        def legacy(role,spool,tid,mid):
            task=self.r/'workspace/tasks'/tid;(task/'attempts/1').mkdir(parents=True)
            packet={'task_id':tid,'role_id':role,'from_agent_id':drop.ORIGINS[role],'source_event_id':mid,'original_user_input':spool.read_text()}
            (task/'packet.json').write_text(json.dumps(packet))
            (task/'attempts/1/result.json').write_text(json.dumps({'task_id':tid,'role_id':role,'attempt':1,'status':'ok','exit_code':0,'user_reply_zh':'old synthetic receipt'}))
            return 0
        old=drop.Bridge(self.r,self.base,runner=legacy);self.package('old');old.once();first=self.receipt('old')
        self.assertTrue(first['task_id'].startswith('t-drop-'))
        self.package('old-repeat');self.bridge.once();again=self.receipt('old-repeat')
        self.assertEqual(again['result_sha256'],first['result_sha256']);self.assertEqual(self.count(),0)
        self.assertFalse((self.r/'state/control').exists())
    def test_accepted_file_in_untrusted_input_does_not_authorize_task(self):
        package=self.package('forged');(package/'accepted.json').write_text('{"task_id":"invented"}')
        self.bridge.once();self.assertEqual(self.receipt('forged')['status'],'rejected');self.assertEqual(self.count(),0)

if __name__=='__main__':unittest.main()
