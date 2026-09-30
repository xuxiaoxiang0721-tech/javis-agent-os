"""Real local sandbox, synthetic files/fake native worker; no model calls."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

CODE=Path(os.environ.get('JAVIS_TEST_CODE_ROOT',Path(__file__).resolve().parents[3]))
sys.path.insert(0,str(CODE/'scripts'))
import native_permissions as policy
from task_runtime import run
from raw_policy import safe_file_bytes, CredentialFileBlocked
from raw_storage import snapshot_file

CLI='/home/user/.local/node/bin/codex'


class PrivatePermissions(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='javis-private-permissions-')
        self.base=Path(self.temp.name);self.root=self.base/'root'
        self.task=self.root/'workspace/tasks/synthetic';self.role=self.root/'workspace/roles/cards-master'
        self.task.mkdir(parents=True);self.role.mkdir(parents=True);(self.task/'out').mkdir()
        self.proposal=self.task/'out/.memory-proposals-attempt-1.json'
        self.canonical=self.task/'attempts/1/memory-proposals.json';self.canonical.parent.mkdir(parents=True)
        self.auth=self.base/'authhome';self.auth.mkdir()
        self.config=self.auth/'config.toml'
        self.config.write_text('model = "gpt-5.4"\nmodel_reasoning_effort = "high"\nsandbox_mode = "danger-full-access"\n')
        self.scope=patch.dict(os.environ,{'CODEX_HOME':str(self.auth),'JAVIS_ROOT':str(self.root),
                                        'JAVIS_CODEX_BIN':CLI},clear=False);self.scope.start()
        self.addCleanup(self.scope.stop)

    def tearDown(self):self.temp.cleanup()

    def launch(self,permission='R1',session=None):
        return policy.launch(self.root,self.task,self.role,permission,session)

    def sandbox(self,permission='R1'):
        cmd,env,evidence=self.launch(permission)
        options=[]
        for i,arg in enumerate(cmd):
            if arg=='-c':options.extend([arg,cmd[i+1]])
        return [CLI,'sandbox','-P',policy.PROFILE,'-C',str(self.role),*options,'--'],env,evidence

    def test_native_new_and_resume_parse_on_installed_cli_without_a_model(self):
        for sid in (None,'00000000-0000-4000-8000-000000000001'):
            cmd,env,evidence=self.launch(session=sid)
            self.assertNotIn('-s',cmd);self.assertNotIn('--dangerously-bypass-approvals-and-sandbox',cmd)
            self.assertIn('--ignore-user-config',cmd);self.assertIn('default_permissions="'+policy.PROFILE+'"',cmd)
            self.assertEqual(evidence['retained_native_choices']['model'],'gpt-5.4')
            self.assertEqual(evidence['retained_native_choices']['model_reasoning_effort'],'high')
            result=subprocess.run(cmd[:-1]+['--help'],env=env,text=True,capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('Usage:',result.stdout)
        self.assertIn('sandbox_mode = "danger-full-access"',self.config.read_text())

    def test_real_named_profile_read_write_deny_symlink_and_no_network(self):
        private=self.root/'raw';private.mkdir();(private/'fixture.txt').write_text('synthetic excluded')
        (self.role/'ordinary.txt').write_text('synthetic ordinary')
        # Build policy with a clean tree; then introduce an alias to prove the
        # actual sandbox denies it as well as the launch-time scanner.
        prefix,env,_=self.sandbox()
        (self.role/'private-link').symlink_to(private/'fixture.txt')
        (self.base/'outside.txt').write_text('synthetic outside')
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0));listener.listen(1);port=listener.getsockname()[1]
            script='''import pathlib,json,socket
role=pathlib.Path.cwd();out={}
for key,p in [('ordinary',role/'ordinary.txt'),('raw',pathlib.Path(RAW)),('auth',pathlib.Path(AUTH)),('outside',pathlib.Path(OUTSIDE)),('link',role/'private-link')]:
    try:p.read_bytes();out[key]=True
    except OSError:out[key]=False
for key,p in [('role_write',role/'result.txt'),('task_write',pathlib.Path(TASK)/'result.txt'),('out_write',pathlib.Path(TASK)/'out/result.txt'),('proposal_write',pathlib.Path(PROPOSAL)),('raw_write',pathlib.Path(RAW).parent/'result.txt')]:
    try:p.write_text('synthetic');out[key]=True
    except OSError:out[key]=False
try:s=socket.create_connection(('127.0.0.1',PORT),timeout=2);s.close();out['network']=True
except OSError:out['network']=False
print(json.dumps(out))
'''
            for key,value in {'RAW':str(private/'fixture.txt'),'AUTH':str(self.config),'OUTSIDE':str(self.base/'outside.txt'),'TASK':str(self.task),'PROPOSAL':str(self.proposal),'PORT':port}.items():
                script=script.replace(key,repr(value))
            result=subprocess.run(prefix+['/usr/bin/python3','-B','-c',script],env=env,text=True,capture_output=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout),{'ordinary':True,'raw':False,'auth':False,'outside':False,'link':False,
                                                   'role_write':False,'task_write':False,'out_write':True,'proposal_write':True,'raw_write':False,'network':False})

    def test_real_r0_profile_cannot_write_role_or_task(self):
        prefix,env,_=self.sandbox('R0')
        script='import pathlib,json; paths='+repr([str(self.role/'x'),str(self.task/'x'),str(self.task/'out/x'),str(self.proposal)])+'; out=[]\nfor p in paths:\n try:pathlib.Path(p).write_text("synthetic");out.append(True)\n except OSError:out.append(False)\nprint(json.dumps(out))'
        result=subprocess.run(prefix+['/usr/bin/python3','-B','-c',script],env=env,text=True,capture_output=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(json.loads(result.stdout),[False,False,False,False])

    def test_real_worker_cannot_replace_attempt_metadata_or_proposal_inode(self):
        final=self.canonical.parent/'native-final.txt';final.write_text('trusted fixture')
        self.canonical.write_text('trusted canonical')
        (self.task/'packet.json').write_text('{}')
        prefix,env,_=self.sandbox()
        script='''import pathlib,json,os
task=pathlib.Path(TASK);proposal=pathlib.Path(PROPOSAL);canonical=pathlib.Path(CANONICAL);final=canonical.parent/'native-final.txt';out={}
operations={
'final_write':lambda:final.write_text('changed'),
'final_unlink':lambda:final.unlink(),
'final_symlink':lambda:(canonical.parent/'future-final.txt').symlink_to('/excluded'),
'attempt_rename':lambda:canonical.parent.rename(task/'out/stolen-attempt'),
'proposal_unlink':lambda:canonical.unlink(),
'proposal_sibling':lambda:(canonical.parent/'memory-proposals.tmp').write_text('[]'),
'protected_hardlink':lambda:os.link(final,task/'out/alias'),
'packet_write':lambda:(task/'packet.json').write_text('changed'),
'proposal_direct':lambda:proposal.write_text('[]'),
'out_create':lambda:(task/'out/answer.txt').write_text('714')}
for key,operation in operations.items():
 try:operation();out[key]=True
 except OSError:out[key]=False
print(json.dumps(out))
'''.replace('TASK',repr(str(self.task))).replace('PROPOSAL',repr(str(self.proposal))).replace('CANONICAL',repr(str(self.canonical)))
        result=subprocess.run(prefix+['/usr/bin/python3','-B','-c',script],env=env,text=True,capture_output=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout),dict(final_write=False,final_unlink=False,final_symlink=False,
            attempt_rename=False,proposal_unlink=False,proposal_sibling=False,protected_hardlink=False,packet_write=False,proposal_direct=True,out_create=True))
        self.assertEqual(final.read_text(),'trusted fixture');self.assertFalse(self.proposal.is_symlink())

    def _fake_case(self,side_effect,original='synthetic original'):
        scripts=self.root/'scripts';shutil.copytree(CODE/'scripts',scripts,dirs_exist_ok=True)
        for name in ('raw-index','memory-adapter'):
            source=CODE/'tools'/name
            if source.exists():shutil.copytree(source,self.root/'tools'/name,dirs_exist_ok=True)
        fake=self.base/'case-fake'
        fake.write_text('#!/usr/bin/python3\nimport sys,json,os,re\nfrom pathlib import Path\n'
            +'prompt=sys.stdin.read()\nout=Path(prompt.split("Write deliverables under: ",1)[1].split("\\n",1)[0])\n'
            +side_effect+'\n'
            +'for x in [{"type":"thread.started","thread_id":"synthetic-boundary"},{"type":"item.completed","item":{"type":"agent_message","text":"SUMMARY: synthetic completed"}},{"type":"turn.completed"}]:print(json.dumps(x),flush=True)\n')
        fake.chmod(0o755)
        packet=self.base/'case-packet.json';packet.write_text(json.dumps(dict(task_id='synthetic',role_id='cards-master',
            from_agent_id='100003',goal='synthetic boundary',original_user_input=original)))
        env={**os.environ,'JAVIS_CODEX_BIN':str(fake),'JAVIS_ROOT':str(self.root),'JAVIS_MEMORY_GRAPH_DISABLED':'1'}
        process=subprocess.run([sys.executable,str(scripts/'task-runner.py'),str(packet)],env=env,text=True,capture_output=True,timeout=25)
        return process,json.loads((self.task/'attempts/1/result.json').read_text())

    def test_output_link_and_hardlink_rejected_without_reading_or_modifying_target(self):
        for kind in ('symlink','hardlink'):
            with self.subTest(kind=kind):
                if kind=='hardlink':
                    shutil.rmtree(self.root);self.task.mkdir(parents=True);self.role.mkdir(parents=True);(self.task/'out').mkdir()
                target=self.base/'victim.txt';target.write_bytes(b'OUTSIDE_SENTINEL_DO_NOT_CAPTURE')
                operation='(out/"result.txt").symlink_to(Path('+repr(str(target))+'))' if kind=='symlink' else 'os.link('+repr(str(target))+',out/"result.txt")'
                process,result=self._fake_case(operation)
                self.assertNotEqual(process.returncode,0,process.stdout+process.stderr)
                self.assertEqual(result['recording_status'],'failed');self.assertEqual(target.read_bytes(),b'OUTSIDE_SENTINEL_DO_NOT_CAPTURE')
                self.assertFalse(any(b'OUTSIDE_SENTINEL_DO_NOT_CAPTURE' in p.read_bytes() for p in (self.root/'raw/objects').iterdir()))

    def test_worker_memory_proposal_is_archived_and_not_a_delivery(self):
        proposal=[{'quote':'请记住：我喜欢蓝色','subject_id':'user','subject_label':'用户','predicate':'likes','value':'蓝色','scope':'role'}]
        effect='proposal=Path(re.search(r"JSON array to (.+?)\\. Each item",prompt).group(1))\nproposal.write_text('+repr(json.dumps(proposal,ensure_ascii=False))+')'
        process,result=self._fake_case(effect,original='请记住：我喜欢蓝色')
        self.assertEqual(process.returncode,0,process.stdout+process.stderr)
        self.assertEqual(json.loads(self.canonical.read_text()),proposal)
        self.assertTrue(result['memory_candidate_refs'])
        self.assertFalse(any('memory-proposals' in x.get('path','') for x in result['artifacts']))

    def test_invalid_worker_proposal_is_memory_error_without_target_read(self):
        target=self.base/'private-proposal.json';target.write_text('OUTSIDE_SENTINEL_DO_NOT_CAPTURE')
        process,result=self._fake_case('(out/".memory-proposals-attempt-1.json").symlink_to(Path('+repr(str(target))+'))')
        self.assertEqual(process.returncode,78,process.stdout+process.stderr)
        self.assertEqual(result['status'],'memory_error');self.assertTrue(result['memory_retry_required'])
        self.assertFalse(self.canonical.exists());self.assertEqual(target.read_text(),'OUTSIDE_SENTINEL_DO_NOT_CAPTURE')

    def test_missing_worker_proposal_keeps_explicit_save_fallback(self):
        process,result=self._fake_case('pass',original='请记住：我喜欢蓝色')
        self.assertEqual(process.returncode,0,process.stdout+process.stderr)
        self.assertFalse(self.canonical.exists());self.assertGreaterEqual(len(result['memory_candidate_refs']),2)

    def test_malformed_worker_proposal_is_not_silently_successful(self):
        process,result=self._fake_case('(out/".memory-proposals-attempt-1.json").write_text("{bad-json")')
        self.assertEqual(process.returncode,78,process.stdout+process.stderr)
        self.assertEqual(result['status'],'memory_error');self.assertTrue(result['memory_retry_required'])
        self.assertFalse(self.canonical.exists())

    def test_real_sandbox_cannot_connect_private_or_abstract_unix_sockets(self):
        state=self.root/'state';state.mkdir();path=str(state/'private.sock')
        abstract='\x00javis-private-'+uuid.uuid4().hex
        with socket.socket(socket.AF_UNIX) as private, socket.socket(socket.AF_UNIX) as hidden:
            private.bind(path);private.listen(1);hidden.bind(abstract);hidden.listen(1)
            prefix,env,_=self.sandbox()
            script='import socket,json\naddresses='+repr([path,abstract])+'\nout=[]\nfor address in addresses:\n s=socket.socket(socket.AF_UNIX);s.settimeout(1)\n try:s.connect(address);out.append(True)\n except OSError:out.append(False)\n finally:s.close()\nprint(json.dumps(out))'
            result=subprocess.run(prefix+['/usr/bin/python3','-B','-c',script],env=env,text=True,capture_output=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(json.loads(result.stdout),[False,False])

    def test_environment_is_allowlisted_and_auth_path_preserved(self):
        with patch.dict(os.environ,{'OPENAI_API_KEY':'synthetic-secret','ARBITRARY_SECRET':'synthetic-secret',
                                    'NEO4J_PASSWORD':'synthetic-secret','PATH':'/untrusted/bin','FAKE_CALLS':'synthetic'}):
            _,env,_=self.launch()
        self.assertEqual(env['CODEX_HOME'],str(self.auth))
        self.assertFalse({'OPENAI_API_KEY','ARBITRARY_SECRET','NEO4J_PASSWORD','FAKE_CALLS'} & set(env))
        self.assertNotIn('/untrusted/bin',env['PATH'])

    def test_input_copy_refuses_raw_vault_unclassified_and_link_sources(self):
        allowed=self.root/'workspace/inbox/ordinary-approved';allowed.mkdir(parents=True)
        good=allowed/'ordinary.txt';good.write_text('synthetic')
        self.assertEqual(policy.approved_input_source(self.root,self.task,self.role,good),good)
        for directory in (self.root/'raw',self.root/'memory',self.root/'backups',self.base/'vault-unclassified'):
            directory.mkdir(exist_ok=True);file=directory/'fixture.txt';file.write_text('synthetic')
            with self.assertRaises(ValueError):policy.approved_input_source(self.root,self.task,self.role,file)
        link=allowed/'alias.txt';link.symlink_to(good)
        with self.assertRaises(ValueError):policy.approved_input_source(self.root,self.task,self.role,link)
        link.unlink();os.link(good,link)
        with self.assertRaises(ValueError):policy.approved_input_source(self.root,self.task,self.role,good)
        with self.assertRaises(ValueError):policy.approved_input_source(self.root,self.task,self.role,'/mnt/c/Users/user/Javis-Vault/personal/fixture.txt')

    def test_role_task_links_and_project_config_fail_closed(self):
        outside=self.base/'outside';outside.write_text('synthetic')
        link=self.task/'alias';link.symlink_to(outside)
        with self.assertRaises(ValueError):self.launch()
        link.unlink();os.link(outside,link)
        with self.assertRaises(ValueError):self.launch()
        link.unlink()
        config=self.role/'.codex/config.toml';config.parent.mkdir();config.write_text('sandbox_mode="danger-full-access"')
        with self.assertRaises(ValueError):self.launch()

    def test_input_destination_links_never_modify_outside_files(self):
        outside=self.base/'outside';outside.mkdir();victim=outside/'input.txt'
        victim.write_bytes(b'synthetic outside unchanged')
        target=self.task/'in';target.symlink_to(outside,target_is_directory=True)
        with self.assertRaises(OSError):policy.write_input_copy(self.task,'input.txt',b'new')
        self.assertEqual(victim.read_bytes(),b'synthetic outside unchanged')
        target.unlink();target.mkdir()
        for kind in ('symlink','hardlink'):
            with self.subTest(kind=kind):
                dest=target/'input.txt'
                if kind=='symlink':dest.symlink_to(victim)
                else:os.link(victim,dest)
                with self.assertRaises(ValueError):policy.write_input_copy(self.task,'input.txt',b'new')
                self.assertEqual(victim.read_bytes(),b'synthetic outside unchanged');dest.unlink()

    def test_input_destination_substitution_before_replace_does_not_follow_link(self):
        victim=self.base/'outside';victim.write_bytes(b'synthetic outside unchanged')
        target=self.task/'in/input.txt';target.parent.mkdir();target.write_bytes(b'old')
        replace=os.replace
        def substituted(src,dst,**kwargs):
            target.unlink();target.symlink_to(victim)
            return replace(src,dst,**kwargs)
        with patch.object(policy.os,'replace',side_effect=substituted):
            policy.write_input_copy(self.task,'input.txt',b'approved captured')
        self.assertEqual(victim.read_bytes(),b'synthetic outside unchanged')
        self.assertFalse(target.is_symlink());self.assertEqual(target.read_bytes(),b'approved captured')

    def test_secure_input_rejects_source_or_parent_replaced_with_link(self):
        approved=self.root/'workspace/inbox/ordinary-approved';approved.mkdir(parents=True)
        source=approved/'input.txt';source.write_bytes(b'approved')
        outside=self.base/'outside';outside.mkdir();victim=outside/'input.txt';victim.write_bytes(b'excluded')
        checked=policy.approved_input_source(self.root,self.task,self.role,source)
        source.unlink();source.symlink_to(victim)
        with self.assertRaises(OSError):policy.secure_input_bytes(checked)
        source.unlink();source.write_bytes(b'approved')
        checked=policy.approved_input_source(self.root,self.task,self.role,source)
        approved.rename(approved.with_name('moved'));approved.symlink_to(outside,target_is_directory=True)
        with self.assertRaises(OSError):policy.secure_input_bytes(checked)
        self.assertEqual(victim.read_bytes(),b'excluded')

    def test_secure_input_detects_changes_during_capture(self):
        source=self.task/'input.txt';source.write_bytes(b'approved')
        fstat=os.fstat;counter=[0]
        def mutated(fd):
            counter[0]+=1
            if counter[0]==2:source.write_bytes(b'mutated data')
            return fstat(fd)
        with patch.object(policy.os,'fstat',side_effect=mutated):
            with self.assertRaisesRegex(ValueError,'changed during'):policy.secure_input_bytes(source)

    def test_snapshot_uses_verified_capture_and_keeps_redaction_guards(self):
        source=self.task/'input.txt'
        original='普通材料\r\nOPENAI_API_KEY=sk-synthetic-credential-12345678901234567890\r\n'.encode()
        source.write_bytes(original);captured=policy.secure_input_bytes(source)
        expected,changes,_=safe_file_bytes(source,captured_bytes=captured)
        self.assertTrue(changes);self.assertNotIn(b'sk-synthetic-credential-',expected)
        source.unlink() # A snapshot of captured bytes must not reopen the path.
        row=snapshot_file(self.root,source,'synthetic',captured_bytes=captured)
        self.assertEqual(Path(row['object_path']).read_bytes(),expected)
        self.assertTrue(row['redactions'])
        self.assertEqual(safe_file_bytes(source,captured_bytes='普通\r\n'.encode())[0],'普通\r\n'.encode())
        with self.assertRaises(CredentialFileBlocked):safe_file_bytes(self.task/'auth.json',captured_bytes=b'{}')
        with self.assertRaises(CredentialFileBlocked):safe_file_bytes(self.task/'key.key',captured_bytes=b'synthetic')
        with self.assertRaises(CredentialFileBlocked):safe_file_bytes(source,captured_bytes=bytes.fromhex('03d9a29a67fb4bb5')+b'synthetic')

    def test_real_runtime_blocks_unapproved_input_before_fake_worker(self):
        source=self.root/'raw/source.txt';source.parent.mkdir();source.write_text('synthetic excluded body')
        packet=self.base/'packet.json';packet.write_text(json.dumps(dict(task_id='synthetic',role_id='cards-master',
              from_agent_id='100003',goal='synthetic',inputs={'files':[str(source)]})))
        with patch('task_runtime.subprocess.Popen',side_effect=AssertionError('worker must not run')):
            code=run([str(packet)])
        self.assertEqual(code,77)
        self.assertFalse((self.task/'in').exists())
        result=json.loads((self.task/'attempts/1/result.json').read_text())
        self.assertIn('input source is not approved',result['failure_reason'])

    def test_fake_worker_receipt_and_resume_keep_original_native_protocol(self):
        # All fake control data is embedded in this test executable, rather than
        # relying on secret-bearing inherited environment variables.
        scripts=self.root/'scripts';shutil.copytree(CODE/'scripts',scripts)
        for name in ('raw-index','memory-adapter'):
            source=CODE/'tools'/name
            if source.exists(): shutil.copytree(source,self.root/'tools'/name)
        calls=self.base/'calls.jsonl';fake=self.base/'fake-codex'
        fake.write_text('#!/usr/bin/python3\nimport sys,json\nfrom pathlib import Path\n'
            + 'calls=Path('+repr(str(calls))+')\n'
            + 'with calls.open("a") as f:f.write(json.dumps(sys.argv[1:])+"\\n")\n'
            + 'prompt=sys.stdin.read()\n'
            + 'for x in [{"type":"thread.started","thread_id":"synthetic-private-session"},{"type":"item.completed","item":{"type":"agent_message","text":"SUMMARY: synthetic completed"}},{"type":"turn.completed"}]:print(json.dumps(x),flush=True)\n')
        fake.chmod(0o755)
        env={**os.environ,'JAVIS_CODEX_BIN':str(fake),'JAVIS_ROOT':str(self.root),'JAVIS_MEMORY_GRAPH_DISABLED':'1'}
        approved=self.root/'workspace/inbox/ordinary-approved/ordinary.txt'
        approved.parent.mkdir(parents=True);approved.write_text('synthetic approved material\n')
        packet=self.base/'packet.json'
        for mode,goal in [('run','synthetic first'),('continue','synthetic continued'),('continue','legacy rollover')]:
            if goal=='legacy rollover':
                state_path=self.root/'state/tasks/synthetic.json'
                state=json.loads(state_path.read_text());state.pop('native_permissions_profile')
                state_path.write_text(json.dumps(state))
            packet.write_text(json.dumps(dict(task_id='synthetic',role_id='cards-master',from_agent_id='100003',
                goal=goal,mode=mode,inputs={'files':[str(approved)]})))
            result=subprocess.run([sys.executable,str(scripts/'task-runner.py'),str(packet)],env=env,text=True,capture_output=True,timeout=25)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        args=[json.loads(line) for line in calls.read_text().splitlines()]
        self.assertEqual(len(args),3);self.assertNotIn('resume',args[0]);self.assertIn('resume',args[1])
        self.assertNotIn('resume',args[2])
        self.assertEqual((self.task/'in/000-ordinary.txt').read_bytes(),approved.read_bytes())
        for number in (1,2,3):
            result=json.loads((self.task/'attempts'/str(number)/'result.json').read_text())
            self.assertEqual(result['exit_code'],0);self.assertTrue(result['native_final_output_available'])
            self.assertTrue((self.task/'attempts'/str(number)/'native-permissions.json').exists())
        state=json.loads((self.root/'state/tasks/synthetic.json').read_text())
        evidence=json.loads((self.task/'attempts/3/native-permissions.json').read_text())
        self.assertEqual(state['attempt'],3);self.assertEqual(state['task_id'],'synthetic')
        self.assertEqual(state['native_permissions_profile'],policy.PROFILE)
        self.assertEqual(evidence['native_session_rollover_reason'],'prior_native_permissions_unverified')


if __name__=='__main__':unittest.main(verbosity=2)
