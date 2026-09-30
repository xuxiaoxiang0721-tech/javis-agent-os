"""Nine authorized local roles: synthetic queues/workers in temporary roots only."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

os.environ.setdefault('JAVIS_TEST_CODE_ROOT', str(Path(__file__).resolve().parents[3]))
import test_control_p1 as support
from role_registry import ROLE_REGISTRY, ROLE_IDS, ROLE_ORIGINS, DROP_DIRS, get_role, role_workspace
from task_control import Principal, ControlError
from task_service import load_control
from task_runtime import checked_packet, execute, RequestConflict


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


producer = module('nine_bot_producer', support.CODE / 'scripts/submit-drop.py')
drop = producer.contract
entry = module('nine_bot_entry', support.CODE / 'scripts/role-run.py')
EXPECTED = {'gpt-star', 'invest', 'operations', 'property', 'idea-lab',
            'cards-master', 'personal-life', 'ai-data', 'domestic-fund',
            'javis', 'friday', 'toolgo'}


class NineBots(unittest.TestCase):
    def setUp(self):
        support.ControlP1.setUp(self)
        for role in ROLE_IDS:
            (self.r / 'workspace/roles' / role).mkdir(parents=True, exist_ok=True)
        self.owner = Principal('nine-owner', 'owner', ROLE_IDS,
                               frozenset({'task:create', 'task:read', 'task:control'}))
        self.admin = Principal('nine-admin', 'owner', ROLE_IDS,
                               frozenset({'task:read:any', 'task:control:any'}))
        self.base = Path(self.tmp.name) / 'queues'
        self.base.mkdir()
        self.bridge = drop.Bridge(self.r, self.base)
        self.bridge.prepare()
        self.message = Path(self.tmp.name) / 'synthetic.txt'
        self.message.write_bytes(b'\xef\xbb\xbfsynthetic original\r\nsecond\rthird\n')
        self.fake.write_text(support.base_runtime.bind_fake_calls(support.FAKE.replace("{'args':args,'prompt':prompt}",
                                                "{'args':args,'prompt':prompt,'cwd':os.getcwd()}"),self.calls))

    tearDown = support.ControlP1.tearDown
    launch = support.ControlP1.launch
    count = support.ControlP1.count

    def create(self, role, cid='same-command', text='synthetic role task'):
        return self.svc.submit(self.owner, dict(command_id=cid, role_id=role, original_text=text))

    def submit(self, role, sid='same-submission', mid='same-real-message'):
        result = producer.submit(role, str(self.message), sid, mid, str(self.base))
        self.bridge.once()
        return result

    def accepted(self, submitted):
        path = self.base / DROP_DIRS[submitted['role_id']] / 'processing' / (submitted['delivery_id']+'.ready') / 'accepted.json'
        return json.loads(path.read_text())

    def final(self, submitted):
        for name in ('done', 'fail'):
            path = self.base / DROP_DIRS[submitted['role_id']] / name / submitted['delivery_id'] / 'receipt.json'
            if path.exists(): return json.loads(path.read_text())
        self.fail('expected immutable drop receipt')

    def test_registry_is_single_immutable_nine_role_mapping(self):
        self.assertEqual(set(ROLE_IDS), EXPECTED)
        self.assertEqual(set(drop.ROLES), EXPECTED)
        self.assertEqual(set(__import__('task_service').ROLES), EXPECTED)
        self.assertEqual(len(set(ROLE_ORIGINS.values())), len(EXPECTED))
        self.assertEqual(len(set(DROP_DIRS.values())), len(EXPECTED))
        self.assertEqual(DROP_DIRS['cards-master'], 'cards-drop')
        self.assertEqual(DROP_DIRS['invest'], 'invest-drop')
        configured = json.loads((support.CODE/'config/routing.json').read_text())['roles']
        for role in ROLE_IDS:
            row = get_role(role)
            if row['bot_id'] is not None:
                self.assertTrue(row['bot_id'].isdigit())
                self.assertEqual(row['origin_id'], row['bot_id'])
            else:
                self.assertTrue(row['origin_id'].startswith('grok-export-agent:'))
                self.assertIn('numeric id unverified', row['identity_source'])
            self.assertEqual(get_role(role)['cwd'], configured[role]['cwd'])
            self.assertEqual(get_role(role)['label'], configured[role]['bot'])
        with self.assertRaises(TypeError): ROLE_REGISTRY['invest']['bot_id'] = 'wrong'
        with self.assertRaises(TypeError): ROLE_ORIGINS['invest'] = 'wrong'

    def test_nine_producers_preserve_original_and_role_scoped_identity_without_worker(self):
        tasks = []
        for role in sorted(ROLE_IDS):
            first = self.submit(role)
            accepted = self.accepted(first)
            tasks.append(accepted['task_id'])
            control = load_control(self.r, accepted['task_id'])
            self.assertEqual(control['role_id'], role)
            self.assertEqual(control['goals'][0]['text'], self.message.read_bytes().decode('utf-8-sig'))
            state = json.loads((self.r/'state/tasks'/f"{accepted['task_id']}.json").read_text())
            self.assertEqual(state['from_agent_id'], ROLE_ORIGINS[role])
            self.assertEqual(state['attempt'], 0)
            again = self.accepted(self.submit(role))
            self.assertEqual(again['task_id'], accepted['task_id'])
            self.assertTrue(again['replayed'])
        self.assertEqual(len(set(tasks)), len(EXPECTED))
        self.assertEqual(self.count(), 0)
        self.assertEqual(len(list((self.r/'state/tasks').glob('*.json'))), len(EXPECTED))

    def test_nine_fake_executions_cwd_receipts_native_and_no_duplicate_attempt(self):
        for role in sorted(ROLE_IDS):
            first = self.submit(role)
            tid = self.accepted(first)['task_id']
            result = self.launch(tid)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.bridge.once()
            receipt = self.final(first)
            self.assertEqual(receipt['status'], 'succeeded', receipt)
            sealed = self.svc.result(self.admin, tid)['result']
            self.assertEqual((sealed['role_id'], sealed['attempt'], sealed['exit_code']), (role, 1, 0))
            self.assertTrue(sealed['native_final_output_available'])
            packet = json.loads((self.r/'workspace/tasks'/tid/'packet.json').read_text())
            self.assertEqual(packet['from_agent_id'], ROLE_ORIGINS[role])
            self.assertTrue((self.r/'workspace/roles'/role/'outbox'/(tid+'.result.json')).exists())
            call = json.loads(self.calls.read_text().splitlines()[-1])
            self.assertEqual(call['cwd'], str(role_workspace(self.r, role)))
            self.assertNotIn('-s',call['args'])
            filesystem=next(v for v in call['args'] if v.startswith('permissions.javis_private_worker.filesystem='))
            self.assertIn(json.dumps(str(self.r/'workspace/tasks'/tid))+' = "read"',filesystem)
            self.assertIn(json.dumps(str(self.r/'workspace/tasks'/tid/'out'))+' = "write"',filesystem)
            again = self.final(self.submit(role))
            self.assertTrue(again['replayed'])
            self.assertEqual(again['result_sha256'], receipt['result_sha256'])
            self.launch(tid)
        self.assertEqual(self.count(), len(EXPECTED))

    def test_unknown_and_excluded_roles_rejected_before_acceptance(self):
        for role in ('waiting-lounge', 'Saturday', 'saturday', 'unknown', '../invest'):
            with self.assertRaises(ValueError): get_role(role)
            with self.assertRaises(ControlError): self.create(role)
            with self.assertRaises(drop.Reject): self.submit(role)
            with self.assertRaises(ValueError): entry.read_packet(role, ['synthetic'], self.r)
            with self.assertRaises(ValueError): checked_packet(dict(role_id=role, goal='synthetic'))
        self.assertEqual(self.count(), 0)
        self.assertFalse((self.r/'state/tasks').exists())

    def test_principal_cannot_cross_role_or_owner_boundary(self):
        first = self.create('operations')['task_id']
        other = Principal('nine-owner', 'owner', frozenset({'invest'}), self.owner.capabilities)
        stranger = Principal('another-owner', 'owner', ROLE_IDS, self.owner.capabilities)
        for principal in (other, stranger):
            with self.assertRaises(ControlError): self.svc.status(principal, first)
            with self.assertRaises(ControlError): self.svc.result(principal, first)
            with self.assertRaises(ControlError): self.svc.command(principal, first,
                dict(command_id='cancel', action='cancel', expected_goal_revision=1, expected_attempt=0))
        with self.assertRaises(ControlError): self.svc.submit(other,
            dict(command_id='same-command', role_id='operations', original_text='synthetic role task'))
        with self.assertRaises(ControlError): self.svc.submit(self.owner,
            dict(command_id='bad', role_id='operations', original_text='x', actor_id='elevated'))
        self.assertEqual(self.count(), 0)

    def test_changed_bytes_same_message_and_changed_command_rejected(self):
        first = self.submit('property')
        tid = self.accepted(first)['task_id']
        self.message.write_text('changed synthetic')
        self.assertEqual(self.final(self.submit('property'))['status'], 'rejected')
        self.create('idea-lab')
        with self.assertRaises(ControlError): self.create('idea-lab', text='changed')
        self.assertEqual(self.svc.status(self.admin, tid)['attempt'], 0)
        self.assertEqual(self.count(), 0)

    def test_role_entry_platform_ids_never_fall_through_to_invest(self):
        with patch.dict(os.environ, {'INVEST_AGENT_ID':'spoofed', 'CARDS_MASTER_AGENT_ID':'spoofed'}):
            tasks = []
            for role in sorted(ROLE_IDS):
                packet = entry.read_packet(role, ['--message-file', str(self.message), '--message-id', 'same-id'], self.r)
                self.assertEqual(packet['from_agent_id'], 'local-user' if role=='gpt-star' else ROLE_ORIGINS[role])
                self.assertEqual(packet['original_user_input'], self.message.read_bytes().decode('utf-8-sig'))
                tasks.append(packet['task_id'])
        self.assertEqual(len(set(tasks)), len(EXPECTED))

    def test_workspace_symlink_and_routing_cwd_mismatch_block_dispatch(self):
        role = 'operations'
        directory = self.r/'workspace/roles'/role
        directory.rmdir()
        directory.symlink_to(self.r/'workspace/roles/invest', target_is_directory=True)
        with self.assertRaises(ValueError): role_workspace(self.r, role)
        tid = self.create(role)['task_id']
        self.launch(tid)
        self.assertEqual(self.count(), 0)
        self.assertEqual(self.svc.status(self.owner, tid)['dispatch_status'], 'needs_review')
        directory.unlink(); directory.mkdir()
        (self.r/'config').mkdir()
        (self.r/'config/routing.json').write_text(json.dumps({'roles':{role:{'cwd':'workspace/roles/invest'}}}))
        with self.assertRaises(ValueError): role_workspace(self.r, role)

    def test_common_cli_scopes_come_from_registry(self):
        path = Path(self.tmp.name)/'cli-request.json'
        path.write_text(json.dumps(dict(command_id='cli-submit', role_id='domestic-fund', original_text='synthetic CLI')))
        command = [sys.executable, str(self.r/'scripts/task-cli.py'), 'submit', '--request-file', str(path)]
        first = subprocess.run(command, env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(first.returncode, 0, first.stderr)
        result = json.loads(first.stdout)
        second = subprocess.run(command, env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(json.loads(second.stdout)['task_id'], result['task_id'])
        self.assertTrue(json.loads(second.stdout)['replayed'])
        self.assertEqual(self.count(), 0)

    def test_existing_task_cannot_change_role_or_origin_via_direct_runtime(self):
        tid = self.create('property')['task_id']
        state_path = self.r/'state/tasks'/f'{tid}.json'
        before = state_path.read_bytes()
        for role, origin in [('invest', ROLE_ORIGINS['invest']), ('property', ROLE_ORIGINS['invest'])]:
            packet = checked_packet(dict(task_id=tid, role_id=role, from_agent_id=origin,
                                         goal='synthetic identity change', mode='continue'))
            with self.assertRaises(RequestConflict):
                execute(self.r, self.r/'workspace/tasks'/tid, role_workspace(self.r, role), packet)
            self.assertEqual(state_path.read_bytes(), before)
        self.assertEqual(self.count(), 0)

    def test_l4_preserves_only_registered_namespaced_origin_and_withholds_body(self):
        packet = checked_packet(dict(role_id='operations', from_agent_id=ROLE_ORIGINS['operations'],
                                     goal='L4: synthetic restricted body'))
        self.assertEqual(packet['from_agent_id'], ROLE_ORIGINS['operations'])
        self.assertNotIn('synthetic restricted body', json.dumps(packet))


if __name__ == '__main__': unittest.main(verbosity=2)
