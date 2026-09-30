"""Focused scenario regressions: pure renderer/policy and early identity rejection only."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from urllib.parse import unquote

sys.dont_write_bytecode = True
CODE = Path(os.environ.get('JAVIS_SCENARIO_CODE_ROOT', Path.home() / 'javis'))
sys.path.insert(0, str(CODE / 'scripts'))
import task_runtime as runtime


class ScenarioRuntimeFixes(unittest.TestCase):
    def result(self, **extra):
        return {'role_id': 'gpt-star', 'summary_zh': '合成文件已完成。', 'status': 'ok', 'artifacts': [], **extra}

    def target(self, reply):
        return re.findall(r'\]\(<([^>]+)>\)', reply)

    def test_unicode_spaces_special_filename_maps_to_same_real_windows_file(self):
        parent = Path('/mnt/c/Users/user/Javis-Exchange/javis-scenario-test-20260918/renderer-fixtures')
        parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='case-', dir=parent) as tmp:
            source = Path(tmp) / '中文 空格 [方括号](括号)#百分%.csv'
            source.write_text('synthetic,value\nfixture,1\n')
            result = self.result(artifacts=[{'delivery_status': 'verified', 'exchange_path': str(source)}])
            original = copy.deepcopy(result)
            reply = runtime.render_user_reply(result)
            targets = self.target(reply)
            self.assertEqual(len(targets), 1)
            self.assertNotIn(' ', targets[0]); self.assertNotIn('#', targets[0])
            decoded = unquote(targets[0])
            self.assertTrue(decoded.startswith('C:/'))
            resolved = Path('/mnt') / decoded[0].lower() / decoded[3:]
            self.assertTrue(resolved.is_file())
            self.assertTrue(resolved.samefile(source))
            self.assertEqual(hashlib.sha256(resolved.read_bytes()).hexdigest(), hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertIn('中文 空格 \\[方括号\\](括号)#百分%.csv', reply)
            self.assertEqual(result, original)

    def test_native_windows_backslashes_map_to_windows_target(self):
        reply = runtime.render_user_reply(self.result(artifacts=[{'delivery_status': 'verified', 'exchange_path': 'C:\\folder\\中文 文件.txt'}]))
        self.assertEqual(unquote(self.target(reply)[0]), 'C:/folder/中文 文件.txt')

    def test_unverified_missing_or_unmappable_delivery_never_becomes_link(self):
        artifacts = [{'delivery_status': 'exchange_not_configured', 'exchange_path': '/mnt/c/fake.txt'},
                     {'delivery_status': 'failed', 'exchange_path': 'C:/fake2.txt'},
                     {'exchange_path': 'C:/fake3.txt'}, {'delivery_status': 'verified', 'exchange_path': None},
                     {'delivery_status': 'verified', 'exchange_path': '/home/user/linux-only.txt'}]
        reply = runtime.render_user_reply(self.result(artifacts=artifacts))
        self.assertEqual(self.target(reply), [])
        self.assertNotIn('Windows 交付文件', reply)

    def test_duplicate_artifact_path_is_only_listed_once(self):
        item = {'delivery_status': 'verified', 'exchange_path': '/mnt/c/folder/test.txt'}
        reply = runtime.render_user_reply(self.result(artifacts=[item, dict(item), {**item, 'exchange_path': 'C:/folder/test.txt'}]))
        self.assertEqual(len(self.target(reply)), 1)

    def test_repeated_trailing_signature_is_one_after_links_summary_unchanged(self):
        for role, signature in [('gpt-star', '—— 来自本机 GPT Star'), ('cards-master', '—— 来自0号机codex_Cards'), ('invest', '—— 来自0-invest_codex')]:
            with self.subTest(role=role):
                summary = '原始合成正文\n\n' + signature + '\n\n' + signature
                result = self.result(role_id=role, summary_zh=summary, artifacts=[{'delivery_status': 'verified', 'exchange_path': '/mnt/c/file.txt'}])
                before = copy.deepcopy(result)
                reply = runtime.render_user_reply(result)
                self.assertEqual(reply.splitlines().count(signature), 1)
                self.assertTrue(reply.endswith(signature))
                self.assertEqual(result, before)
                self.assertEqual(result['summary_zh'], summary)
                self.assertEqual(runtime.render_user_reply(result), reply)

    def test_inline_signature_mention_is_preserved(self):
        text = '资料原文提到 —— 来自本机 GPT Star；这是正文引用。'
        reply = runtime.render_user_reply(self.result(summary_zh=text))
        self.assertIn(text, reply)
        self.assertEqual(reply.splitlines().count('—— 来自本机 GPT Star'), 1)

    def test_no_artifact_behavior_unchanged_and_failure_status_kept(self):
        self.assertEqual(runtime.render_user_reply(self.result()), '合成文件已完成。\n\n—— 来自本机 GPT Star')
        self.assertEqual(runtime.render_user_reply(self.result(status='waiting_user', exit_code=77)),
                         '合成文件已完成。\n\n—— 来自本机 GPT Star\n(status=waiting_user exit=77)')

    def test_label_newlines_cannot_inject_markdown_lines(self):
        # A newline-containing /mnt path is rejected by the full-match mapper.
        blocked = runtime.render_user_reply(self.result(artifacts=[{'delivery_status': 'verified', 'exchange_path': '/mnt/c/name\n[next].txt'}]))
        self.assertEqual(self.target(blocked), [])
        # A native drive prefix may still be formatted; its label cannot add a line.
        reply = runtime.render_user_reply(self.result(artifacts=[{'delivery_status': 'verified', 'exchange_path': 'C:/name\n[next].txt'}]))
        self.assertIn('[name \\[next\\].txt]', reply)
        self.assertIn('%0A', self.target(reply)[0])

    def test_l4_full_structure_is_classified_before_allowlist(self):
        marker = 'SYNTHETIC_REGRESSION_L4_BODY'
        packet = {'task_id': 'l4-regression', 'role_id': 'gpt-star', 'goal': 'test', 'from_agent_id': 'synthetic-origin',
                  'metadata': {'classification': 'L4', 'memo': marker}, 'approval_refs': [marker],
                  'redactions': [{'detail': marker}], 'cwd_hint': marker, 'source': {'text': marker}}
        original = copy.deepcopy(packet)
        safe = runtime.checked_packet(packet)
        self.assertNotIn(marker, json.dumps(safe))
        self.assertEqual(safe['privacy_level'], 'L4')
        self.assertEqual(safe['from_agent_id'], 'synthetic-origin')
        self.assertEqual(packet, original)

    def test_l4_origin_must_be_scalar_identifier_and_permission_must_be_enum(self):
        for origin in [['SYNTHETIC_BODY'], 'SYNTHETIC_BODY with spaces', 'x' * 161]:
            with self.subTest(origin_kind=type(origin).__name__):
                safe = runtime.checked_packet({'task_id': 'l4-id', 'role_id': 'gpt-star', 'goal': 'test', 'privacy_level': 'L4', 'from_agent_id': origin})
                self.assertNotIn('from_agent_id', safe)
        with self.assertRaisesRegex(ValueError, 'invalid permission'):
            runtime.checked_packet({'task_id': 'l4-bad-permission', 'role_id': 'gpt-star', 'goal': 'test', 'privacy_level': 'L4', 'permission': 'SYNTHETIC_BODY'})

    def test_task_origin_rejection_happens_before_any_task_write(self):
        with tempfile.TemporaryDirectory(prefix='javis-origin-regression-') as tmp:
            root = Path(tmp); task = root / 'workspace/tasks/identity-test'; role = root / 'workspace/roles/gpt-star'
            task.mkdir(parents=True); role.mkdir(parents=True); (root / 'state/tasks').mkdir(parents=True)
            state_path = root / 'state/tasks/identity-test.json'
            state_path.write_text(json.dumps({'task_id': 'identity-test', 'role_id': 'gpt-star', 'from_agent_id': 'origin-A', 'state': 'completed'}))
            (task / 'packet.json').write_text('{"synthetic":"unchanged"}')
            before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            with self.assertRaisesRegex(ValueError, 'task origin cannot change'):
                runtime.execute(root, task, role, {'task_id': 'identity-test', 'role_id': 'gpt-star', 'from_agent_id': 'origin-B', 'mode': 'continue'})
            after = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            self.assertEqual(after, before)


if __name__ == '__main__':
    unittest.main(verbosity=2)
