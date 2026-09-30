"""Focused runtime review regressions; synthetic fixtures, no external model calls."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

STAGE = Path(__file__).resolve().parent
CODE = Path(os.environ.get('JAVIS_TEST_CODE_ROOT', STAGE))
sys.path.insert(0, str(CODE / 'scripts'))
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('runtime_fixture', STAGE / 'test_v02_runtime.py')
fixture_module = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture_module)


class RuntimeEdges(unittest.TestCase):
    def setUp(self):
        # Composition avoids inheriting/repeating the original runtime suite.
        self.fixture = fixture_module.RuntimeV02()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)

    def test_non_json_stdout_pem_never_persists_secret_body(self):
        case = self.fixture
        marker = 'syntheticStdoutPrivateMaterial'
        fake = fixture_module.FAKE.replace(
            "if goal=='slow': time.sleep(15)",
            "if goal=='slow': time.sleep(15)\nif goal=='stdout pem':\n"
            "    print('-----BEGIN PRIVATE KEY-----',flush=True)\n"
            "    print('syntheticStdoutPrivateMaterial',flush=True)\n"
            "    print('-----END PRIVATE KEY-----',flush=True)")
        case.fake.write_text(fake)
        result = case.invoke(goal='stdout pem')
        self.assertIn(result.returncode, (0, 74), result.stderr)
        for path in case.r.rglob('*'):
            if path.is_file() and 'scripts' not in path.parts:
                self.assertNotIn(marker.encode(), path.read_bytes(), str(path.relative_to(case.r)))
        gaps = [e for e in case.events() if (e.get('payload') or {}).get('kind') in ('unparsed_codex_stdout', 'recording_gap')]
        self.assertTrue(gaps, 'Malformed stdout must leave an explicit capture limitation')

    def test_l4_in_original_user_input_blocks_external_execution(self):
        case = self.fixture
        result = case.invoke(goal='summarize the synthetic request',
                             original_user_input='L4: synthetic classified original text')
        self.assertEqual(result.returncode, 77, result.stderr)
        self.assertFalse(case.calls.exists())
        self.assertEqual(case.state()['state'], 'waiting_user')

    def test_original_user_constraints_reach_model_prompt(self):
        case = self.fixture
        fake = fixture_module.FAKE.replace(
            "args=sys.argv[1:]; prompt=sys.stdin.read()",
            "args=sys.argv[1:]; prompt=sys.stdin.read()\n"
            "Path(os.environ['FAKE_CALLS']+'.prompt').write_text(prompt)")
        case.fake.write_text(fake)
        original = 'EXACT_ORIGINAL_SCOPE_CONSTRAINT: only edit the synthetic draft'
        result = case.invoke(goal='normalized request', original_user_input=original)
        self.assertEqual(result.returncode, 0, result.stderr)
        prompt = Path(str(case.calls) + '.prompt').read_text()
        self.assertIn(original, prompt)
        self.assertIn('normalized request', prompt)

    def test_preparation_failures_leave_terminal_failure_results(self):
        case = self.fixture
        import task_runtime
        packet = case.packet(tid='rawfail')
        with patch.dict(os.environ, case.env), patch('task_runtime.state_event', side_effect=OSError('synthetic RAW write failure')):
            try:
                code = task_runtime.run([str(packet)])
            except OSError:
                # Reporting an error is permitted, but persistent state/result
                # must already show the failure; created cannot be left hanging.
                code = 1
        self.assertNotEqual(code, 0)
        state = case.state('rawfail')
        self.assertEqual(state['state'], 'failed')
        result = json.loads((case.r / 'workspace/tasks/rawfail/result.json').read_text())
        self.assertNotEqual(result['exit_code'], 0)
        self.assertIn(result['recording_status'], ('failed', 'partial'))
        self.assertFalse(case.calls.exists())
        invalid = case.invoke(tid='invalid-input', inputs={'files': [{'label': 'missing-path'}]})
        self.assertNotEqual(invalid.returncode, 0)
        state_path = case.r / 'state/tasks/invalid-input.json'
        if state_path.exists():
            self.assertNotEqual(json.loads(state_path.read_text())['state'], 'created')
        self.assertFalse(case.calls.exists())


if __name__ == '__main__': unittest.main(verbosity=2)
