import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'scripts'), str(ROOT/'tools/memory-adapter')]
from memory_corpus_scope import resolve_scope_binding, verify_scope_binding, scope_index

INVEST_UUID = '00000000-0000-4000-8000-000000000012'
OPERATIONS_UUID = '00000000-0000-4000-8000-000000000001'


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
    def tearDown(self):
        self.tmp.cleanup()
    def write(self, path, row):
        path = self.root/path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(row), encoding='utf-8')
        return path
    def bot(self, uid=OPERATIONS_UUID, **extra):
        meta = self.write('memory/imports/export/bots/misleading-label/BOT-META.json', {'agent_id':uid, **extra})
        text = meta.parent/'transcript.jsonl'
        text.write_text('{"text":"Synthetic"}\n')
        return text, meta
    def bridge(self, uid=INVEST_UUID, server='100002', batch='identity'):
        base = f'memory/imports/{batch}/grokbot-agents/not-a-role/'
        name = self.write(base+'agent-name.json', {'uuid':uid, 'name':'irrelevant label'})
        profile = self.write(base+'profile.json', {'serverId':server})
        return name, profile
    def test_exact_exported_uuid_maps_despite_path_label(self):
        text, _ = self.bot()
        binding = resolve_scope_binding(self.root,text)
        self.assertEqual(binding['scope'],'operations')
        self.assertEqual(verify_scope_binding(self.root,binding),'operations')
        self.assertEqual(binding['evidence'][0]['selector'],['agent_id'])
        self.assertNotIn('authorship_verified',binding)
    def test_numeric_registry_bridge_binds_all_three_files(self):
        self.bridge()
        text, _ = self.bot(INVEST_UUID)
        binding = resolve_scope_binding(self.root,text)
        self.assertEqual(binding['scope'],'invest')
        self.assertEqual({x['selector'][0] for x in binding['evidence']},{'agent_id','uuid','serverId'})
        self.assertEqual(verify_scope_binding(self.root,binding),'invest')
    def test_profile_group_resolves_from_content_not_uuid_in_directory(self):
        name, _ = self.bridge()
        self.assertEqual(resolve_scope_binding(self.root,name)['scope'],'invest')
    def test_label_or_javis_role_without_identity_never_maps(self):
        text, _ = self.bot('016b76b6-943b-4fd7-a70d-e76c2c78ebf4',javis_role='gpt-star')
        self.assertIsNone(resolve_scope_binding(self.root,text))
    def test_known_conflicting_role_or_numeric_identity_is_rejected(self):
        text, _ = self.bot(scope='invest')
        self.assertIsNone(resolve_scope_binding(self.root,text))
        self.bridge(OPERATIONS_UUID, '100002')
        text, _ = self.bot()
        self.assertIsNone(resolve_scope_binding(self.root,text))
    def test_bot_metadata_conflicting_runtime_id_does_not_override_uuid(self):
        for field in ('bot_id', 'serverId'):
            text, _ = self.bot(**{field:'100002'})
            self.assertIsNone(resolve_scope_binding(self.root,text))
    def test_two_numeric_bridges_conflict_and_invalidate_old_binding(self):
        self.bridge()
        text, _ = self.bot(INVEST_UUID)
        old = resolve_scope_binding(self.root,text)
        self.bridge(server='100003',batch='conflict')
        self.assertIsNone(resolve_scope_binding(self.root,text))
        with self.assertRaises(ValueError):verify_scope_binding(self.root,old)
    def test_every_dependency_byte_change_invalidates(self):
        name, profile = self.bridge()
        text, meta = self.bot(INVEST_UUID)
        for path in (name, profile, meta):
            old = resolve_scope_binding(self.root,text)
            body = path.read_text()
            path.write_text(body+'\n')
            with self.assertRaises(ValueError):verify_scope_binding(self.root,old)
    def test_parent_privacy_flags_exclude_whole_metadata(self):
        for extra in ({'cloud_eligible':False},{'nested':{'sensitivity':'L4'}},
                      {'ignored':{'api_key':'syntheticsecret'}},{'notes':'[REDACTED:CREDENTIAL]'}):
            text, _ = self.bot(**extra)
            self.assertIsNone(resolve_scope_binding(self.root,text))
    def test_bridge_privacy_changes_revoke_saved_binding(self):
        _, profile = self.bridge()
        text, _ = self.bot(INVEST_UUID)
        old = resolve_scope_binding(self.root,text)
        profile.write_text(json.dumps({'serverId':'100002','cloud_eligible':False}))
        with self.assertRaises(ValueError):verify_scope_binding(self.root,old)
    def test_hardlink_and_symlink_metadata_are_rejected(self):
        for link in ('hard','symbolic'):
            text, meta = self.bot()
            saved = meta.with_suffix('.saved')
            if saved.exists():saved.unlink()
            meta.rename(saved)
            if link=='hard':os.link(saved,meta)
            else:meta.symlink_to(saved)
            self.assertIsNone(resolve_scope_binding(self.root,text))
            meta.unlink()
            saved.unlink()
    def test_linked_parent_and_dotdot_are_rejected(self):
        text, meta = self.bot()
        alias = self.root/'alias'
        alias.symlink_to(meta.parent,target_is_directory=True)
        for path in (alias/'transcript.jsonl',self.root/'memory/../outside'):
            with self.assertRaises(ValueError):resolve_scope_binding(self.root,path)
    def test_binding_cannot_be_forged_across_scope_or_prefix(self):
        text, _ = self.bot()
        binding = resolve_scope_binding(self.root,text)
        for patch in ({'scope':'invest'},{'group_prefix':'memory/imports/export/bots/other'},
                      {'group_prefix':'memory/imports/export/bots/../../outside'}, {'evidence':[]}):
            forged = {**copy.deepcopy(binding),**patch}
            with self.assertRaises(ValueError):verify_scope_binding(self.root,forged)
    def test_index_is_per_call_and_root_bound(self):
        text, _ = self.bot()
        index = scope_index(self.root)
        self.assertEqual(resolve_scope_binding(self.root,text,index=index)['scope'],'operations')
        with tempfile.TemporaryDirectory() as other:
            with self.assertRaises(ValueError):resolve_scope_binding(other,'memory/imports/e/bots/a/a.json',index=index)
    def test_unrecognized_session_group_not_inferred(self):
        text = self.write('memory/imports/export/openclaw-sessions-light/card-master/session.json',{'role':'cards-master'})
        self.assertIsNone(resolve_scope_binding(self.root,text))
    def test_no_writes_occur_during_empty_scan(self):
        self.assertIsNone(resolve_scope_binding(self.root,'memory/imports/e/bots/a/a.json'))
        self.assertEqual(list(self.root.iterdir()),[])


if __name__ == '__main__':unittest.main()
