"""Corpus source revalidation at screening and owner-review boundaries.

Only synthetic local fixtures are used. Invalid sources must fail before either
the Jev or Graphiti stub is reached; no API credentials or network are needed.
"""
import json
from pathlib import Path
import sys
import tempfile
import unittest

CODE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(CODE/'scripts'), str(CODE/'tools/memory-adapter')]
from memory_corpus import inventory, build_event, sha
from memory_screen import _source, load_source, screen
from raw_storage import append_event
from javis_memory_adapter.review_policy import digest, source_digests, ReviewBlocked


class NoCloudClient:
    def __init__(self):self.calls = 0
    async def evaluate(self, *args, **kwargs):
        self.calls += 1
        raise AssertionError('synthetic source reached Jev')


class NoGraphClient:
    def __init__(self):self.calls = 0
    async def extract(self, **kwargs):
        self.calls += 1
        raise AssertionError('synthetic source reached Graphiti')


class CorpusPipelineIntegrationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='corpus-source-boundary-')
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
    def write(self, relative, row):
        path = self.root/relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(row)+'\n', encoding='utf-8')
        return path
    def materialize(self, predicate=lambda item: True):
        item = next(item for item in inventory(self.root)['items']
                    if item['route']=='candidate' and predicate(item))
        canonical = build_event(self.root, item)
        append_event(self.root, canonical, relative_path='events/synthetic-corpus.jsonl')
        return load_source(self.root, canonical['event_id'])
    def import_fixture(self):
        path = self.write('memory/imports/synthetic.jsonl',
            {'agent':'invest', 'body_full':'Synthetic complete source with its original conditions.'})
        return path, self.materialize()
    async def blocked(self, event):
        model, graph = NoCloudClient(), NoGraphClient()
        with self.assertRaises(ValueError):
            await screen(self.root, event_id=event['event_id'], scope=event['agent'],
                text=event['payload']['text'], source_digest=digest(event), model_client=model,
                graph_client=graph, model='jev-1.13.0', env_path=self.root/'unused.env',
                learning_version='baseline')
        self.assertEqual((model.calls, graph.calls), (0, 0))
        with self.assertRaisesRegex(ReviewBlocked, 'corpus_original_source_changed_or_unavailable'):
            source_digests(self.root, [event['event_id']])
        self.assertFalse((self.root/'memory/screen/runs.jsonl').exists())
    async def test_unchanged_corpus_is_accepted_by_screen_and_owner_source_guards(self):
        _, event = self.import_fixture()
        self.assertEqual(_source(self.root, event['event_id'], event['payload']['text'], digest(event)), event)
        self.assertEqual(source_digests(self.root, [event['event_id']]), {event['event_id']:digest(event)})
        self.assertFalse(event['payload']['authorship_verified'])
        self.assertFalse(event['payload']['confirmation_authority'])
    async def test_original_text_changed_blocks_before_any_model_or_owner_source_use(self):
        path, event = self.import_fixture()
        canonical_before = digest(load_source(self.root, event['event_id']))
        path.write_text(json.dumps({'agent':'invest','body_full':'Synthetic corrected original.'})+'\n')
        await self.blocked(event)
        self.assertEqual(digest(load_source(self.root, event['event_id'])), canonical_before)
    async def test_original_parent_cloud_false_blocks_bound_object_everywhere(self):
        body = b'Synthetic whole artifact body.'
        content_hash = sha(body)
        obj = self.root/'raw/objects'/content_hash
        obj.parent.mkdir(parents=True)
        obj.write_bytes(body)
        self.write('raw/manifests/synthetic.jsonl',
            {'sha256':content_hash,'object_path':str(obj.relative_to(self.root))})
        parent = {'event_id':'synthetic-parent','event_type':'native_final_output','agent':'invest',
                  'payload':{'native_final_output_sha256':content_hash}}
        path = self.write('raw/events/parent.jsonl', parent)
        event = self.materialize(lambda item:item.get('event_type')=='bound_object')
        parent['cloud_eligible'] = False
        path.write_text(json.dumps(parent)+'\n')
        await self.blocked(event)
    async def test_scope_metadata_change_blocks_before_any_model_or_owner_source_use(self):
        base = 'memory/imports/synthetic/bots/arbitrary-label/'
        metadata = self.write(base+'BOT-META.json', {'agent_id':'00000000-0000-4000-8000-000000000001'})
        self.write(base+'conversation.jsonl', {'role':'user','text':'Synthetic original conversation.'})
        event = self.materialize()
        self.assertEqual(event['agent'],'operations')
        metadata.write_text(json.dumps({'agent_id':'00000000-0000-4000-8000-000000000006'})+'\n')
        await self.blocked(event)
    async def test_forged_canonical_authority_cannot_bypass_by_supplying_new_raw_digest(self):
        _, event = self.import_fixture()
        event['payload']['authorship_verified'] = True
        self.write('raw/events/synthetic-corpus.jsonl', event)
        await self.blocked(event)


if __name__ == '__main__':unittest.main()
