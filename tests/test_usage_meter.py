import json
import multiprocessing
import os
from pathlib import Path
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest.mock import patch

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE / 'tools/memory-adapter'))
from javis_memory_adapter import usage_meter as um

HOST = 'dashscope.aliyuncs.com'
MODEL = 'qwen-turbo'
USAGE = {'prompt_tokens': 100, 'completion_tokens': 20, 'total_tokens': 120}


def _parallel_request(root, index):
    meter = um.UsageMeter(root)
    aid = meter.start('graphiti', MODEL, HOST, run_id='test_' + str(index))
    meter.finish(aid, usage=USAGE, actual_model=MODEL, provider_request_id='same-provider-id')


def _parallel_finish(root, attempt):
    um.UsageMeter(root).finish(attempt, usage=USAGE, actual_model=MODEL)


class UsageMeterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.meter = um.UsageMeter(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def catalog(self, version='prices-v1', **rates):
        path = self.root / 'config/memory-pricing.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        entry = {'provider_host': HOST, 'model': MODEL, 'mode': 'any',
                 'input_per_million': '0.3', 'output_per_million': '0.6',
                 'thinking_output_per_million': '3.0', **rates}
        value = {'schema_version': 'javis-memory-pricing-1', 'version': version,
                 'currency': 'CNY', 'source_url': 'https://help.aliyun.com/zh/model-studio/deep-thinking',
                 'prices': [entry]}
        path.write_text(json.dumps(value))
        return path

    def start(self, **extra):
        return self.meter.start(extra.pop('stage', 'screening'), extra.pop('model', MODEL),
                                extra.pop('provider_host', HOST), **extra)

    def ledger(self):
        return [json.loads(s) for s in (self.root / 'memory/usage/requests.jsonl').read_text().splitlines()]

    def test_read_only_empty_summary_never_initializes_or_claims_free_usage(self):
        result = um.summary(self.root)
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertIsNone(result['meter_started_at'])
        self.assertEqual(result['all']['calls'], 0)
        self.assertIsNone(result['all']['tokens']['total'])
        self.assertEqual(um.recent(self.root), [])

    def test_initialize_creates_only_activation_metadata_idempotently(self):
        one = um.initialize(self.root)
        two = um.initialize(self.root)
        self.assertEqual(one, two)
        self.assertFalse((self.root / 'memory/usage/requests.jsonl').exists())
        self.assertEqual(um.summary(self.root)['meter_started_at'], one['started_at'])

    def test_exact_usage_and_decimal_catalog_estimate(self):
        self.catalog()
        aid = self.start(scope='cards-master', run_id='screen_test')
        result = self.meter.finish(aid, usage=USAGE, actual_model=MODEL, duration_ms=12.5, http_status=200)
        self.assertEqual(result['tokens']['total'], 120)
        self.assertEqual(result['estimated_cost']['amount'], '0.000042')
        summary = um.summary(self.root)['all']
        self.assertEqual(summary['calls'], 1)
        self.assertEqual(summary['estimated_cost']['amount'], '0.000042')
        self.assertEqual(summary['pricing_coverage']['fraction'], '1')
        self.assertEqual(summary['breakdown'][0]['stage'], 'screening')
        self.assertEqual(self.ledger()[0]['pricing']['catalog_version'], 'prices-v1')

    def test_no_price_and_no_usage_remain_unknown(self):
        aid = self.start()
        result = self.meter.finish(aid, status='http_error', http_status=429)
        self.assertIsNone(result['tokens']['total'])
        self.assertIsNone(result['estimated_cost']['amount'])
        total = um.summary(self.root)['all']
        self.assertEqual((total['unknown_usage'], total['unknown_price'], total['unpriced_requests']), (1, 1, 1))
        self.assertIsNone(total['tokens']['input'])
        self.assertIsNone(total['estimated_cost']['amount'])

    def test_unknown_host_model_mode_or_actual_model_never_gets_guessed_price(self):
        self.catalog(mode='non_thinking')
        ids = [self.start(provider_host='unlisted.example'), self.start(model='unlisted-model'), self.start()]
        for aid in ids:
            self.assertIsNone(self.meter.finish(aid, usage=USAGE)['estimated_cost']['amount'])
        known = self.start(request_meta={'enable_thinking': False})
        result = self.meter.finish(known, usage=USAGE, actual_model='different-model')
        self.assertIsNone(result['estimated_cost']['amount'])
        self.assertEqual(result['estimated_cost']['reason'], 'actual_model_differs_from_price_snapshot')

    def typesafe_catalog(self):
        path = self.catalog()
        value = json.loads(path.read_text())
        value['prices'].append({'provider_host': 'api.typesafe.ai', 'model': 'jev-1.13.0',
            'mode': 'any', 'currency': 'USD', 'input_per_million': '0.042',
            'output_per_million': '0', 'source_url': 'https://docs.typesafe.ai/models'})
        path.write_text(json.dumps(value))
        return path

    def test_jev_exact_catalog_entry_uses_usd_with_zero_output_rate(self):
        self.typesafe_catalog()
        aid = self.start(model='jev-1.13.0', provider_host='api.typesafe.ai')
        result = self.meter.finish(aid, usage={'input_tokens': 1000000, 'output_tokens': 1200}, actual_model='jev-1.13.0')
        self.assertEqual(result['estimated_cost']['currency'], 'USD')
        self.assertEqual(result['estimated_cost']['amount'], '0.042')
        self.assertEqual(result['tokens']['total'], 1001200)
        snapshot = self.ledger()[0]['pricing']
        self.assertEqual(snapshot['currency'], 'USD')
        self.assertEqual(snapshot['entry']['currency'], 'USD')
        self.assertEqual(snapshot['entry']['source_url'], 'https://docs.typesafe.ai/models')
        total = um.summary(self.root)['all']
        self.assertEqual(total['estimated_cost']['currency'], 'USD')
        self.assertEqual(total['estimated_cost_by_currency']['USD']['amount'], '0.042')

    def test_mixed_cny_usd_totals_never_add_or_convert(self):
        self.typesafe_catalog()
        self.meter.finish(self.start(), usage=USAGE)
        self.meter.finish(self.start(model='jev-1.13.0', provider_host='api.typesafe.ai'),
                          usage={'input_tokens': 1000, 'output_tokens': 100})
        result = um.summary(self.root)['all']
        self.assertEqual(result['estimated_cost'], {'currency': None, 'kind': 'catalog_estimate',
                                                  'known_amount': None, 'amount': None})
        self.assertEqual(result['estimated_cost_by_currency']['CNY']['amount'], '0.000042')
        self.assertEqual(result['estimated_cost_by_currency']['USD']['amount'], '0.000042')
        self.assertEqual({r['estimated_cost']['currency'] for r in um.recent(self.root)}, {'CNY', 'USD'})
        self.assertEqual({r['estimated_cost']['currency'] for r in result['breakdown']}, {'CNY', 'USD'})
        self.assertEqual(result['pricing_coverage']['priced_requests'], 2)

    def test_pending_and_unknown_currency_never_become_free_in_mixed_totals(self):
        self.typesafe_catalog()
        self.meter.finish(self.start(), usage=USAGE)
        self.start(model='jev-1.13.0', provider_host='api.typesafe.ai')
        result = um.summary(self.root)['all']
        self.assertEqual(result['estimated_cost_by_currency']['USD']['priced_requests'], 0)
        self.assertIsNone(result['estimated_cost_by_currency']['USD']['amount'])
        self.assertEqual(result['estimated_cost_by_currency']['CNY']['amount'], '0.000042')
        unknown = self.meter.finish(self.start(model='unlisted', provider_host='unlisted.example'), usage=USAGE)
        self.assertIsNone(unknown['estimated_cost']['currency'])
        result = um.summary(self.root)['all']
        self.assertEqual(result['unknown_currency_requests'], 1)
        self.assertIsNone(result['estimated_cost_by_currency']['CNY']['amount'])
        self.assertIsNone(result['estimated_cost_by_currency']['USD']['amount'])
        self.assertEqual(result['estimated_cost_by_currency']['CNY']['known_amount'], '0.000042')

    def test_catalog_currency_change_never_reprices_old_cny_requests(self):
        path = self.catalog()
        aid = self.start()
        old_bytes = (self.root / 'memory/usage/requests.jsonl').read_bytes()
        value = json.loads(path.read_text())
        value.update(currency='USD', version='different-currency-v2')
        path.write_text(json.dumps(value))
        first = self.meter.finish(aid, usage=USAGE)
        second = self.meter.finish(self.start(), usage=USAGE)
        self.assertEqual(first['estimated_cost']['currency'], 'CNY')
        self.assertEqual(second['estimated_cost']['currency'], 'USD')
        self.assertTrue((self.root / 'memory/usage/requests.jsonl').read_bytes().startswith(old_bytes))
        self.assertIsNone(um.summary(self.root)['all']['estimated_cost']['amount'])

    def test_unrecognized_currency_fails_to_unknown_and_cannot_be_spent_as_cny(self):
        self.catalog(currency='WRONG')
        row = self.meter.finish(self.start(), usage=USAGE)
        self.assertIsNone(row['estimated_cost']['currency'])
        self.assertIsNone(row['estimated_cost']['amount'])
        self.assertEqual(um.summary(self.root)['all']['estimated_cost_by_currency'], {})

    def test_existing_cny_snapshot_without_entry_currency_remains_valid(self):
        self.catalog()
        self.meter.finish(self.start(), usage=USAGE)
        rows = self.ledger()
        rows[0]['pricing']['entry'].pop('currency')
        # Construct the previous release's valid record shape, not a live ledger edit.
        (self.root / 'memory/usage/requests.jsonl').unlink()
        for row in rows:
            row.pop('record_sha256')
            um._append(self.root, row)
        self.typesafe_catalog()
        result = um.summary(self.root)['all']
        self.assertEqual(result['estimated_cost']['currency'], 'CNY')
        self.assertEqual(result['estimated_cost']['amount'], '0.000042')

    def test_shipped_catalog_contains_only_exact_verified_jev_usd_price(self):
        value = json.loads((CODE / 'config/memory-pricing.json').read_text())
        jev = [row for row in value['prices'] if row.get('provider_host') == 'api.typesafe.ai']
        self.assertEqual(len(jev), 1)
        self.assertEqual(jev[0]['model'], 'jev-1.13.0')
        self.assertEqual((jev[0]['currency'], jev[0]['input_per_million'], jev[0]['output_per_million']), ('USD', '0.042', '0'))
        self.assertIn('https://docs.typesafe.ai/models', value['sources'])

    def test_price_snapshot_does_not_change_after_catalog_update(self):
        self.catalog()
        aid = self.start()
        self.catalog(version='prices-v2', input_per_million='300', output_per_million='600')
        result = self.meter.finish(aid, usage=USAGE)
        self.assertEqual(result['estimated_cost']['amount'], '0.000042')
        second = self.meter.finish(self.start(), usage=USAGE)
        self.assertEqual(second['estimated_cost']['amount'], '0.042')
        self.assertEqual(self.ledger()[0]['pricing']['catalog_version'], 'prices-v1')

    def test_thinking_rate_applies_to_entire_output_without_double_count(self):
        self.catalog()
        aid = self.start(request_meta={'enable_thinking': True})
        result = self.meter.finish(aid, usage={**USAGE,
            'prompt_tokens_details': {'cached_tokens': 80},
            'completion_tokens_details': {'reasoning_tokens': 15}})
        self.assertEqual(result['tokens'], {'input': 100, 'output': 20, 'total': 120, 'cached': 80, 'reasoning': 15})
        self.assertEqual(result['estimated_cost']['amount'], '0.00009')
        self.assertEqual(um.summary(self.root)['all']['tokens']['total'], 120)

    def test_embedding_total_only_is_input_but_chat_total_only_is_partial(self):
        self.catalog(model='text-embedding-v3', input_per_million='0.5', output_per_million='0')
        aid = self.start(stage='embedding', model='text-embedding-v3')
        result = self.meter.finish(aid, usage={'total_tokens': 40})
        self.assertTrue(result['usage_known'])
        self.assertEqual(result['tokens']['input'], 40)
        self.assertEqual(result['tokens']['output'], 0)
        self.assertEqual(result['estimated_cost']['amount'], '0.00002')
        chat = self.meter.finish(self.start(), usage={'total_tokens': 40})
        self.assertIsNone(chat['tokens']['input'])
        self.assertFalse(chat['usage_known'])

    def test_cached_reasoning_invalid_subsets_do_not_inflate_tokens_or_price(self):
        self.catalog()
        result = self.meter.finish(self.start(), usage={**USAGE,
            'cached_tokens': 1000, 'reasoning_tokens': 1000})
        self.assertEqual(result['tokens']['total'], 120)
        self.assertIsNone(result['tokens']['cached'])
        self.assertIsNone(result['estimated_cost']['amount'])

    def test_pending_after_crash_and_finish_failure_never_replays_request(self):
        aid = self.start()
        self.assertEqual(um.summary(self.root)['all']['pending'], 1)
        with patch.object(um, '_append', side_effect=OSError('synthetic disk failure')):
            with self.assertRaises(OSError):
                self.meter.finish(aid, usage=USAGE)
        self.assertEqual(um.recent(self.root)[0]['status'], 'pending')
        self.assertEqual(um.summary(self.root)['all']['calls'], 1)

    def test_start_failure_propagates_before_network_caller_can_proceed(self):
        with patch.object(um, '_append', side_effect=OSError('synthetic disk failure')):
            with self.assertRaises(OSError):
                self.start()
        self.assertFalse((self.root / 'memory/usage/requests.jsonl').exists())

    def test_finish_replay_keeps_first_terminal_and_duplicate_provider_ids_are_distinct(self):
        self.catalog()
        first = self.start()
        initial = self.meter.finish(first, usage=USAGE, provider_request_id='same-id')
        replay = self.meter.finish(first, usage={'total_tokens': 9999}, status='http_error')
        self.assertEqual(initial, replay)
        second = self.start()
        self.meter.finish(second, usage=USAGE, provider_request_id='same-id')
        self.assertEqual(um.summary(self.root)['all']['calls'], 2)
        self.assertEqual(len(self.ledger()), 4)

    def test_concurrent_processes_and_concurrent_finish_are_idempotent(self):
        self.catalog()
        context = multiprocessing.get_context('fork')
        processes = [context.Process(target=_parallel_request, args=(str(self.root), n)) for n in range(10)]
        for p in processes: p.start()
        for p in processes:
            p.join(10)
            self.assertEqual(p.exitcode, 0)
        aid = self.start()
        processes = [context.Process(target=_parallel_finish, args=(str(self.root), aid)) for _ in range(5)]
        for p in processes: p.start()
        for p in processes:
            p.join(10)
            self.assertEqual(p.exitcode, 0)
        result = um.summary(self.root)['all']
        self.assertEqual(result['calls'], 11)
        self.assertEqual(result['completed'], 11)
        self.assertEqual(result['tokens']['total'], 1320)
        self.assertEqual(len(self.ledger()), 22)

    def test_shanghai_day_and_month_boundaries_use_request_start(self):
        for stamp in ('2026-08-31T15:59:59Z', '2026-08-31T16:00:00Z', '2026-09-23T15:59:59Z', '2026-09-23T16:00:00Z'):
            with patch.object(um, '_now', return_value=stamp):
                self.meter.finish(self.start(), usage=USAGE)
        result = um.summary(self.root, now='2026-09-24T01:00:00+08:00')
        self.assertEqual(result['today']['calls'], 1)
        self.assertEqual(result['month']['calls'], 3)
        self.assertEqual(result['all']['calls'], 4)

    def test_as_of_before_finish_reports_pending(self):
        with patch.object(um, '_now', return_value='2026-09-23T16:00:00Z'):
            aid = self.start()
        with patch.object(um, '_now', return_value='2026-09-23T16:02:00Z'):
            self.meter.finish(aid, usage=USAGE)
        self.assertEqual(um.summary(self.root, now='2026-09-23T16:01:00Z')['today']['pending'], 1)

    def test_metadata_allowlist_never_persists_provider_body_or_key(self):
        self.catalog()
        secret = 'SUPER_PRIVATE_PROMPT_AND_KEY'
        aid = self.start(request_meta={'enable_thinking': False, 'prompt': secret, 'api_key': secret, 'messages': [secret]})
        self.meter.finish(aid, response={'model': MODEL, 'content': secret,
            'usage': {**USAGE, 'prompt': secret}, 'authorization': secret})
        text = (self.root / 'memory/usage/requests.jsonl').read_text()
        self.assertNotIn(secret, text)
        self.assertNotIn(secret, json.dumps(um.recent(self.root)))
        self.assertNotIn(secret, json.dumps(um.summary(self.root)))

    def test_malformed_tokens_are_unknown_not_zero_and_do_not_persist_strings(self):
        secret = 'private-value'
        row = self.meter.finish(self.start(), usage={'prompt_tokens': secret, 'completion_tokens': -1, 'total_tokens': True})
        self.assertFalse(row['usage_known'])
        self.assertIsNone(row['tokens']['total'])
        self.assertNotIn(secret, (self.root / 'memory/usage/requests.jsonl').read_text())

    def test_partial_usage_does_not_show_unknown_dimensions_as_zero(self):
        self.meter.finish(self.start(), usage={'prompt_tokens': 15})
        result = um.summary(self.root)['all']
        self.assertEqual(result['tokens']['input'], 15)
        self.assertIsNone(result['tokens']['total'])
        self.assertEqual(result['usage_coverage']['partial_requests'], 1)
        empty = self.meter.finish(self.start(stage='embedding'), usage={})
        self.assertIsNone(empty['tokens']['output'])

    def test_conflicting_provider_total_is_not_summed_as_known(self):
        row = self.meter.finish(self.start(), usage={**USAGE, 'total_tokens': 999})
        self.assertIsNone(row['tokens']['total'])
        self.assertFalse(row['usage_known'])
        self.assertIsNone(um.summary(self.root)['all']['tokens']['total'])
        self.assertEqual(self.ledger()[1]['provider_usage']['total_tokens'], 999)

    def test_read_cache_parses_only_new_tail_and_reuses_unchanged_ledger(self):
        self.meter.finish(self.start(), usage=USAGE)
        um.summary(self.root)
        original = um._parse_lines
        with patch.object(um, '_parse_lines', wraps=original) as parse:
            um.summary(self.root)
            um.recent(self.root)
            self.assertEqual(parse.call_count, 0)
            self.start()
            result = um.summary(self.root)
            self.assertEqual(parse.call_count, 1)
            self.assertEqual(len(parse.call_args.args[0].splitlines()), 1)
            self.assertEqual(result['all']['calls'], 2)

    def test_cache_detects_prefix_tampering_even_when_attacker_also_appends(self):
        self.meter.finish(self.start(), usage=USAGE)
        um.summary(self.root)
        path = self.root / 'memory/usage/requests.jsonl'
        original = path.read_bytes()
        tampered = original.replace(b'"total_tokens":120', b'"total_tokens":999')
        self.assertNotEqual(original, tampered)
        path.write_bytes(tampered)
        self.start()
        result = um.summary(self.root)
        self.assertEqual(result['integrity']['invalid_rows'], 1)
        self.assertEqual(result['all']['calls'], 2)
        self.assertEqual(result['all']['pending'], 2)
        self.assertIsNone(result['all']['tokens']['total'])

    def test_cache_detects_truncation_and_replacement(self):
        self.meter.finish(self.start(), usage=USAGE)
        um.summary(self.root)
        path = self.root / 'memory/usage/requests.jsonl'
        first = path.read_bytes().splitlines(keepends=True)[0]
        path.write_bytes(first)
        self.assertEqual(um.summary(self.root)['all']['pending'], 1)
        replacement = path.with_suffix('.new')
        replacement.write_bytes(b'')
        replacement.replace(path)
        self.assertEqual(um.summary(self.root)['all']['calls'], 0)

    def test_concurrent_threads_observe_consistent_cached_snapshots(self):
        def worker(index):
            self.meter.finish(self.start(run_id='thread_' + str(index)), usage=USAGE)
            return um.summary(self.root)['all']['calls']
        with ThreadPoolExecutor(max_workers=6) as executor:
            result = list(executor.map(worker, range(18)))
        self.assertTrue(all(1 <= count <= 18 for count in result))
        self.assertEqual(um.summary(self.root)['all']['completed'], 18)

    def test_corrupt_and_injected_ledger_rows_are_visible_but_never_exposed(self):
        self.meter.finish(self.start(), usage=USAGE)
        path = self.root / 'memory/usage/requests.jsonl'
        rows = self.ledger()
        altered = {**rows[1], 'provider_request_id': 'private leaked body with spaces'}
        with path.open('a') as handle:
            handle.write(json.dumps(altered) + '\n{broken tail')
        before = path.read_bytes()
        self.start()
        self.assertTrue(path.read_bytes().startswith(before))
        result = um.summary(self.root)
        self.assertEqual(result['integrity']['invalid_rows'], 2)
        self.assertNotIn('private leaked', json.dumps(um.recent(self.root)))

    def test_symlink_and_hardlink_ledger_are_rejected(self):
        self.start()
        path = self.root / 'memory/usage/requests.jsonl'
        other = self.root / 'linked.jsonl'
        os.link(path, other)
        with self.assertRaises(ValueError): self.start()
        with self.assertRaises(ValueError): um.summary(self.root)
        other.unlink()
        path.rename(other)
        path.symlink_to(other)
        with self.assertRaises(ValueError): self.start()
        with self.assertRaises(ValueError): um.recent(self.root)


if __name__ == '__main__':
    unittest.main()
