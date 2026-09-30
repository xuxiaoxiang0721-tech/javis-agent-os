"""Read-only usage HTTP boundaries and actual JS rendering with synthetic records."""
import copy
import json
import shutil
import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import test_control_http as support

CODE = Path(__file__).resolve().parents[1]
APP = CODE / 'tools/control-panel/web/app.js'
sys.path.insert(0, str(CODE / 'tools/memory-adapter'))


def fixture():
    window = {'calls': 2, 'completed': 1, 'pending': 1, 'unknown_usage': 1,
        'unknown_price': 1, 'unpriced_requests': 1,
        'tokens': {'input': None, 'output': None, 'total': None, 'cached': None, 'reasoning': None},
        'usage_coverage': {'complete_requests': 0, 'partial_requests': 0, 'missing_requests': 1},
        'estimated_cost': {'currency': 'CNY', 'kind': 'catalog_estimate', 'amount': None, 'known_amount': '0'},
        'pricing_coverage': {'priced_requests': 0, 'completed_requests': 1, 'fraction': '0'},
        'breakdown': []}
    summary = {'schema_version': 'usage-test', 'timezone': 'Asia/Shanghai',
        'as_of': '2026-09-24T02:00:00Z', 'meter_started_at': None,
        'today': copy.deepcopy(window), 'month': copy.deepcopy(window), 'all': copy.deepcopy(window),
        'integrity': {'invalid_rows': 0, 'conflicting_rows': 0}}
    record = {'started_at': '2026-09-24T01:00:00Z', 'finished_at': None, 'stage': 'embedding',
        'model': 'synthetic-embedding', 'actual_model': None, 'status': 'pending', 'usage_known': False,
        'tokens': {'input': None, 'output': None, 'total': None, 'cached': None, 'reasoning': None},
        'estimated_cost': {'currency': 'CNY', 'kind': 'catalog_estimate', 'amount': None}, 'pricing_status': 'unknown'}
    return {'ok': True, 'summary': summary, 'recent': [record]}


class UsageHTTPTests(unittest.TestCase):
    request = support.HTTPTests.request

    def setUp(self):
        support.HTTPTests.setUp(self)
        self.data = fixture()
        self.calls = []
        self.module = types.ModuleType('javis_memory_adapter.usage_meter')
        def summary(root):
            self.assertEqual(root, self.root)
            self.calls.append('summary')
            return copy.deepcopy(self.data['summary'])
        def recent(root, *, limit):
            self.assertEqual(root, self.root)
            self.assertEqual(limit, 20)
            self.calls.append('recent')
            return copy.deepcopy(self.data['recent'])
        self.module.summary = summary
        self.module.recent = recent
        mock = patch.dict(sys.modules, {'javis_memory_adapter.usage_meter': self.module})
        mock.start()
        self.addCleanup(mock.stop)

    def test_owner_session_required_before_reading_any_usage(self):
        status, result = self.request('/api/memory/usage')
        self.assertEqual(status, 403)
        self.assertNotIn('summary', result)
        self.assertEqual(self.calls, [])

    def test_owner_get_preserves_unknown_and_filters_non_meter_data(self):
        marker = 'synthetic-private-prompt-do-not-return'
        self.data['summary']['prompt'] = marker
        self.data['summary']['today']['messages'] = marker
        self.data['summary']['today']['tokens']['raw_response'] = marker
        self.data['summary']['today']['estimated_cost_by_currency'] = {
            'USD': {'currency': 'USD', 'amount': None, 'known_amount': '0', 'prompt': marker},
            marker: {'currency': marker, 'amount': '1'}}
        self.data['recent'][0].update(prompt=marker, api_key=marker, run_id=marker)
        status, result = self.request('/api/memory/usage', auth=True)
        self.assertEqual(status, 200)
        self.assertTrue(result['read_only'])
        self.assertIsNone(result['summary']['today']['estimated_cost']['amount'])
        self.assertIsNone(result['recent'][0]['tokens']['total'])
        self.assertEqual(set(result['summary']['today']['estimated_cost_by_currency']), {'USD'})
        self.assertNotIn(marker, json.dumps(result))
        self.assertEqual(self.calls, ['summary', 'recent'])

    def test_post_cannot_reset_or_change_prices(self):
        for action in ('reset', 'set_price'):
            status, _ = self.request('/api/memory/usage', {'action': action}, auth=True)
            self.assertEqual(status, 404)
        self.assertEqual(self.calls, [])

    def test_expired_session_cannot_read_usage(self):
        self.app.auth.sessions['test-only-session']['expires'] = 1
        status, _ = self.request('/api/memory/usage', auth=True)
        self.assertEqual(status, 403)
        self.assertEqual(self.calls, [])

    def test_service_socket_cannot_read_owner_usage(self):
        with patch.object(support.panel.Handler, 'boundary', return_value=True):
            status, _ = self.request('/api/memory/usage')
        self.assertEqual(status, 403)
        self.assertEqual(self.calls, [])

    def test_host_and_origin_protection_also_apply_to_usage(self):
        for headers in ({'Host': 'evil.example'}, {'Origin': 'https://evil.example'}):
            status, _ = self.request('/api/memory/usage', auth=True, headers=headers)
            self.assertEqual(status, 403)
        self.assertEqual(self.calls, [])

    def test_multicurrency_projection_keeps_separate_totals_and_no_combined_amount(self):
        for key in ('today', 'month', 'all'):
            row = self.data['summary'][key]
            row['estimated_cost'] = {'currency': None, 'amount': None, 'known_amount': None, 'kind': 'catalog_estimate'}
            row['estimated_cost_by_currency'] = {
                'CNY': {'currency': 'CNY', 'amount': '1.25', 'known_amount': '1.25', 'priced_requests': 1, 'requests': 1},
                'USD': {'currency': 'USD', 'amount': '0.042', 'known_amount': '0.042', 'priced_requests': 1, 'requests': 1}}
        status, result = self.request('/api/memory/usage', auth=True)
        self.assertEqual(status, 200)
        row = result['summary']['all']
        self.assertIsNone(row['estimated_cost']['amount'])
        self.assertIsNone(row['estimated_cost']['currency'])
        self.assertEqual(row['estimated_cost_by_currency']['CNY']['amount'], '1.25')
        self.assertEqual(row['estimated_cost_by_currency']['USD']['amount'], '0.042')


JS_RENDER = r'''
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const source=fs.readFileSync(process.argv[1],'utf8');const data=JSON.parse(process.argv[2]);
class Element{constructor(tag){this.tag=tag;this.children=[];this.textContent='';this.hidden=false;this.disabled=false;}append(...x){this.children.push(...x);}replaceChildren(...x){this.children=x;}}
const nodes=new Map();const get=id=>{if(!nodes.has(id))nodes.set(id,new Element('div'));return nodes.get(id);};
const context={document:{getElementById:get,createElement:t=>new Element(t),querySelectorAll:()=>[]},
  crypto:{randomUUID:()=> 'synthetic'},window:{},setInterval:()=>{},Uint8Array,Map,JSON,Date,Error,
  fetch:async()=>({ok:false,status:403,json:async()=>({error:'synthetic_no_session'})}),data};
vm.createContext(context);vm.runInContext(source,context);vm.runInContext('renderMemoryUsage(data)',context);
const text=e=>[e.textContent,...e.children.map(text)].join(' ');
const cards=text(get('usage-cards'));const recent=text(get('usage-recent'));
assert(cards.includes('今日')&&cards.includes('本月')&&cards.includes('累计'));
assert(cards.includes('金额待核对'));assert(!cards.includes('¥0'));assert(cards.includes('未知用量'));
assert(recent.includes('未知')&&recent.includes('未完成')&&recent.includes('待完成'));
assert(!recent.includes('¥0'));assert(get('usage-coverage').textContent.includes('更早历史未计量'));
assert.equal(vm.runInContext('usageCount(null)',context),'未知');
assert.equal(vm.runInContext('usageMoney(null)',context),'未知');
assert.equal(vm.runInContext('usageWindowTokens(data.summary.today)',context),'未知');
assert.equal(vm.runInContext("usageMoney('0.00000004')",context),'¥0.00000004');
assert.equal(vm.runInContext("usageMoney('4E-8')",context),'¥4E-8');
assert.equal(vm.runInContext("usageMoney('0.042','USD')",context),'US$0.042');
assert.equal(vm.runInContext("usageMoney('1',null)",context),'未知');
data.summary.all.breakdown=[{...data.summary.all,breakdown:undefined,stage:'graphiti',model:'<b>synthetic</b>'}];
data.recent[0].prompt='private-do-not-display';data.summary.prompt='private-do-not-display';
vm.runInContext('renderMemoryUsage(data)',context);
assert(text(get('usage-breakdown')).includes('Graphiti / <b>synthetic</b>'));
assert(!text(get('usage-recent')).includes('private-do-not-display'));
for(const key of ['today','month','all'])data.summary[key]={...data.summary[key],calls:0,completed:0,pending:0,unknown_usage:0,unknown_price:0,unpriced_requests:0,estimated_cost:{currency:'CNY',amount:'0',known_amount:'0'},breakdown:[]};
data.recent=[];vm.runInContext('renderMemoryUsage(data)',context);
assert(text(get('usage-cards')).includes('暂无计量记录'));assert(!text(get('usage-cards')).includes('¥0'));
assert(text(get('usage-recent')).includes('不能据此判断没有费用'));
for(const key of ['today','month','all'])data.summary[key]={...data.summary[key],calls:2,completed:2,
  estimated_cost:{currency:null,amount:null,known_amount:null},pricing_coverage:{priced_requests:2},
  estimated_cost_by_currency:{CNY:{currency:'CNY',amount:'1.25',known_amount:'1.25',priced_requests:1,requests:1},USD:{currency:'USD',amount:'0.042',known_amount:'0.042',priced_requests:1,requests:1}}};
data.recent=[{stage:'screening',model:'jev-1.13.0',status:'success',usage_known:true,tokens:{input:1000000,output:100,total:1000100},estimated_cost:{currency:'USD',amount:'0.042'}}];
vm.runInContext('renderMemoryUsage(data)',context);
assert(text(get('usage-cards')).includes('¥1.25'));assert(text(get('usage-cards')).includes('US$0.042'));
assert(!text(get('usage-cards')).includes('¥1.292'));assert(text(get('usage-cards')).includes('人民币与美元不相加'));
assert(text(get('usage-recent')).includes('US$0.042'));assert(!text(get('usage-recent')).includes('¥0.042'));
for(const key of ['today','month','all']){data.summary[key].pricing_coverage.priced_requests=1;data.summary[key].estimated_cost_by_currency.USD={currency:'USD',amount:null,known_amount:'0',priced_requests:0,requests:1};}
vm.runInContext('renderMemoryUsage(data)',context);
assert(text(get('usage-cards')).includes('US$ 金额待核对'));assert(!text(get('usage-cards')).includes('US$0'));
for(const key of ['today','month','all'])data.summary[key]={...data.summary[key],calls:1,subscription_requests:1,estimated_cost_by_currency:{},estimated_cost:{currency:null,amount:null,known_amount:null}};
data.recent=[{...data.recent[0],billing_mode:'subscription',estimated_cost:{currency:null,amount:null}}];
vm.runInContext('renderMemoryUsage(data)',context);
assert(text(get('usage-cards')).includes('使用订阅额度'));assert(text(get('usage-cards')).includes('其中订阅调用'));
assert(!text(get('usage-cards')).includes('金额待核对'));assert(text(get('usage-recent')).includes('不折算 API 金额'));
console.log('PASS actual usage UI: unknowns, partial costs, history coverage, empty meter, safe text rendering');
'''


class UsageRenderTests(unittest.TestCase):
    def test_real_ui_renders_unknown_without_zero_or_raw_content(self):
        node = shutil.which('node')
        if not node:
            self.fail('Node.js is required to execute the actual usage UI regression')
        result = subprocess.run([node, '-e', JS_RENDER, str(APP), json.dumps(fixture())],
            text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_page_has_clear_readonly_meter_entry_and_billing_explanation(self):
        html = (APP.parent / 'index.html').read_text()
        self.assertIn('data-tab="usage">记忆用量', html)
        self.assertIn('按 API 返回用量估价，实际扣费以云账单为准', html)
        self.assertIn('只读计量', html)
        self.assertIn('人民币与美元分别展示，不做汇率换算', html)
        self.assertNotIn('计价器', html)


class UsageMeterHTTPIntegrationTests(unittest.TestCase):
    setUp = support.HTTPTests.setUp
    request = support.HTTPTests.request

    def test_subscription_usage_projection_preserves_billing_mode(self):
        from javis_memory_adapter.usage_meter import UsageMeter
        meter = UsageMeter(self.root)
        item = meter.start('graphiti', 'gpt-test', 'api.openai.com',
            request_meta={'request_type': 'chat', 'billing_mode': 'subscription'})
        meter.finish(item, response={'model': 'gpt-test', 'usage': {'input_tokens': 10,
            'output_tokens': 2, 'total_tokens': 12}})
        status, result = self.request('/api/memory/usage', auth=True)
        self.assertEqual(status, 200)
        self.assertEqual(result['summary']['all']['subscription_requests'], 1)
        self.assertEqual(result['recent'][0]['billing_mode'], 'subscription')
        self.assertIsNone(result['recent'][0]['estimated_cost']['amount'])

    def test_empty_real_meter_get_is_readonly_and_keeps_unknown_tokens(self):
        before = {str(p.relative_to(self.root)) for p in self.root.rglob('*')}
        status, value = self.request('/api/memory/usage', auth=True)
        self.assertEqual(status, 200, value)
        self.assertEqual(value['summary']['all']['calls'], 0)
        self.assertIsNone(value['summary']['all']['tokens']['total'])
        self.assertEqual(value['recent'], [])
        self.assertEqual({str(p.relative_to(self.root)) for p in self.root.rglob('*')}, before)

    def test_real_ledger_known_unknown_and_pending_are_visible_without_prompt(self):
        from javis_memory_adapter.usage_meter import UsageMeter
        path = self.root / 'config/memory-pricing.json'
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({'version': 'synthetic-test', 'currency': 'CNY', 'prices': [
            {'provider_host': 'synthetic.example', 'model': 'synthetic-priced', 'mode': 'any',
             'input_per_million': '1', 'output_per_million': '2'}]}))
        meter = UsageMeter(self.root)
        known = meter.start('screening', 'synthetic-priced', 'synthetic.example', scope='invest',
            request_meta={'request_type': 'chat', 'enable_thinking': False})
        marker = 'synthetic-private-input-never-persist-or-display'
        meter.finish(known, response={'model': 'synthetic-priced', 'prompt': marker,
            'usage': {'prompt_tokens': 1000, 'completion_tokens': 200, 'total_tokens': 1200},
            'choices': [{'message': {'content': marker}}]})
        code, only_known = self.request('/api/memory/usage', auth=True)
        self.assertEqual(code, 200, only_known)
        self.assertEqual(only_known['summary']['all']['estimated_cost']['amount'], '0.0014')
        unknown = meter.start('graphiti', 'synthetic-unpriced', 'synthetic.example')
        meter.finish(unknown, response={'model': 'synthetic-unpriced', 'prompt': marker}, status='transport_error')
        meter.start('embedding', 'synthetic-embedding', 'synthetic.example')
        status, result = self.request('/api/memory/usage', auth=True)
        self.assertEqual(status, 200, result)
        total = result['summary']['all']
        self.assertEqual(total['calls'], 3)
        self.assertEqual(total['pending'], 1)
        self.assertEqual(total['unknown_usage'], 1)
        self.assertEqual(total['unknown_price'], 1)
        self.assertEqual(total['tokens']['total'], 1200)
        self.assertIsNone(total['estimated_cost']['amount'])
        self.assertEqual(total['estimated_cost']['known_amount'], '0.0014')
        self.assertEqual(total['usage_coverage']['complete_requests'], 1)
        self.assertEqual(total['usage_coverage']['missing_requests'], 1)
        self.assertEqual({r['stage'] for r in total['breakdown']}, {'screening', 'graphiti', 'embedding'})
        self.assertEqual(len(result['recent']), 3)
        self.assertNotIn(marker, json.dumps(result))
        self.assertNotIn(marker, (self.root / 'memory/usage/requests.jsonl').read_text())

    def test_real_mixed_currency_ledger_is_never_returned_as_one_money_total(self):
        from javis_memory_adapter.usage_meter import UsageMeter
        path = self.root / 'config/memory-pricing.json'
        path.parent.mkdir(parents=True)
        path.write_text((CODE / 'config/memory-pricing.json').read_text())
        meter = UsageMeter(self.root)
        cny = meter.start('graphiti', 'qwen-turbo', 'dashscope.aliyuncs.com')
        meter.finish(cny, usage={'prompt_tokens': 1000, 'completion_tokens': 200, 'total_tokens': 1200})
        usd = meter.start('screening', 'jev-1.13.0', 'api.typesafe.ai')
        meter.finish(usd, usage={'input_tokens': 1000, 'output_tokens': 200})
        status, result = self.request('/api/memory/usage', auth=True)
        self.assertEqual(status, 200, result)
        total = result['summary']['all']
        self.assertIsNone(total['estimated_cost']['amount'])
        self.assertIsNone(total['estimated_cost']['known_amount'])
        self.assertIsNone(total['estimated_cost']['currency'])
        self.assertEqual(total['estimated_cost_by_currency']['CNY']['amount'], '0.00042')
        self.assertEqual(total['estimated_cost_by_currency']['USD']['amount'], '0.000042')
        self.assertEqual({row['estimated_cost']['currency'] for row in result['recent']}, {'CNY', 'USD'})


if __name__ == '__main__':
    unittest.main(verbosity=2)
