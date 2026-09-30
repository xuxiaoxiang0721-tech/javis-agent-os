"""Append-only accounting for physical provider requests, never request bodies.

Prices are optional catalog estimates in their original currency, frozen at start.
Missing provider usage or price information remains unknown, never zero-priced.
"""
from __future__ import annotations

from collections import defaultdict, OrderedDict
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import threading
import uuid
from zoneinfo import ZoneInfo

from .review_policy import guarded_path

SCHEMA = 'javis-memory-usage-1'
SHANGHAI = ZoneInfo('Asia/Shanghai')
STATUSES = {'success', 'http_error', 'transport_error', 'cancelled', 'invalid_response'}
LABEL = re.compile(r'^[A-Za-z0-9_.:/-]{1,160}$')
HOST = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?)(?::[0-9]{1,5})?$')
MAX_TOKENS = 10**15
RATE_KEYS = ('input_per_million', 'output_per_million', 'thinking_output_per_million', 'cached_input_per_million')
CURRENCIES = frozenset({'CNY', 'USD'})
_READ_CACHE = OrderedDict()
_READ_CACHE_LOCK = threading.RLock()


def _now():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def _time(value):
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str):
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    else:
        raise ValueError('invalid_usage_timestamp')
    if result.tzinfo is None:
        raise ValueError('usage_timestamp_requires_timezone')
    return result


def _label(value, *, optional=False):
    if optional and value is None:
        return None
    if (not isinstance(value, str) or not LABEL.fullmatch(value)
            or re.search(r'(?:sk-[A-Za-z0-9_-]{10,}|gh[pousr]_[A-Za-z0-9]{20,})', value)):
        raise ValueError('invalid_usage_metadata_label')
    return value


def _host(value):
    if not isinstance(value, str) or not HOST.fullmatch(value):
        raise ValueError('invalid_usage_provider_host')
    return value.lower()


def _decimal(value):
    if not isinstance(value, (str, int, Decimal)) or isinstance(value, bool):
        raise ValueError('invalid_usage_rate')
    try:
        result = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError('invalid_usage_rate') from exc
    if not result.is_finite() or result < 0 or result > Decimal('1000000000'):
        raise ValueError('invalid_usage_rate')
    return result


def _money(value):
    return format(value, 'f')


@contextmanager
def _lock(root, *, shared=False):
    path = guarded_path(root, root / 'state/locks/memory-usage.lock')
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(guarded_path(root, path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        if os.fstat(fd).st_nlink != 1:
            raise ValueError('hardlinked_usage_lock')
        fcntl.flock(fd, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _append(root, row):
    path = guarded_path(root, root / 'memory/usage/requests.jsonl')
    path.parent.mkdir(parents=True, exist_ok=True)
    row = dict(row)
    row['record_sha256'] = hashlib.sha256(json.dumps(row, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    encoded = (json.dumps(row, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
    fd = os.open(guarded_path(root, path), os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        if os.fstat(fd).st_nlink != 1:
            raise ValueError('hardlinked_usage_ledger')
        size = os.lseek(fd, 0, os.SEEK_END)
        if size:
            os.lseek(fd, -1, os.SEEK_END)
            if os.read(fd, 1) != b'\n':
                # Preserve incomplete bytes; a parse issue remains visible in summary.
                os.write(fd, b'\n')
        view = memoryview(encoded)
        while view:
            written = os.write(fd, view)
            if not written:
                raise OSError('usage_ledger_write_failed')
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _initialize_locked(root):
    path = guarded_path(root, root / 'memory/usage/meter.json')
    if path.exists():
        row = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(row, dict) or row.get('schema_version') != SCHEMA:
            raise ValueError('invalid_usage_meter_metadata')
        _time(row['started_at'])
        return {'schema_version': SCHEMA, 'started_at': row['started_at'], 'historical_backfill': False}
    row = {'schema_version': SCHEMA, 'started_at': _now(), 'historical_backfill': False}
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = guarded_path(root, path.parent / ('.meter-' + uuid.uuid4().hex))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(row, stream)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, guarded_path(root, path))
    finally:
        if temp.exists():
            temp.unlink()
    return row


def initialize(root):
    """Mark metering activation without recording or inventing an API call."""
    root = Path(root).resolve()
    with _lock(root):
        return _initialize_locked(root)


def _request_meta(value):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError('invalid_usage_request_metadata')
    out = {}
    if 'billing_mode' in value:
        if value['billing_mode'] not in {'api', 'subscription'}:
            raise ValueError('invalid_usage_billing_mode')
        out['billing_mode'] = value['billing_mode']
    if 'enable_thinking' in value:
        if type(value['enable_thinking']) is not bool:
            raise ValueError('invalid_usage_thinking_mode')
        out['enable_thinking'] = value['enable_thinking']
    if 'request_type' in value:
        if value['request_type'] not in {'chat', 'embedding'}:
            raise ValueError('invalid_usage_request_type')
        out['request_type'] = value['request_type']
    if 'operation' in value:
        out['operation'] = _label(value['operation'])
    if 'batch_size' in value:
        if type(value['batch_size']) is not int or not 0 <= value['batch_size'] <= 1000000:
            raise ValueError('invalid_usage_batch_size')
        out['batch_size'] = value['batch_size']
    return out


def _price(root, host, model, meta):
    mode = ('thinking' if meta['enable_thinking'] else 'non_thinking') if 'enable_thinking' in meta else 'unknown'
    unknown = {'status': 'unknown', 'currency': None, 'mode': mode, 'reason': 'price_not_configured'}
    if meta.get('billing_mode') == 'subscription':
        return {**unknown, 'reason': 'subscription_plan_usage'}
    path = guarded_path(root, root / 'config/memory-pricing.json')
    if not path.exists():
        return unknown
    try:
        catalog = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(catalog, dict) or catalog.get('currency') not in CURRENCIES or not isinstance(catalog.get('prices'), list):
            raise ValueError('invalid_catalog')
        version = _label(catalog.get('version'))
        matches = []
        for entry in catalog['prices']:
            if not isinstance(entry, dict):
                continue
            if entry.get('provider_host') == host and entry.get('model') == model and entry.get('mode') in {mode, 'any'}:
                matches.append(entry)
        exact = [r for r in matches if r.get('mode') == mode]
        matches = exact or matches
        if len(matches) != 1:
            return {**unknown, 'reason': 'price_match_missing_or_ambiguous', 'catalog_version': version}
        entry = matches[0]
        currency = entry.get('currency', catalog['currency'])
        if currency not in CURRENCIES:
            raise ValueError('unsupported_catalog_currency')
        if 'input_per_million' not in entry or 'output_per_million' not in entry:
            raise ValueError('missing_catalog_rate')
        safe = {key: _money(_decimal(entry[key])) for key in RATE_KEYS if key in entry}
        safe.update(provider_host=host, model=model, mode=entry['mode'], currency=currency)
        source_url = entry.get('source_url') or catalog.get('source_url')
        # Documentation only: reject query strings, fragments and embedded credentials.
        if isinstance(source_url, str) and re.fullmatch(r'https://[A-Za-z0-9.-]+/[A-Za-z0-9_./%~-]*', source_url) and len(source_url) <= 500:
            safe['source_url'] = source_url
        return {'status': 'known', 'currency': currency, 'mode': mode,
            'catalog_version': version, 'entry': safe,
            'snapshot_sha256': hashlib.sha256(json.dumps(safe, sort_keys=True).encode()).hexdigest()}
    except (ValueError, TypeError, KeyError, OSError):
        return {**unknown, 'reason': 'invalid_price_catalog'}


def _get(value, name):
    return value.get(name) if isinstance(value, dict) else getattr(value, name, None)


def _usage(value, embedding):
    empty = {key: None for key in ('input', 'output', 'total', 'cached', 'reasoning')}
    if value is None:
        return empty, False, {}, ['provider_usage_missing']
    if not isinstance(value, dict):
        if callable(getattr(value, 'model_dump', None)):
            value = value.model_dump()
        elif hasattr(value, '__dict__'):
            value = vars(value)
    if not isinstance(value, dict):
        return empty, False, {}, ['invalid_provider_usage']
    safe, errors = {}, []
    def count(obj, key):
        if not isinstance(obj, dict) or key not in obj or obj[key] is None:
            return None
        item = obj[key]
        if type(item) is not int or not 0 <= item <= MAX_TOKENS:
            errors.append('invalid_token_count')
            return None
        return item
    def aliases(*keys):
        found = []
        for key in keys:
            number = count(value, key)
            if number is not None:
                safe[key] = number
                found.append(number)
        if len(set(found)) > 1:
            errors.append('conflicting_token_aliases')
            return None
        return found[0] if found else None
    inp = aliases('prompt_tokens', 'input_tokens')
    output = aliases('completion_tokens', 'output_tokens')
    total = aliases('total_tokens')
    cached = aliases('cached_tokens')
    reasoning = aliases('reasoning_tokens')
    for parent, child, target in (
        ('prompt_tokens_details', 'cached_tokens', 'cached'),
        ('input_tokens_details', 'cached_tokens', 'cached'),
        ('completion_tokens_details', 'reasoning_tokens', 'reasoning'),
        ('output_tokens_details', 'reasoning_tokens', 'reasoning')):
        number = count(value.get(parent), child)
        if number is not None:
            safe[parent] = {child: number}
            if target == 'cached':
                if cached is not None and cached != number:
                    errors.append('conflicting_cached_tokens')
                cached = number
            else:
                if reasoning is not None and reasoning != number:
                    errors.append('conflicting_reasoning_tokens')
                reasoning = number
    if embedding:
        if inp is None and total is not None:
            inp = total
        if output is None and (inp is not None or total is not None):
            output = 0
    if total is None and inp is not None and output is not None:
        total = inp + output
    if total is not None and inp is not None and output is not None and total != inp + output:
        errors.append('inconsistent_total_tokens')
        total = None
    if cached is not None and inp is not None and cached > inp:
        errors.append('invalid_cached_subset')
        cached = None
    if reasoning is not None and output is not None and reasoning > output:
        errors.append('invalid_reasoning_subset')
        reasoning = None
    tokens = {'input': inp, 'output': output, 'total': total, 'cached': cached, 'reasoning': reasoning}
    known = all(tokens[k] is not None for k in ('input', 'output', 'total')) and not errors
    return tokens, known, safe, sorted(set(errors))


def _estimate(start, tokens, known, actual_model):
    price = start['pricing']
    base = {'currency': price.get('currency') if price['status'] == 'known' else None,
            'kind': 'catalog_estimate', 'amount': None}
    if price['status'] != 'known':
        return {**base, 'reason': price.get('reason', 'price_unknown')}
    if actual_model is not None and actual_model != start['model']:
        return {**base, 'reason': 'actual_model_differs_from_price_snapshot'}
    if not known:
        return {**base, 'reason': 'provider_usage_incomplete_or_invalid'}
    entry = price['entry']
    input_rate = _decimal(entry['input_per_million'])
    output_key = 'thinking_output_per_million' if price['mode'] == 'thinking' and 'thinking_output_per_million' in entry else 'output_per_million'
    cached = tokens.get('cached') or 0
    cached_rate = _decimal(entry.get('cached_input_per_million', entry['input_per_million']))
    amount = (Decimal(tokens['input'] - cached) * input_rate + Decimal(cached) * cached_rate
              + Decimal(tokens['output']) * _decimal(entry[output_key])) / Decimal(1000000)
    return {**base, 'amount': _money(amount), 'reason': None,
            'catalog_version': price['catalog_version'], 'snapshot_sha256': price['snapshot_sha256']}


def _parse_lines(data, starts, finishes, integrity):
    for line in data.decode('utf-8', errors='replace').split('\n'):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            if not isinstance(row, dict) or row.get('schema_version') != SCHEMA:
                raise ValueError('invalid_usage_row')
            expected = row.get('record_sha256')
            actual = hashlib.sha256(json.dumps({k: v for k, v in row.items() if k != 'record_sha256'},
                sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
            if not isinstance(expected, str) or expected != actual:
                raise ValueError('usage_record_integrity_failed')
            attempt = row['attempt_id']
            if not isinstance(attempt, str) or not re.fullmatch(r'usage_[a-f0-9]{32}', attempt):
                raise ValueError('invalid_attempt_id')
            if row.get('event') == 'started':
                _time(row['started_at'])
                for key in ('stage', 'model'):
                    _label(row[key])
                _host(row['provider_host'])
                _label(row.get('scope'), optional=True)
                _label(row.get('run_id'), optional=True)
                _request_meta(row.get('request_meta'))
                if row['pricing'].get('status') not in {'known', 'unknown'}:
                    raise ValueError('invalid_pricing_status')
                if row['pricing']['status'] == 'known' and row['pricing'].get('currency') not in CURRENCIES:
                    raise ValueError('invalid_pricing_currency')
                target = starts
            elif row.get('event') == 'finished':
                _time(row['finished_at'])
                if row['status'] not in STATUSES:
                    raise ValueError('invalid_usage_status')
                for key in ('actual_model', 'error_type', 'provider_request_id'):
                    _label(row.get(key), optional=True)
                http_status = row.get('http_status')
                if http_status is not None and (type(http_status) is not int or not 100 <= http_status <= 599):
                    raise ValueError('invalid_usage_http_status')
                duration = row.get('duration_ms')
                if duration is not None and (not isinstance(duration, (int, float)) or isinstance(duration, bool) or not 0 <= duration <= 86400000):
                    raise ValueError('invalid_usage_duration')
                for key in ('input', 'output', 'total', 'cached', 'reasoning'):
                    value = row['tokens'][key]
                    if value is not None and (type(value) is not int or not 0 <= value <= MAX_TOKENS * 2):
                        raise ValueError('invalid_persisted_tokens')
                if type(row['usage_known']) is not bool:
                    raise ValueError('invalid_usage_known')
                amount = row['estimated_cost']['amount']
                currency = row['estimated_cost'].get('currency')
                if currency is not None and currency not in CURRENCIES:
                    raise ValueError('invalid_estimate_currency')
                if amount is not None:
                    _decimal(amount)
                    if currency not in CURRENCIES:
                        raise ValueError('estimate_currency_required')
                target = finishes
            else:
                raise ValueError('invalid_usage_event')
            if attempt in target:
                if target[attempt] != row:
                    integrity['conflicting_rows'] += 1
            else:
                target[attempt] = row
        except (ValueError, KeyError, TypeError, AttributeError):
            integrity['invalid_rows'] += 1


def _stat_signature(stat):
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)


def _read(root):
    """Incremental parse with full-prefix hashing before accepting an append.

    Stat equality reuses a process-local cache. Growth verifies every previous
    byte before tail parsing, so rewriting a prefix while appending is detected.
    Replacement, truncation, in-place edit or incomplete tail triggers full read.
    """
    path = guarded_path(root, root / 'memory/usage/requests.jsonl')
    key = str(path)
    with _READ_CACHE_LOCK:
        if not path.exists():
            _READ_CACHE.pop(key, None)
            return {}, {}, {'invalid_rows': 0, 'conflicting_rows': 0}
        signature = _stat_signature(path.stat())
        old = _READ_CACHE.get(key)
        if not old or old['signature'] != signature:
            data = None
            appended = False
            with path.open('rb') as handle:
                if (old and old['terminated'] and signature[:2] == old['signature'][:2]
                        and signature[2] > old['signature'][2]):
                    digest = hashlib.sha256()
                    remaining = old['signature'][2]
                    while remaining:
                        chunk = handle.read(min(1048576, remaining))
                        if not chunk:
                            break
                        remaining -= len(chunk)
                        digest.update(chunk)
                    if not remaining and digest.hexdigest() == old['digest']:
                        data = handle.read()
                        digest.update(data)
                        appended = True
                if data is None:
                    handle.seek(0)
                    data = handle.read()
                    digest = hashlib.sha256(data)
                if _stat_signature(os.fstat(handle.fileno())) != signature:
                    raise ValueError('usage_ledger_changed_during_read')
            if appended:
                current = old
            else:
                current = {'starts': {}, 'finishes': {},
                           'integrity': {'invalid_rows': 0, 'conflicting_rows': 0}}
            _parse_lines(data, current['starts'], current['finishes'], current['integrity'])
            current.update(signature=signature, digest=digest.hexdigest(), terminated=not data or data.endswith(b'\n'))
            _READ_CACHE[key] = current
        current = _READ_CACHE[key]
        _READ_CACHE.move_to_end(key)
        while len(_READ_CACHE) > 4:
            _READ_CACHE.popitem(last=False)
        integrity = dict(current['integrity'])
        integrity['invalid_rows'] += sum(key not in current['starts'] for key in current['finishes'])
        # Shallow copies isolate iteration from another thread's incremental read.
        return dict(current['starts']), dict(current['finishes']), integrity


class UsageMeter:
    def __init__(self, root):
        self.root = Path(root).resolve()

    def start(self, stage, model, provider_host, run_id=None, scope=None, request_meta=None, attempt_id=None):
        stage, model, host = _label(stage), _label(model), _host(provider_host)
        run_id, scope = _label(run_id, optional=True), _label(scope, optional=True)
        meta = _request_meta(request_meta)
        attempt = attempt_id or ('usage_' + uuid.uuid4().hex)
        if not isinstance(attempt, str) or not re.fullmatch(r'usage_[a-f0-9]{32}', attempt):
            raise ValueError('invalid_attempt_id')
        with _lock(self.root):
            _initialize_locked(self.root)
            if attempt_id is not None and attempt in _read(self.root)[0]:
                raise ValueError('usage_attempt_already_started')
            row = {'schema_version': SCHEMA, 'event': 'started', 'attempt_id': attempt,
                'started_at': _now(), 'stage': stage, 'model': model, 'provider_host': host,
                'run_id': run_id, 'scope': scope, 'request_meta': meta,
                'pricing': _price(self.root, host, model, meta)}
            _append(self.root, row)
        return attempt

    def finish(self, attempt_id, *, response=None, usage=None, actual_model=None, status='success',
               http_status=None, error_type=None, duration_ms=None, provider_request_id=None):
        if status not in STATUSES:
            raise ValueError('invalid_usage_status')
        if not isinstance(attempt_id, str) or not re.fullmatch(r'usage_[a-f0-9]{32}', attempt_id):
            raise ValueError('invalid_attempt_id')
        with _lock(self.root):
            starts, finishes, _ = _read(self.root)
            if attempt_id not in starts:
                raise ValueError('usage_attempt_not_started')
            if attempt_id in finishes:
                return _public(starts[attempt_id], finishes[attempt_id])
            start = starts[attempt_id]
            if usage is None:
                usage = _get(response, 'usage')
            if actual_model is None:
                actual_model = _get(response, 'model')
            actual_model = _label(actual_model, optional=True)
            error_type = _label(error_type, optional=True)
            provider_request_id = _label(provider_request_id, optional=True)
            if http_status is not None and (type(http_status) is not int or not 100 <= http_status <= 599):
                raise ValueError('invalid_usage_http_status')
            if duration_ms is not None and (not isinstance(duration_ms, (int, float)) or isinstance(duration_ms, bool) or not 0 <= duration_ms <= 86400000):
                raise ValueError('invalid_usage_duration')
            embedding = start['stage'] == 'embedding' or start['request_meta'].get('request_type') == 'embedding'
            tokens, known, provider_usage, warnings = _usage(usage, embedding)
            row = {'schema_version': SCHEMA, 'event': 'finished', 'attempt_id': attempt_id,
                'finished_at': _now(), 'status': status, 'actual_model': actual_model,
                'http_status': http_status, 'error_type': error_type, 'duration_ms': duration_ms,
                'provider_request_id': provider_request_id, 'tokens': tokens,
                'usage_known': known, 'provider_usage': provider_usage, 'usage_warnings': warnings,
                'estimated_cost': _estimate(start, tokens, known, actual_model)}
            _append(self.root, row)
            return _public(start, row)


def _public(start, finish=None):
    # Strict projection: unexpected fields in a damaged ledger never reach the UI.
    row = {key: start.get(key) for key in ('attempt_id', 'started_at', 'stage', 'model', 'provider_host', 'scope', 'run_id')}
    row['billing_mode'] = start.get('request_meta', {}).get('billing_mode', 'api')
    row.update(status='pending', finished_at=None, actual_model=None,
        tokens={k: None for k in ('input', 'output', 'total', 'cached', 'reasoning')},
        usage_known=False, pricing_status=start['pricing']['status'],
        estimated_cost={'currency': start['pricing'].get('currency') if start['pricing']['status'] == 'known' else None,
                        'kind': 'catalog_estimate', 'amount': None, 'reason': 'request_pending'},
        http_status=None, error_type=None, duration_ms=None, provider_request_id=None)
    if finish:
        for key in ('finished_at', 'actual_model', 'status', 'usage_known',
                    'http_status', 'error_type', 'duration_ms', 'provider_request_id'):
            row[key] = finish.get(key)
        row['tokens'] = {key: finish['tokens'].get(key) for key in ('input', 'output', 'total', 'cached', 'reasoning')}
        reason = finish['estimated_cost'].get('reason')
        reasons = {'price_not_configured', 'price_match_missing_or_ambiguous', 'invalid_price_catalog',
                   'actual_model_differs_from_price_snapshot', 'provider_usage_incomplete_or_invalid', 'subscription_plan_usage'}
        currency = finish['estimated_cost'].get('currency')
        if start['pricing']['status'] != 'known' and finish['estimated_cost'].get('amount') is None:
            currency = None  # Old unknown-price rows used a default CNY label, not an actual price.
        row['estimated_cost'] = {'currency': currency, 'kind': 'catalog_estimate',
            'amount': finish['estimated_cost'].get('amount'),
            'reason': reason if reason is None or reason in reasons else 'invalid_ledger_estimate'}
        if reason == 'actual_model_differs_from_price_snapshot':
            row['pricing_status'] = 'unknown'
    return row


def _read_snapshot(root):
    """Consistent read without creating a directory or lock on an untouched root."""
    path = guarded_path(root, root / 'state/locks/memory-usage.lock')
    if not path.exists():
        return _read(root)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if os.fstat(fd).st_nlink != 1:
            raise ValueError('hardlinked_usage_lock')
        fcntl.flock(fd, fcntl.LOCK_SH)
        return _read(root)
    finally:
        os.close(fd)


def recent(root, limit=20):
    root = Path(root).resolve()
    if type(limit) is not int or not 0 <= limit <= 500:
        raise ValueError('invalid_usage_recent_limit')
    starts, finishes, _ = _read_snapshot(root)
    records = sorted(starts.values(), key=lambda r: (_time(r['started_at']), r['attempt_id']), reverse=True)
    return [_public(start, finishes.get(start['attempt_id'])) for start in records[:limit]]


def _totals(rows, *, breakdown=True):
    result = {'calls': len(rows), 'completed': 0, 'pending': 0, 'unknown_usage': 0,
        'unknown_price': 0, 'unpriced_requests': 0, 'subscription_requests': 0,
        'usage_coverage': {'complete_requests': 0, 'partial_requests': 0, 'missing_requests': 0},
        'tokens': {key: None for key in ('input', 'output', 'total', 'cached', 'reasoning')}}
    costs = {}
    unknown_currency = 0
    priced = 0
    api_completed = 0
    groups = defaultdict(list)
    for row in rows:
        subscription = row.get('billing_mode') == 'subscription'
        result['subscription_requests'] += subscription
        groups[(row['stage'], row['model'], row['provider_host'])].append(row)
        currency = row['estimated_cost'].get('currency')
        if not subscription and currency in CURRENCIES:
            bucket = costs.setdefault(currency, {'known_amount': Decimal(0), 'calls': 0, 'priced': 0})
            bucket['calls'] += 1
        elif not subscription:
            unknown_currency += 1
        if row['status'] == 'pending':
            result['pending'] += 1
            continue
        result['completed'] += 1
        result['unknown_usage'] += not row['usage_known']
        coverage = 'complete_requests' if row['usage_known'] else (
            'partial_requests' if any(row['tokens'][key] is not None for key in ('input', 'output', 'total')) else 'missing_requests')
        result['usage_coverage'][coverage] += 1
        if not subscription:
            api_completed += 1
            result['unknown_price'] += row['pricing_status'] != 'known'
        for key in result['tokens']:
            if row['tokens'][key] is not None:
                result['tokens'][key] = (result['tokens'][key] or 0) + row['tokens'][key]
        if subscription:
            continue
        amount = row['estimated_cost']['amount']
        if amount is None:
            result['unpriced_requests'] += 1
        else:
            # Parsed priced rows always have a validated currency. No exchange rate exists here.
            costs[currency]['known_amount'] += _decimal(amount)
            costs[currency]['priced'] += 1
            priced += 1
    result['estimated_cost_by_currency'] = {
        currency: {'currency': currency, 'kind': 'catalog_estimate',
            'requests': bucket['calls'], 'priced_requests': bucket['priced'],
            'known_amount': _money(bucket['known_amount']),
            'amount': _money(bucket['known_amount']) if bucket['priced'] == bucket['calls'] and not unknown_currency else None}
        for currency, bucket in sorted(costs.items())}
    result['unknown_currency_requests'] = unknown_currency
    sole_cost = next(iter(result['estimated_cost_by_currency'].values())) if len(costs) == 1 else None
    result['estimated_cost'] = ({key: sole_cost[key] for key in ('currency', 'kind', 'known_amount', 'amount')}
        if sole_cost is not None else {'currency': None, 'kind': 'catalog_estimate', 'known_amount': None, 'amount': None})
    result['pricing_coverage'] = {'priced_requests': priced, 'completed_requests': api_completed,
        'fraction': _money(Decimal(priced) / Decimal(api_completed)) if api_completed else None}
    if breakdown:
        result['breakdown'] = [{'stage': key[0], 'model': key[1], 'provider_host': key[2],
                               **_totals(value, breakdown=False)} for key, value in sorted(groups.items())]
    return result


def summary(root, now=None):
    root = Path(root).resolve()
    moment = _time(now) if now is not None else datetime.now(timezone.utc)
    local = moment.astimezone(SHANGHAI)
    starts, finishes, integrity = _read_snapshot(root)
    windows = {'today': [], 'month': [], 'all': []}
    for start in starts.values():
        at = _time(start['started_at'])
        if at > moment:
            continue
        finish = finishes.get(start['attempt_id'])
        if finish and _time(finish['finished_at']) > moment:
            finish = None
        row = _public(start, finish)
        day = at.astimezone(SHANGHAI)
        windows['all'].append(row)
        if day.date() == local.date():
            windows['today'].append(row)
        if (day.year, day.month) == (local.year, local.month):
            windows['month'].append(row)
    meta = guarded_path(root, root / 'memory/usage/meter.json')
    started_at = None
    if meta.exists():
        try:
            value = json.loads(meta.read_text(encoding='utf-8'))
            if value.get('schema_version') == SCHEMA:
                _time(value['started_at'])
                started_at = value['started_at']
            else:
                integrity['invalid_rows'] += 1
        except (ValueError, KeyError, AttributeError):
            integrity['invalid_rows'] += 1
    return {'schema_version': SCHEMA, 'timezone': 'Asia/Shanghai', 'as_of': moment.isoformat(),
        'meter_started_at': started_at, 'historical_backfill': False, 'integrity': integrity,
        **{name: _totals(rows) for name, rows in windows.items()}}
