"""Dedicated OpenAI memory credentials. Local configuration never probes a provider."""
from __future__ import annotations
import json
import os
import re
import sys
from pathlib import Path

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE / 'tools/memory-adapter'))
from javis_memory_adapter.review_policy import guarded_path, ReviewBlocked
from runtime_io import atomic_json, lock

BASE_URL = 'https://api.openai.com/v1'
CONFIG = 'config/memory-model.json'
SECRET = 'secrets/openai-memory.json'
EMBEDDING = 'text-embedding-3-small'
EMBEDDING_SECRET = 'secrets/memory-embedding.json'
DASHSCOPE_BASE_URL = 'https://dashscope.aliyuncs.com/compatible-mode/v1'
MODEL_WAIT_STATES = frozenset({'waiting_for_configuration', 'waiting_for_key',
    'waiting_for_embedding_configuration', 'waiting_for_embedding_key',
    'chatgpt_subscription_login_required', 'chatgpt_subscription_account_changed',
    'chatgpt_subscription_access_denied', 'chatgpt_subscription_usage_limit_exceeded',
    'chatgpt_subscription_usage_unavailable'})


class MemoryModelUnavailable(ReviewBlocked):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _path(root, name):
    return guarded_path(root, Path(root) / name)


def _read(root, name):
    path = _path(root, name)
    if not path.exists():
        return {}
    if path.stat().st_size > 16384 or path.stat().st_nlink != 1:
        raise ReviewBlocked('memory_model_configuration_invalid')
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, OSError):
        raise ReviewBlocked('memory_model_configuration_invalid') from None


def _values(root):
    cfg = _read(root, CONFIG)
    secret = _read(root, SECRET)
    mode = cfg.get('auth_mode', 'api_key')
    if mode not in {'api_key', 'chatgpt_subscription'}:
        raise ReviewBlocked('memory_auth_mode_invalid')
    model = (os.environ.get('OPENAI_MEMORY_MODEL') if mode == 'api_key' else None) or cfg.get('model')
    key = os.environ.get('OPENAI_MEMORY_API_KEY') or secret.get('api_key')
    # Intentionally ignore OPENAI_API_KEY, OPENAI_BASE_URL and LLM_*: those
    # names belong to the historical DashScope-compatible Graphiti client.
    if model is not None and (not isinstance(model, str) or not re.fullmatch(r'gpt-[a-zA-Z0-9][a-zA-Z0-9._-]{1,120}', model)):
        raise ReviewBlocked('memory_model_invalid')
    if key is not None and (not isinstance(key, str) or not re.fullmatch(r'[!-~]{20,1024}', key)):
        raise ReviewBlocked('memory_key_invalid')
    embedding = cfg.get('embedding_model', EMBEDDING)
    _embedding_spec(cfg.get('embedding_provider', 'openai'), embedding)
    revision = cfg.get('revision', 0)
    if type(revision) is not int or revision < 0:
        raise ReviewBlocked('memory_model_configuration_invalid')
    return cfg, model, key, embedding, revision


def _embedding_spec(provider, model):
    if provider == 'openai' and model in {EMBEDDING, 'text-embedding-3-large'}:
        return BASE_URL, 1536 if model == EMBEDDING else 3072
    if provider == 'dashscope' and model == 'text-embedding-v3':
        return DASHSCOPE_BASE_URL, 1024
    raise ReviewBlocked('memory_embedding_model_invalid')


def _subscription_state(root):
    import chatgpt_subscription
    return chatgpt_subscription.status(root)


def _embedding_values(root, cfg, llm_key):
    provider = cfg.get('embedding_provider', 'openai')
    model = cfg.get('embedding_model', EMBEDDING)
    base, dimensions = _embedding_spec(provider, model)
    secret = _read(root, EMBEDDING_SECRET)
    key = secret.get(provider)
    # Backward compatibility is confined to the dedicated OpenAI memory key.
    # A ChatGPT subscription access token is never an embedding credential.
    if not key and provider == 'openai':
        key = llm_key
    if cfg.get('embedding_credential_source') == 'legacy_dashscope':
        legacy = _legacy_embedding(root)
        if provider != 'dashscope' or legacy['base_url'] != base or legacy['model'] != model:
            raise MemoryModelUnavailable('waiting_for_embedding_configuration')
        key = legacy['api_key']
    if key is not None and (not isinstance(key, str) or not re.fullmatch(r'[!-~]{20,1024}', key)):
        raise ReviewBlocked('memory_embedding_key_invalid')
    return {'provider': provider, 'base_url': base, 'embedding_provider': provider,
        'embedding_model': model, 'embedding_dimensions': dimensions, 'api_key': key,
        'status': 'ready' if key else 'waiting_for_embedding_key', 'key_configured': bool(key),
        'credential_source': cfg.get('embedding_credential_source', 'dedicated')}


def _legacy_embedding(root):
    """Read only an explicitly selected historical embedding credential source."""
    path = _path(root, 'tools/graphiti/.env')
    if not path.is_file() or path.stat().st_size > 65536 or path.stat().st_nlink != 1:
        raise MemoryModelUnavailable('waiting_for_embedding_configuration')
    values = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        if line.strip() and not line.lstrip().startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            values[k.strip()] = v.strip().strip('"').strip("'")
    # No arbitrary host or LLM credentials can become an embedding endpoint.
    model = values.get('EMBEDDING_MODEL')
    if model and model.startswith(('openai/', 'dashscope/')):
        model = model.split('/', 1)[1]
    base = values.get('EMBEDDING_BASE_URL') or values.get('OPENAI_BASE_URL')
    key = values.get('EMBEDDING_API_KEY') or values.get('OPENAI_API_KEY')
    if base != DASHSCOPE_BASE_URL or model != 'text-embedding-v3' or values.get('EMBEDDING_DIMS') != '1024':
        raise MemoryModelUnavailable('waiting_for_embedding_configuration')
    return {'model': model, 'base_url': base, 'api_key': key}


def _status(root):
    cfg, model, key, embedding, revision = _values(root)
    mode = cfg.get('auth_mode', 'api_key')
    account = cfg.get('account_id') if mode == 'chatgpt_subscription' else None
    state = 'waiting_for_configuration' if not model else 'waiting_for_key' if not key else 'ready'
    if mode == 'chatgpt_subscription':
        sub = _subscription_state(root)
        state = ('waiting_for_configuration' if not model or not account else
            'chatgpt_subscription_account_changed' if sub.get('account_id') != account else
            'chatgpt_subscription_' + sub['availability_code'] if sub.get('availability_code') in {
                'login_required', 'access_denied', 'usage_limit_exceeded', 'usage_unavailable'} else
            'chatgpt_subscription_login_required' if not sub.get('connected') or sub.get('requires_login') else
            'chatgpt_subscription_access_denied' if not sub.get('plan_usage') else 'ready')
    try:
        emb = _embedding_values(root, cfg, key)
    except MemoryModelUnavailable as exc:
        provider = cfg.get('embedding_provider', 'openai')
        base, dimensions = _embedding_spec(provider, embedding)
        emb = {'provider':provider, 'base_url':base, 'embedding_dimensions':dimensions,
               'status':exc.code, 'key_configured':False,
               'credential_source':cfg.get('embedding_credential_source', 'dedicated')}
    combined = state if state != 'ready' else emb['status']
    return {'provider': 'openai', 'base_url': BASE_URL, 'status': combined, 'llm_status': state,
            'auth_mode': mode, 'account_id': account, 'billing_mode': 'subscription' if mode == 'chatgpt_subscription' else 'api',
            'retry_at': sub.get('retry_at') if mode == 'chatgpt_subscription' else None,
            'model': model, 'model_is_snapshot': bool(model and re.search(r'-\d{4}-\d{2}-\d{2}$', model)),
            'embedding_model': embedding, 'embedding_dimensions': emb['embedding_dimensions'],
            'embedding_provider': emb['provider'], 'embedding_status': emb['status'],
            'embedding_key_configured': emb['key_configured'], 'embedding_base_url': emb['base_url'],
            'embedding_credential_source': emb['credential_source'],
            'key_configured': bool(key), 'revision': revision, 'verified': False,
            'environment_override': bool(os.environ.get('OPENAI_MEMORY_MODEL') or os.environ.get('OPENAI_MEMORY_API_KEY'))}


def status(root):
    root = Path(root).resolve()
    # UI readiness is a read-only hint; actual client creation takes the lock
    # and repeats the check. Atomic files prevent partially written JSON.
    return _status(root)


def configure(root, *, expected_revision, model=None, api_key=None, embedding_model=None,
              auth_mode=None, account_id=None, embedding_provider=None, embedding_api_key=None,
              use_legacy_embedding=False):
    root = Path(root).resolve()
    with lock(_path(root, 'state/locks/memory-model.lock')):
        cfg, old_model, old_key, old_embedding, revision = _values(root)
        if type(expected_revision) is not int or expected_revision != revision:
            raise ReviewBlocked('memory_model_revision_changed')
        mode = auth_mode if auth_mode is not None else cfg.get('auth_mode', 'api_key')
        if mode not in {'api_key', 'chatgpt_subscription'}:
            raise ReviewBlocked('memory_auth_mode_invalid')
        account = account_id if account_id is not None else cfg.get('account_id')
        if mode == 'chatgpt_subscription':
            sub = _subscription_state(root)
            if not isinstance(account, str) or account != sub.get('account_id'):
                raise MemoryModelUnavailable('chatgpt_subscription_account_changed')
        selected = model if model is not None else cfg.get('model')
        if not isinstance(selected, str) or not re.fullmatch(r'gpt-[a-zA-Z0-9][a-zA-Z0-9._-]{1,120}', selected):
            raise ReviewBlocked('memory_model_invalid')
        provider = embedding_provider or cfg.get('embedding_provider', 'openai')
        embedding = embedding_model or (old_embedding if provider == cfg.get('embedding_provider', 'openai')
            else 'text-embedding-v3' if provider == 'dashscope' else EMBEDDING)
        _embedding_spec(provider, embedding)
        credential_source = cfg.get('embedding_credential_source', 'dedicated')
        if provider != cfg.get('embedding_provider', 'openai') or embedding_api_key is not None:
            credential_source = 'dedicated'
        if type(use_legacy_embedding) is not bool:
            raise ReviewBlocked('memory_embedding_configuration_invalid')
        if use_legacy_embedding:
            if provider != 'dashscope':
                raise ReviewBlocked('memory_embedding_configuration_invalid')
            _legacy_embedding(root)
            credential_source = 'legacy_dashscope'
        if api_key is not None and (not isinstance(api_key, str) or not re.fullmatch(r'[!-~]{20,1024}', api_key)):
            raise ReviewBlocked('memory_key_invalid')
        if embedding_api_key is not None:
            if not isinstance(embedding_api_key, str) or not re.fullmatch(r'[!-~]{20,1024}', embedding_api_key):
                raise ReviewBlocked('memory_embedding_key_invalid')
            secrets = _read(root, EMBEDDING_SECRET)
            secrets[provider] = embedding_api_key
            path = _path(root, EMBEDDING_SECRET)
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            atomic_json(path, secrets)
            os.chmod(path, 0o600)
        if api_key is not None:
            if not isinstance(api_key, str) or not re.fullmatch(r'[!-~]{20,1024}', api_key):
                raise ReviewBlocked('memory_key_invalid')
            path = _path(root, SECRET)
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            atomic_json(path, {'api_key': api_key})
            os.chmod(path, 0o600)
        atomic_json(_path(root, CONFIG), {'provider': 'openai', 'model': selected,
            'auth_mode': mode, 'account_id': account if mode == 'chatgpt_subscription' else None,
            'embedding_provider': provider, 'embedding_model': embedding,
            'embedding_credential_source': credential_source, 'revision': revision + 1})
        return _status(root)


def runtime_config(root):
    """Internal only: never serialize or send this dict to the UI/logs."""
    root = Path(root).resolve()
    with lock(_path(root, 'state/locks/memory-model.lock'), shared=True):
        state = _status(root)
        if state['llm_status'] != 'ready':
            raise MemoryModelUnavailable(state['llm_status'])
        _, _, key, _, _ = _values(root)
        if state['auth_mode'] == 'chatgpt_subscription':
            import chatgpt_subscription
            try:
                key = chatgpt_subscription.access_token(root, expected_account_id=state['account_id'])
            except chatgpt_subscription.SubscriptionError as exc:
                raise MemoryModelUnavailable(exc.code) from None
        return {**state, 'api_key': key}


def runtime_embedding_config(root):
    """Internal independent API credential; never returns a subscription token."""
    root = Path(root).resolve()
    with lock(_path(root, 'state/locks/memory-model.lock'), shared=True):
        cfg, _, key, _, revision = _values(root)
        value = _embedding_values(root, cfg, key)
        if value['status'] != 'ready':
            raise MemoryModelUnavailable(value['status'])
        return {**value, 'revision': revision, 'billing_mode': 'api'}


def embedding_config(root):
    """Read-only embedding readiness, independent of subscription login state."""
    root = Path(root).resolve()
    cfg, _, key, _, revision = _values(root)
    value = _embedding_values(root, cfg, key)
    return {k:v for k,v in {**value, 'revision':revision, 'billing_mode':'api'}.items() if k != 'api_key'}
