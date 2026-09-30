"""Locate trusted runtime code; never import executable code from a data root."""
import sys
from pathlib import Path


def runtime_module(name):
    import importlib
    scripts = str(Path(__file__).resolve().parents[3] / 'scripts')
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    return importlib.import_module(name)


def held_error(error):
    seen = set()
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        code = getattr(error, 'code', None)
        if code in {'global_paused', 'role_paused', 'daily_budget_exhausted',
                'waiting_for_key', 'waiting_for_configuration', 'waiting_for_embedding_key',
                'waiting_for_embedding_configuration', 'memory_model_revision_changed'} or (
                isinstance(code, str) and code.startswith('chatgpt_subscription_')):
            return error
        error = error.__cause__ or error.__context__
    return None
