#!/usr/bin/env python3
"""One-shot local Neo4j access after a human unlocks the program KDBX.

Only graph-check and graph-sync are supported. Read one bounded JSON object
from stdin; never accept credentials, destinations or scopes in argv/env.
The caller must terminate this process if its own transport deadline expires.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
from pathlib import Path
import signal
import sys

CODE_ROOT = Path(__file__).resolve().parents[1]
DEPLOY_ROOT = Path('/home/user/javis')
NEO4J_URI = 'bolt://127.0.0.1:7687'
SCOPES = ('cards-master', 'invest', 'gpt-star', 'shared')
MAX_INPUT_BYTES = 16384
HARD_TIMEOUT_SECONDS = 45


class InputRejected(ValueError):
    pass


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputRejected('duplicate_field')
        result[key] = value
    return result


def read_credentials(stream):
    raw = stream.read(MAX_INPUT_BYTES + 1)
    if not isinstance(raw, bytes) or len(raw) > MAX_INPUT_BYTES:
        raise InputRejected('invalid_size')
    try:
        payload = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError, TypeError, RecursionError):
        raise InputRejected('invalid_payload') from None
    if not isinstance(payload, dict) or set(payload) != {'schema_version', 'username', 'password'}:
        raise InputRejected('invalid_fields')
    if type(payload['schema_version']) is not int or payload['schema_version'] != 1:
        raise InputRejected('invalid_version')
    username, password = payload['username'], payload['password']
    if (not isinstance(username, str) or not 1 <= len(username) <= 128
            or any(ord(c) < 32 for c in username)
            or not isinstance(password, str) or not 1 <= len(password) <= 8192
            or '\0' in password):
        raise InputRejected('invalid_credentials')
    return username, password


def receipt(action, status, reason, *, scopes=0, written=0, errors=0):
    # All strings and numbers in the receipt are locally chosen, never driver
    # messages, entry names, usernames, secret values, facts or database rows.
    return {'schema_version': 1, 'action': action, 'status': status,
            'reason': reason, 'scopes_checked': scopes,
            'facts_written': written, 'errors': errors}


async def _check(username, password):
    from neo4j import AsyncGraphDatabase
    driver = AsyncGraphDatabase.driver(NEO4J_URI, auth=(username, password),
        connection_timeout=5, connection_acquisition_timeout=5,
        max_transaction_retry_time=0)
    try:
        async with driver.session(default_access_mode='READ', database='neo4j') as session:
            result = await session.run('RETURN 1 AS ok')
            row = await result.single(strict=True)
            if row is None or row['ok'] != 1:
                raise RuntimeError('unexpected_health_result')
    finally:
        await driver.close()


async def _sync(username, password):
    # The installed location is part of this fixed consumer's authority. A
    # staged copy must not accidentally operate on the production ledger.
    if CODE_ROOT != DEPLOY_ROOT:
        raise RuntimeError('consumer_not_deployed')
    sys.path.insert(0, str(CODE_ROOT / 'scripts'))
    sys.path.insert(0, str(CODE_ROOT / 'tools/memory-adapter'))
    from task_memory import _store, _group
    from javis_memory_adapter.type_b import rebuild_group_from_store
    written, errors = 0, 0
    for scope in SCOPES:
        store = _store(CODE_ROOT, scope)
        if not store.load_facts():
            continue
        with store.rebuild_lock():
            report = await rebuild_group_from_store(
                store=store, target_group_id=_group(CODE_ROOT, scope),
                neo4j_uri=NEO4J_URI, neo4j_user=username,
                neo4j_password=password, embed=False)
        written += len(report['written'])
        errors += len(report['errors'])
        # Reports may contain driver exceptions or memory content. They are
        # neither printed nor persisted by this consumer.
        report.clear()
    return receipt('graph-sync', 'partial' if errors else 'ok',
        'projection_pending' if errors else 'projection_complete',
        scopes=len(SCOPES), written=written, errors=errors)


async def execute(action, credentials):
    username, password = credentials
    # Authentication is checked before any ledger mutation, even for an
    # empty ledger; a wrong key must never produce a successful receipt.
    await asyncio.wait_for(_check(username, password), timeout=10)
    if action == 'graph-check':
        return receipt(action, 'ok', 'graph_verified')
    return await asyncio.wait_for(_sync(username, password), timeout=30)


def _harden():
    import faulthandler
    import resource
    faulthandler.disable()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    logging.disable(logging.CRITICAL)
    os.umask(0o077)


def run(argv, input_stream, output_stream):
    action = argv[0] if len(argv) == 1 and argv[0] in ('graph-check', 'graph-sync') else 'invalid'
    if action == 'invalid':
        result = receipt(action, 'failed', 'invalid_action')
        output_stream.write(json.dumps(result) + '\n')
        return 2
    try:
        credentials = read_credentials(input_stream)
    except InputRejected:
        output_stream.write(json.dumps(receipt(action, 'failed', 'invalid_input')) + '\n')
        return 2
    try:
        # Suppress dependency output as well as logging; final output below
        # is the only permitted stdout payload.
        with open(os.devnull, 'w') as quiet:
            with contextlib.redirect_stdout(quiet), contextlib.redirect_stderr(quiet):
                result = asyncio.run(execute(action, credentials))
    except (TimeoutError, asyncio.TimeoutError):
        result = receipt(action, 'failed', 'operation_timeout', written=None)
    except Exception:
        result = receipt(action, 'failed', 'graph_unavailable', written=None)
    finally:
        # Python/driver string copies cannot be guaranteed securely erased.
        # The containing process exits after one operation; nothing caches
        # an unlock, saves a key, or launches another consumer.
        del credentials
    output_stream.write(json.dumps(result, ensure_ascii=True) + '\n')
    return 0 if result['status'] == 'ok' else 1


def main():
    action = sys.argv[1] if len(sys.argv) == 2 and sys.argv[1] in ('graph-check', 'graph-sync') else 'invalid'
    timeout_output = (json.dumps(receipt(action, 'failed', 'operation_timeout', written=None)) + '\n').encode('ascii')

    def deadline(_signum, _frame):
        # Hard deadline includes blocked stdin and synchronous ledger locks.
        # Use a fixed payload and exit immediately, without exception repr.
        os.write(1, timeout_output)
        os._exit(124)

    try:
        _harden()
        signal.signal(signal.SIGALRM, deadline)
        signal.alarm(HARD_TIMEOUT_SECONDS)
        return run(sys.argv[1:], sys.stdin.buffer, sys.stdout)
    except Exception:
        sys.stdout.write(json.dumps(receipt(action, 'failed', 'consumer_unavailable')) + '\n')
        return 1
    finally:
        signal.alarm(0)


if __name__ == '__main__':
    raise SystemExit(main())
