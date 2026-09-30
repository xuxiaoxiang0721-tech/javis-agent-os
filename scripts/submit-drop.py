#!/usr/bin/env python3
"""Atomically publish an authorized message; never execute a model or change review policy."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import uuid

sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location('javis_drop_contract', Path(__file__).with_name('drop-bridge.py'))
contract = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(contract)


def local_path(value):
    """Accept absolute Linux paths or local Windows drive paths; never UNC/device paths."""
    if not isinstance(value, str) or not value or '\x00' in value:
        raise contract.Reject('a nonempty local path is required')
    if value.startswith(('\\\\', '//')):
        raise contract.Reject('UNC and device paths are not accepted')
    match = re.match(r'^([A-Za-z]):[\\/](.*)$', value)
    if match:
        parts = match.group(2).replace('\\', '/').split('/')
        if any(part in ('.', '..') for part in parts):
            raise contract.Reject('Windows path traversal components are not accepted')
        return Path('/mnt') / match.group(1).lower() / Path(*parts)
    path = Path(value)
    if not path.is_absolute() or '\\' in value or '..' in path.parts:
        raise contract.Reject('use an absolute Linux path or a local Windows drive path')
    return path


def no_link_ancestors(path):
    for parent in reversed((path, *path.parents)):
        if parent.is_symlink():
            raise contract.Reject('links in input or queue paths are not accepted')
        if parent.exists() and parent != path:
            contract.ordinary_dir(parent)


def make_directory(path):
    no_link_ancestors(path)
    path.mkdir(parents=True, exist_ok=True)
    no_link_ancestors(path)
    contract.ordinary_dir(path)


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def submit(role, message_file, submission_id, message_id=None, base=None):
    base = base or os.environ.get('JAVIS_DROP_BASE', str(Path.home() / 'javis-drop'))
    if role not in contract.ROLES:
        raise contract.Reject('role is not authorized for local Bot execution')
    if not isinstance(submission_id, str) or not contract.IDENT.fullmatch(submission_id):
        raise contract.Reject('submission_id must be 1..80 ASCII letters, numbers, underscore or hyphen')
    if message_id is not None and (not isinstance(message_id, str) or not message_id.strip()
                                   or len(message_id) > 160 or not message_id.isprintable()):
        raise contract.Reject('message_id must be a real printable upstream ID, at most 160 characters')
    source = local_path(message_file)
    no_link_ancestors(source)
    data = contract.regular_bytes(source, contract.MAX_MESSAGE)
    text = data.decode('utf-8-sig')
    if not text.strip() or '\x00' in text:
        raise contract.Reject('message.txt must be nonempty UTF-8 text without NUL')
    queue = local_path(base) / contract.ROLES[role]
    inbox = queue / 'inbox'
    make_directory(inbox)
    delivery = uuid.uuid4().hex
    temporary, ready = inbox / (delivery + '.tmp'), inbox / (delivery + '.ready')
    temporary.mkdir(mode=0o700, exist_ok=False)
    request = dict(schema_version=1, submission_id=submission_id)
    if message_id is not None:
        request['message_id'] = message_id
    write_new(temporary / 'message.txt', data)
    write_new(temporary / 'request.json', (json.dumps(request, ensure_ascii=False) + '\n').encode('utf-8'))
    # Same validator as the consumer, before a package becomes visible as ready.
    contract.validate(temporary)
    no_link_ancestors(inbox)
    if ready.exists() or ready.is_symlink():
        raise contract.Reject('delivery_id collision; previous evidence was not changed')
    os.rename(temporary, ready)
    return dict(schema_version=1, submission_status='queued', role_id=role,
                delivery_id=delivery, submission_id=submission_id, message_id=message_id,
                input_sha256=contract.digest(data), ready_path=str(ready),
                receipt_locations=dict(done=str(queue / 'done' / delivery / 'receipt.json'),
                                       fail=str(queue / 'fail' / delivery / 'receipt.json')))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', required=True, choices=tuple(contract.ROLES))
    parser.add_argument('--message-file', required=True)
    parser.add_argument('--submission-id', required=True)
    parser.add_argument('--message-id', default=None)
    parser.add_argument('--base', default=os.environ.get('JAVIS_DROP_BASE', str(Path.home() / 'javis-drop')), help='isolated base override for controlled tests')
    args = parser.parse_args()
    try:
        outcome = submit(args.role, args.message_file, args.submission_id, args.message_id, args.base)
    except (contract.Reject, OSError, ValueError, UnicodeError) as exc:
        # Uncommitted .tmp packages are never consumed; do not remove or alter prior deliveries.
        reason = str(exc) if isinstance(exc, contract.Reject) else 'input or queue could not be safely read/written'
        print(json.dumps(dict(submission_status='rejected', reason=reason), ensure_ascii=False), file=sys.stderr)
        return 1
    print(json.dumps(outcome, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
