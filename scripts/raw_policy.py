"""Remove explicitly labelled credentials before persistence; not a general DLP scanner."""
from __future__ import annotations
import re
from pathlib import Path

MASK = '[REDACTED:CREDENTIAL]'
KEY = re.compile(r'^(?:(?:[A-Z0-9]+[_-])*(?:password|passwd|secret|token|api[ _-]?key|access[_-]?key|authorization|cookie|private[_-]?key)|密码|口令|密钥|令牌)$', re.I)
ASSIGN_PREFIX = r'''(?<![\w])(?:[\w-]+[_-])?(?:password|passwd|secret|token|api[ _-]?key|access[_-]?key|authorization|cookie|private[_-]?key|密码|口令|密钥|令牌)["']?\s*(?:[:=：]|是|为)\s*'''
ASSIGN = re.compile(r'''(?P<prefix>''' + ASSIGN_PREFIX + r''')(?P<value>"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;，；}\]]+)''', re.I)
INCOMPLETE_ASSIGN = re.compile(ASSIGN_PREFIX + r'$', re.I)
BEARER = re.compile(r'\bBearer\s+(?!\[REDACTED)[A-Za-z0-9._~+/=-]+', re.I)
API_VALUE = re.compile(r'\b(?:sk-[A-Za-z0-9_-]{10,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16})\b')
PRIVATE = re.compile(r'-----BEGIN (?:[A-Z ]*PRIVATE KEY)-----.*?(?:-----END (?:[A-Z ]*PRIVATE KEY)-----|\Z)', re.S)
# KeePass databases and key files stay outside ordinary task capture/backup.
# Include compound backups such as personal.kdbx.bak and personal.KEYX~.
VAULT_NAME = re.compile(r'\.(?:kdbx|kdb|keyx)(?:$|[._~ :\-])', re.I)
# https://keepass.info/help/kb/kdbx.html (little-endian signature words).
# Legacy and prerelease signatures are also excluded, never opened as data.
VAULT_SIGNATURES = (bytes.fromhex('03d9a29a67fb4bb5'),
                    bytes.fromhex('03d9a29a65fb4bb5'),
                    bytes.fromhex('03d9a29a66fb4bb5'))


def is_vault_path(path):
    """Check both lexical and resolved names (including parent directory links)."""
    path = Path(path)
    return any(part.casefold() == 'javis-vault' or VAULT_NAME.search(part)
               for candidate in (path, path.resolve()) for part in candidate.parts)


def is_vault_bytes(data):
    """Recognise KeePass signatures without parsing or decrypting a database.

    Arbitrary key material and compressed/encrypted containers are not scanned.
    """
    return data.startswith(VAULT_SIGNATURES)


def redact(value):
    """Return (safe copy, [{path, category, count}]); metadata never includes values."""
    changes = []
    def text(s, path):
        def replace(pattern, category, fn=None):
            nonlocal s
            s, n = pattern.subn(fn or MASK, s)
            if n: changes.append({'path': path, 'category': category, 'count': n})
        replace(PRIVATE, 'private_key')
        replace(BEARER, 'bearer')
        replace(API_VALUE, 'credential_format')
        def assignment(m):
            val = m.group('value')
            if MASK in val or val.lstrip('"\'').startswith('[REDACTED:') or val in ('null', 'None', 'true', 'false'): return m.group(0)
            quote = val[0] if val[:1] in ('"', "'") else ''
            return m.group('prefix') + quote + MASK + quote
        # Count only actual substitutions, preserving idempotent metadata.
        before = s
        s = ASSIGN.sub(assignment, s)
        if before != s: changes.append({'path': path, 'category': 'credential_assignment', 'count': 1})
        return s
    def walk(obj, path):
        if isinstance(obj, dict):
            out = {}
            for key, item in obj.items():
                child = path + '.' + str(key)
                if KEY.fullmatch(str(key)) and isinstance(item, str) and item and item != MASK:
                    out[key] = MASK
                    changes.append({'path': child, 'category': 'credential_field', 'count': 1})
                else: out[key] = walk(item, child)
            return out
        if isinstance(obj, list): return [walk(item, f'{path}[{i}]') for i, item in enumerate(obj)]
        if isinstance(obj, tuple): return [walk(item, f'{path}[{i}]') for i, item in enumerate(obj)]
        if isinstance(obj, str): return text(obj, path)
        return obj
    return walk(value, '$'), changes


def sanitize(value):
    return redact(value)[0]


class StreamRedactor:
    """Buffer incomplete lines and PEM blocks, so chunk boundaries cannot leak keys.

    feed(text) emits complete safe lines; finish() flushes the final safe fragment.
    redactions contains metadata only. Use one instance per independent stream.
    """
    def __init__(self):
        self.pending = ''
        self.in_private = False
        self.assignment_prefix = ''
        self.redactions = []

    def feed(self, text, *, final=False):
        self.pending += text
        lines = self.pending.splitlines(keepends=True)
        self.pending = ''
        if lines and not final and not lines[-1].endswith(('\n', '\r')):
            self.pending = lines.pop()
        output = []
        for line in lines:
            if self.assignment_prefix:
                line = self.assignment_prefix + line
                self.assignment_prefix = ''
            if self.in_private:
                if re.search(r'-----END [A-Z ]*PRIVATE KEY-----', line): self.in_private = False
                continue
            if re.search(r'-----BEGIN [A-Z ]*PRIVATE KEY-----', line):
                self.in_private = not bool(re.search(r'-----END [A-Z ]*PRIVATE KEY-----', line))
                safe, changes = redact(line)
                output.append(safe.rstrip('\r\n') + '\n')
                self.redactions.extend(changes)
                continue
            if INCOMPLETE_ASSIGN.search(line):
                self.assignment_prefix = line
                continue
            safe, changes = redact(line)
            output.append(safe); self.redactions.extend(changes)
        if final and self.assignment_prefix:
            output.append(self.assignment_prefix)
            self.assignment_prefix = ''
        return ''.join(output)

    def finish(self):
        return self.feed('', final=True)


class CredentialFileBlocked(ValueError):
    pass


def safe_file_bytes(path, *, captured_bytes=None):
    """Return safe bytes and redactions. Explicit binary credentials block capture.

    Text UTF-8/UTF-16 is filtered. Opaque formats are not asserted credential-free;
    only visible credential signatures are checked, without unpacking containers.
    """
    path = Path(path)
    if is_vault_path(path):
        raise CredentialFileBlocked('vault_file_excluded')
    if path.name.lower() in ('auth.json', 'credentials.json', 'id_rsa', 'id_ed25519', '.env') or path.suffix.lower() in ('.p12', '.pfx', '.key'):
        raise CredentialFileBlocked('known_credential_file_excluded')
    if captured_bytes is None:
        with path.open('rb') as handle:
            header = handle.read(8)
            if is_vault_bytes(header):
                raise CredentialFileBlocked('vault_signature_excluded')
            data = header + handle.read()
    else:
        if not isinstance(captured_bytes,bytes):raise TypeError('captured_bytes must be bytes')
        data=captured_bytes
        if is_vault_bytes(data[:8]):
            raise CredentialFileBlocked('vault_signature_excluded')
    encoding = 'utf-16' if data.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8'
    try:
        decoded = data.decode(encoding)
        if '\x00' in decoded and encoding == 'utf-8': raise UnicodeError()
    except UnicodeError:
        # Scans explicit ASCII and UTF-16 spellings, never persists decoded data.
        for decoded in (data.decode('ascii', errors='replace'), data.decode('utf-16-le', errors='ignore'), data.decode('utf-16-be', errors='ignore')):
            _, changes = redact(decoded)
            if changes: raise CredentialFileBlocked('explicit_credential_in_binary_file')
        return data, [], 'opaque_bytes_explicit_patterns_only'
    safe, changes = redact(decoded)
    return (safe.encode(encoding) if changes else data), changes, 'text_explicit_credentials'
