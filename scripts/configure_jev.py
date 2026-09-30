"""Read-only status or an explicit, TTY-only TypeSafe secret update.

The key is never accepted in argv, printed, backed up, or sent to the provider.
Run in Javis's Linux/WSL environment, whose ownership/mode semantics we verify.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import stat
import sys
import uuid
import warnings

from jev_client import CODE_ROOT, _key, credentials_status


class ConfigureJevError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _check_owner(info, *, directory=False):
    if (info.st_uid != os.geteuid() or
            (not stat.S_ISDIR(info.st_mode) if directory else
             not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077)):
        raise ConfigureJevError("jev_unsafe_credentials_path")


def _open_root(root):
    if not hasattr(os, "geteuid") or not hasattr(os, "O_NOFOLLOW"):
        raise ConfigureJevError("jev_configuration_requires_posix")
    path = Path(os.path.abspath(root))
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        # Walk every component through descriptors: a symlink or concurrent
        # ancestor substitution must not redirect the secret write.
        for name in path.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        _check_owner(info, directory=True)
        if info.st_mode & 0o022:
            raise ConfigureJevError("jev_unsafe_credentials_path")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _directory(parent_fd, name, *, private=False):
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except FileExistsError:
        pass
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
    try:
        info = os.fstat(fd)
        _check_owner(info, directory=True)
        if private:
            os.fchmod(fd, 0o700)
            os.fsync(fd)
        elif info.st_mode & 0o022:
            raise ConfigureJevError("jev_unsafe_credentials_path")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _existing(directory_fd):
    try:
        info = os.stat(".env", dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    _check_owner(info)
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def set_key(root):
    """Prompt privately, then replace only tools/typesafe/.env atomically."""
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ConfigureJevError("jev_key_input_requires_tty")
    try:
        with warnings.catch_warnings():
            # Refuse getpass's fallback to potentially echoed input when the
            # terminal says TTY but its echo controls are unavailable.
            warnings.simplefilter("error", getpass.GetPassWarning)
            entered = getpass.getpass("TypeSafe API key (hidden): ")
    except (EOFError, KeyboardInterrupt):
        raise ConfigureJevError("jev_key_input_cancelled") from None
    except (getpass.GetPassWarning, OSError):
        raise ConfigureJevError("jev_hidden_input_unavailable") from None
    if (not isinstance(entered, str) or any(ord(char) < 32 or ord(char) == 127 for char in entered)):
        raise ConfigureJevError("jev_invalid_api_key")
    key = _key(entered)
    if not key:
        raise ConfigureJevError("jev_invalid_api_key")
    quote = "'" if "'" not in key else '"' if '"' not in key else None
    if quote is None:
        raise ConfigureJevError("jev_invalid_api_key")
    content = ("TYPESAFE_API_KEY=" + quote + key + quote + "\n").encode("utf-8")
    descriptors = []
    temporary = None
    directory_fd = None
    try:
        root_fd = _open_root(root)
        descriptors.append(root_fd)
        tools_fd = _directory(root_fd, "tools")
        descriptors.append(tools_fd)
        directory_fd = _directory(tools_fd, "typesafe", private=True)
        descriptors.append(directory_fd)
        previous = _existing(directory_fd)
        # Existing backup policy excludes .env and .env.*. Keep crash leftovers
        # under that same exclusion, without creating any secret backup copy.
        temporary = ".env.jev-key-" + uuid.uuid4().hex + ".tmp"
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory_fd)
        with os.fdopen(fd, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            _check_owner(os.fstat(handle.fileno()))
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if _existing(directory_fd) != previous:
            raise ConfigureJevError("jev_credentials_changed_during_update")
        os.replace(temporary, ".env", src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        temporary = None
        os.fsync(directory_fd)
    except ConfigureJevError:
        raise
    except Exception:
        raise ConfigureJevError("jev_credentials_write_failed") from None
    finally:
        if temporary is not None and directory_fd is not None:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except OSError:
                pass
        for fd in reversed(descriptors):
            os.close(fd)


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default includes unknown argv values, possibly a key that
        # somebody accidentally supplied. Never echo arguments in an error.
        self.exit(2, "jev_invalid_arguments\n")


def _resume_rejected(root):
    # Imported only after an explicit successful write. The queue implementation
    # owns its maintenance/worker locks and never makes a provider request here.
    from memory_pipeline import resume_credentials
    value = resume_credentials(root)
    count = value.get("resumed") if isinstance(value, dict) else value
    if type(count) is not int or count < 0:
        raise ValueError("invalid_resume_result")
    return count


def main(argv=None):
    parser = _Parser(description="Configure TypeSafe using hidden terminal input, or show safe credential status.")
    parser.add_argument("--root", type=Path, default=CODE_ROOT)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--status", action="store_true")
    action.add_argument("--set-key", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.set_key:
            set_key(args.root)
            # Read through the same rules as the worker. Environment variables
            # still take precedence; saving a file never mutates the environment.
        result = credentials_status(args.root)
    except ConfigureJevError as exc:
        print(json.dumps({"configured": False, "status": exc.code}))
        return 1
    except Exception:
        print(json.dumps({"configured": False, "status": "jev_configuration_failed"}))
        return 1
    if args.set_key:
        # This is deliberately separate from the write failure handler: even if
        # queue recovery fails, the key is already saved and must be reported so.
        result["key_saved"] = True
        try:
            result.update(resumed=_resume_rejected(args.root), resume_status="resumed")
        except Exception:
            result.update(resumed=None, resume_status="resumed_error")
            print(json.dumps(result))
            return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
