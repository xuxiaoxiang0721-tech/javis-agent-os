"""Cloud-worker access within the user's explicit local privacy boundary.

The native CLI keeps its normal local authentication. Its tools get only the
current role/task and approved ordinary sources, never the complete archive.
No danger-full-access, global configuration mutation, or privilege escalation.
"""
import ast
import json
import os
from pathlib import Path
import re
import shutil
import stat
import uuid

PROFILE = 'javis_private_worker'
MODEL_KEYS = {'model', 'model_reasoning_effort', 'model_reasoning_summary',
              'model_provider', 'cli_auth_credentials_store', 'forced_login_method'}
SECRET_NAMES = {'auth.json', 'credentials.json', 'credentials', '.env', '.netrc',
                '.npmrc', '.pypirc', 'id_rsa', 'id_ed25519'}


def _absolute(path):
    path = Path(path).expanduser()
    if not path.is_absolute(): raise ValueError('permission path must be absolute')
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink(): raise ValueError('permission/input paths cannot contain symlinks')
    return path.resolve()


def blocked_roots(root, home=None, codex_home=None):
    root = Path(root).resolve(); home = Path(home or Path.home())
    values = [root/name for name in ('raw', 'memory', 'backups', 'state')]
    values += [root/'tools/neo4j/data', root/'tools/graphiti/.env',
               home/'.codex', home/'.ssh', home/'.aws', home/'.azure', home/'.config',
               Path('/mnt/c/Users/user/Javis-Vault'), Path('/mnt/c/Users/user/Javis-Exchange'),
               Path('/mnt/c/Users/user/.codex'), Path('/mnt/c/Users/user/AppData/Local/Temp')]
    if codex_home: values.append(Path(codex_home).resolve())
    return tuple(dict.fromkeys(values))


def _within(path, roots):
    return any(path == root or path.is_relative_to(root) for root in roots)


def _ordinary_name(path):
    return not any(part.lower() in SECRET_NAMES or part.lower().endswith('.env')
                   or part.lower() in {'.ssh', '.codex', '.aws', '.azure'} for part in path.parts)


def approved_input_source(root, task, role_dir, source):
    """Validate BEFORE the trusted runtime copies a file into a visible task."""
    path = _absolute(source)
    allowed = (_absolute(task), _absolute(role_dir),
               _absolute(Path(root)/'workspace/inbox/ordinary-approved'))
    if _within(path, blocked_roots(root)) or not _within(path, allowed) or not _ordinary_name(path):
        raise ValueError('input source is not approved for cloud tools; stage an ordinary non-L4 copy in workspace/inbox/ordinary-approved')
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('input must be an ordinary file without hardlinks')
    return path


def _directory_fd(path):
    """Walk from / using no-follow directory descriptors, not checked strings."""
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts:raise ValueError('directory must be absolute without traversal')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child
        return fd
    except BaseException:
        os.close(fd);raise


def secure_input_bytes(path):
    """Hold one regular source inode across capture, checking read-time changes."""
    path=Path(path);parent=_directory_fd(path.parent)
    try:fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
    finally:os.close(parent)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1:
            raise ValueError('input inode must be a regular unlinked file')
        data=stream.read();after=os.fstat(stream.fileno())
        signature=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns,value.st_nlink)
        if signature(before)!=signature(after) or len(data)!=after.st_size:
            raise ValueError('input changed during verified capture')
    return data


def write_input_copy(task, name, data):
    """Never follow an old task/in directory or overwrite a linked target inode."""
    if Path(name).name!=name or name in {'.','..'}:raise ValueError('invalid input copy name')
    task_fd=_directory_fd(task)
    try:
        try:os.mkdir('in',mode=0o700,dir_fd=task_fd)
        except FileExistsError:pass
        directory=os.open('in',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=task_fd)
    finally:os.close(task_fd)
    return _replace_verified(directory,name,data,Path(task)/'in'/name)


def write_verified_file(path,data):
    """Trusted output sanitation/receipt copy without following worker aliases."""
    path=Path(path)
    return _replace_verified(_directory_fd(path.parent),path.name,data,path)


def _replace_verified(directory,name,data,path):
    temporary='.javis-file-'+uuid.uuid4().hex
    try:
        try:prior=os.stat(name,dir_fd=directory,follow_symlinks=False)
        except FileNotFoundError:prior=None
        if prior and (not stat.S_ISREG(prior.st_mode) or prior.st_nlink!=1):
            raise ValueError('existing input copy is linked or not an ordinary file')
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
        with os.fdopen(fd,'wb') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        # Even a target substitution after lstat is replaced as a directory
        # entry; its symlink/hardlink target is never opened or modified.
        os.replace(temporary,name,src_dir_fd=directory,dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:os.unlink(temporary,dir_fd=directory)
        except FileNotFoundError:pass
        os.close(directory)
    return path


def _check_visible_tree(directory):
    # An alias inside a granted tree must not expose a private inode elsewhere.
    # Do not follow links or print file contents/names in a failure explanation.
    for base, dirs, files in os.walk(directory, followlinks=False):
        for name in dirs + files:
            path = Path(base)/name; info = path.lstat()
            if stat.S_ISLNK(info.st_mode): raise ValueError('visible task/role contains a symlink; review its source before cloud execution')
            if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                raise ValueError('visible task/role contains a hardlink; review its source before cloud execution')


def retained_model_config(codex_home):
    """Read only recognized top-level nonsecret choices; never load auth files."""
    path = Path(codex_home)/'config.toml'
    if not path.is_file(): return {}
    result = {}; section = False
    with path.open(encoding='utf-8') as stream:
        for raw in stream:
            line = raw.strip()
            if line.startswith('['): section = True
            if section: continue
            match = re.match(r'([A-Za-z_][A-Za-z_0-9]*)\s*=\s*(.*)', line)
            if not match or match[1] not in MODEL_KEYS: continue
            literal = match[2].split('#', 1)[0].strip()
            try: value = ast.literal_eval(literal)
            except (ValueError, SyntaxError): raise ValueError('native model/auth-storage configuration needs review')
            if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9._:/-]{1,128}', value):
                raise ValueError('native model/auth-storage configuration needs review')
            if match[1] == 'model_provider' and value != 'openai':
                raise ValueError('custom native provider needs an explicit private-worker configuration')
            result[match[1]] = value
    return result


def _reject_project_config(role_dir, codex_home):
    # --ignore-user-config deliberately keeps authentication but drops legacy
    # global sandbox_mode. Other local config layers must not override this.
    user_config = Path(codex_home)/'config.toml'
    for directory in (Path(role_dir), *Path(role_dir).parents):
        path = directory/'.codex/config.toml'
        if path == user_config: continue
        if path.exists():
            raise ValueError('project Codex config must be reviewed before applying the private-worker profile')


def native_environment():
    """Only verified runtime necessities; credentials remain in CLI auth storage."""
    home = Path.home(); source = os.environ
    env = {'HOME':str(home), 'PATH':str(home/'.local/node/bin')+':/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
           'LANG':'C.UTF-8', 'LC_ALL':'C.UTF-8', 'TZ':'Asia/Shanghai', 'PYTHONDONTWRITEBYTECODE':'1'}
    for key in ('USER', 'LOGNAME'):
        value = source.get(key, '')
        if re.fullmatch(r'[A-Za-z0-9_-]{1,80}', value): env[key] = value
    if source.get('CODEX_HOME'): env['CODEX_HOME'] = str(_absolute(source['CODEX_HOME']))
    # These are existing non-authenticated local transport endpoints, not a
    # grant for tool network access. Do not inherit arbitrary proxy credentials.
    for key in ('http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'):
        value = source.get(key, source.get('http_proxy', ''))
        if value and not re.fullmatch(r'https?://(?:127\.0\.0\.1|localhost|\[::1\]):[0-9]{1,5}/?', value):
            raise ValueError('native proxy must be a reviewed credential-free loopback endpoint')
        if value: env[key] = value
    env['no_proxy'] = 'localhost,127.0.0.1,::1'
    return env


def _toml_table(values):
    return '{' + ', '.join(json.dumps(str(k))+' = '+json.dumps(v) for k,v in values.items()) + '}'


def launch(root, task, role_dir, permission, session_id=None):
    if permission not in {'R0', 'R1'}: raise ValueError('native access requires R0 or R1')
    root = Path(root).resolve(); task = _absolute(task); role_dir = _absolute(role_dir)
    if not task.is_relative_to(root/'workspace/tasks') or not role_dir.is_relative_to(root/'workspace/roles'):
        raise ValueError('native role/task roots are outside the authorized workspace')
    env = native_environment(); home = Path(env['HOME']); codex_home = Path(env.get('CODEX_HOME', home/'.codex'))
    _reject_project_config(role_dir, codex_home)
    _check_visible_tree(task); _check_visible_tree(role_dir)
    retained = retained_model_config(codex_home)
    access = 'read' if permission == 'R0' else 'write'
    output=_absolute(task/'out')
    if not output.is_dir():raise ValueError('task output directory must exist before launch')
    filesystem = {':minimal':'read', str(role_dir):'read', str(task):'read',str(output):access,
                  str(home/'.local/node/bin'):'read',
                  str(home/'.local/node/lib/node_modules/@openai/codex'):'read',
                  str(root/'scripts'):'read'}
    # Read only the common rules and explicitly ordinary technical docs. Raw
    # backups/imports, all other tasks/roles and unclassified docs are absent.
    for path in (root/'workspace/AGENTS.md', role_dir/'AGENTS.md', root/'docs/codex-access-policy.md'):
        if path.is_file() and not path.is_symlink(): filesystem[str(path)] = 'read'
    for path in blocked_roots(root, home, codex_home): filesystem[str(path)] = 'deny'
    for directory in (role_dir, task):
        for name in SECRET_NAMES | {'.ssh', '.codex', '.aws', '.azure'}:
            # 0.154 treats an absent exact deny as a file placeholder. Its
            # protected .codex directory can then conflict during R1 setup.
            # Existing sensitive paths are denied; absent ones hold no data.
            if (directory/name).exists(): filesystem[str(directory/name)] = 'deny'
        for base, _, files in os.walk(directory, followlinks=False):
            for name in files:
                path = Path(base)/name
                if not _ordinary_name(path): filesystem[str(path)] = 'deny'
    options = {'default_permissions':PROFILE,
               'permissions.'+PROFILE+'.filesystem':filesystem,
               'permissions.'+PROFILE+'.network.enabled':False,
               'shell_environment_policy.inherit':'none',
               'shell_environment_policy.set':{k:env[k] for k in ('HOME','PATH','LANG','LC_ALL','TZ')},
               **retained}
    binary = os.environ.get('JAVIS_CODEX_BIN') or shutil.which('codex', path=env['PATH'])
    if not binary: raise ValueError('native Codex binary is unavailable')
    cmd = [binary, '-a', 'never', 'exec', '--json', '--skip-git-repo-check', '--ignore-user-config', '--strict-config']
    for key, value in options.items():
        cmd += ['-c', key+'='+(_toml_table(value) if isinstance(value,dict) else json.dumps(value))]
    if session_id: cmd += ['resume', session_id, '--ignore-user-config']
    cmd += ['-']
    evidence = {'profile':PROFILE, 'approval_policy':'never', 'permission':permission,
                'filesystem':filesystem, 'network_enabled':False,
                'user_config_ignored_for_permissions':True, 'retained_native_choices':retained,
                'authentication':'existing CODEX_HOME; tool filesystem denies auth directory',
                'boundary':'role and task metadata read-only; only out writable in R1, including untrusted proposals; full archives remain local'}
    return cmd, env, evidence
