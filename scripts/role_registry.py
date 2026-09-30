"""Example local Bot connections for the public source release.

All numeric and UUID identities below are synthetic placeholders. Configure
your own verified bot identity mappings before enabling external dispatch. Technical identity only; no business routing.

This is the single enabled-role registry. routing.json remains the existing
workspace/name reference; its additional roles do not grant execution permission.
Bot identifiers are public source identifiers, never authentication credentials.
"""
import json
from pathlib import Path
from types import MappingProxyType


_ROWS = (
    ('gpt-star', 'Grok Star', '100001', None, 'gpt-star-drop'),
    ('invest', 'Invest bot', '100002', None, 'invest-drop'),
    ('operations', 'Operations', None, '00000000-0000-4000-8000-000000000001', 'operations-drop'),
    ('property', '地产', None, '00000000-0000-4000-8000-000000000006', 'property-drop'),
    ('idea-lab', 'Idea Lab', None, '00000000-0000-4000-8000-000000000002', 'idea-lab-drop'),
    ('cards-master', 'Cards Master', '100003', None, 'cards-drop'),
    ('personal-life', "Personal Life", None, '00000000-0000-4000-8000-000000000007', 'personal-life-drop'),
    ('ai-data', 'AI 数据', None, '00000000-0000-4000-8000-000000000010', 'ai-data-drop'),
    ('domestic-fund', '国内基金', None, '00000000-0000-4000-8000-000000000008', 'domestic-fund-drop'),
    ('javis', 'Javis', None, '00000000-0000-4000-8000-000000000005', 'javis-drop'),  # Javis260926 design/build discussion role
    ('friday', 'Friday', None, '00000000-0000-4000-8000-000000000004', 'friday-drop'),  # Javis260926 design/build discussion role
    ('toolgo', 'toolgo', None, '00000000-0000-4000-8000-000000000013', 'toolgo-drop'),  # Javis260926 design/build discussion role
)
ROLE_REGISTRY = MappingProxyType({role: MappingProxyType(dict(
    role_id=role, label=label, bot_id=bot_id, exported_agent_id=exported_agent_id,
    origin_id=bot_id or 'grok-export-agent:' + exported_agent_id,
    identity_source=('existing documented runtime numeric id' if bot_id else
                     'imported BOT-META agent_id; upstream runtime numeric id unverified'),
    cwd='workspace/roles/' + role, drop_dir=drop_dir))
    for role, label, bot_id, exported_agent_id, drop_dir in _ROWS})
ROLE_IDS = frozenset(ROLE_REGISTRY)
ROLE_ORIGINS = MappingProxyType({role: row['origin_id'] for role, row in ROLE_REGISTRY.items()})
DROP_DIRS = MappingProxyType({role: row['drop_dir'] for role, row in ROLE_REGISTRY.items()})


def get_role(role_id):
    if not isinstance(role_id, str) or role_id not in ROLE_REGISTRY:
        raise ValueError('role is not authorized for local Bot execution')
    return ROLE_REGISTRY[role_id]


def role_workspace(root, role_id):
    """Select the exact role cwd. Never follow a role or parent symlink.

Codex reads this role cwd and its task; R1 writes only the task out directory.
This is workspace separation, not an OS account isolation boundary.
"""
    row = get_role(role_id)
    root = Path(root).resolve()
    routing = root / 'config/routing.json'
    if routing.exists():
        try:
            configured = json.loads(routing.read_text(encoding='utf-8-sig'))['roles'][role_id]['cwd']
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise ValueError('role workspace configuration is missing or invalid') from exc
        if configured != row['cwd']:
            raise ValueError('role workspace configuration differs from authorized registry')
    path = root
    for part in Path(row['cwd']).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError('role workspace links are not accepted')
    if not path.is_dir() or path.resolve() != root / row['cwd']:
        raise ValueError('authorized role workspace is unavailable')
    return path
