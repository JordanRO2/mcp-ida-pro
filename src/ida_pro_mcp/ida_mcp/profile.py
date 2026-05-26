"""Compatibility shim. Canonical module: application.profile.

Kept so existing imports (`from .profile import load_profile`) keep working
until the tool-migration phase rewrites them to the canonical
``ida_pro_mcp.ida_mcp.application.profile`` path.
"""

from .application.profile import *  # noqa: F401,F403
from .application.profile import (  # noqa: F401
    parse_profile,
    load_profile,
    dump_profile,
    apply_profile,
)
