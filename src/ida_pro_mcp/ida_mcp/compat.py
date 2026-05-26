"""Compatibility shim. Canonical module: infrastructure.compat.

Kept so existing imports (`from . import compat`) keep working until the
tool-migration phase rewrites them to the canonical
``ida_pro_mcp.ida_mcp.infrastructure.compat`` path.
"""

from .infrastructure.compat import *  # noqa: F401,F403
from .infrastructure.compat import (  # noqa: F401
    IDA_VERSION,
    IDA_GE_90,
    IDA_GE_85,
    IDA_GE_84,
    get_entry_qty,
    get_entry_ordinal,
    get_entry,
    get_entry_name,
    get_ordinal_limit,
    inf_get_min_ea,
    inf_get_max_ea,
    inf_get_omin_ea,
    inf_get_omax_ea,
    inf_is_64bit,
    get_func_name,
    get_func_prototype,
    raw_bin_search,
    make_bytes_searcher,
    guess_tinfo,
)
