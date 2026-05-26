"""Compatibility shim. Canonical module: infrastructure.framework.

Kept so existing imports (`from ..framework import test, ...` in tests) keep
working until the tool-migration phase rewrites them to the canonical
``ida_pro_mcp.ida_mcp.infrastructure.framework`` path.
"""

from .infrastructure.framework import *  # noqa: F401,F403
from .infrastructure.framework import (  # noqa: F401
    TestInfo,
    TestResult,
    TestResults,
    TESTS,
    SkipTest,
    skip_test,
    test,
    run_tests,
    optional,
    list_of,
    one_of,
    is_hex_address,
    assert_valid_address,
    assert_non_empty,
    assert_is_list,
    assert_has_keys,
    assert_shape,
    assert_typed_dict,
    assert_ok,
    assert_error,
    get_any_function,
    get_named_function,
    get_named_address,
    get_string_address_containing,
    get_any_string,
    get_first_segment,
    get_data_address,
    get_unmapped_address,
    get_current_binary_name,
)
