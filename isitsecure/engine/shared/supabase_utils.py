"""Shared Supabase parsing utilities.

Extracts table names from:
- Supabase REST API URLs (``/rest/v1/profiles?select=*``)
- JavaScript SDK calls (``.from('profiles')``, ``.rpc('get_stats')``)
- Intercepted network traffic (response bodies with table-like structures)

Used by ``AuthenticatedCrawler``, ``EndpointDiscoveryScanner``,
``PrivilegeEscalationScanner``, and the main agent orchestrator.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from isitsecure.engine.constants import (
    AuthenticatedCrawlerConfig,
    EndpointDiscoveryConfig,
)


def extract_supabase_table_from_url(url: str) -> str | None:
    """Extract the table name from a Supabase REST URL.

    Given ``https://xyz.supabase.co/rest/v1/profiles?select=*``,
    returns ``"profiles"``.  Returns ``None`` for non-Supabase URLs
    or for the ``rpc`` pseudo-table.
    """
    if AuthenticatedCrawlerConfig.SUPABASE_REST_INDICATOR not in url:
        return None

    parsed = urlparse(url)
    parts = parsed.path.split(
        AuthenticatedCrawlerConfig.SUPABASE_REST_INDICATOR
    )
    if len(parts) < 2:
        return None

    table = parts[1].split("?")[0].split("/")[0]
    if not table or table == AuthenticatedCrawlerConfig.RPC_PATH_SEGMENT:
        return None

    return table


def extract_tables_from_js(js_content: str) -> list[str]:
    """Extract Supabase table names from JavaScript bundle content.

    Parses ``.from('table_name')`` and ``.rpc('function_name')`` calls
    from the client-side Supabase SDK.  Works even when the REST API is
    locked down with ``service_role`` — the client SDK still references
    table names in the JS bundle.

    Returns:
        Deduplicated list of table names found in the JS content.
    """
    tables: list[str] = []
    seen: set[str] = set()

    # .from('table_name') — the primary pattern
    for match in re.finditer(
        EndpointDiscoveryConfig.SUPABASE_FROM_PATTERN, js_content
    ):
        table = match.group(1)
        if table and table not in seen:
            seen.add(table)
            tables.append(table)

    return tables


def extract_rpc_functions_from_js(js_content: str) -> list[str]:
    """Extract Supabase RPC function names from JavaScript bundle content.

    Parses ``.rpc('function_name')`` calls from the client-side SDK.

    Returns:
        Deduplicated list of RPC function names.
    """
    functions: list[str] = []
    seen: set[str] = set()

    for match in re.finditer(
        EndpointDiscoveryConfig.SUPABASE_RPC_PATTERN, js_content
    ):
        func = match.group(1)
        if func and func not in seen:
            seen.add(func)
            functions.append(func)

    return functions
