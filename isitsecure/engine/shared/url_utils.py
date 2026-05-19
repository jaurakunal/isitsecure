"""Shared URL utility functions for deep security scanners."""

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


def inject_query_param(url: str, param_name: str, value: str) -> str:
    """Inject or replace a query parameter in a URL.

    Args:
        url: The original URL.
        param_name: The query parameter name to inject or replace.
        value: The value to set for the parameter.

    Returns:
        A new URL string with the parameter set to the given value.
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param_name] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))
