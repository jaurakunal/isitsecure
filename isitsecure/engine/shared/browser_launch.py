"""Shared Chromium launch options for the contained pentest lockdown.

On the host — every ``scan`` crawl and non-contained pentest browser — this contributes
**nothing**, so browser behavior is byte-identical. Only when the agent runs inside the
contained lockdown (the ``ISITSECURE_CONTAINED`` sentinel is set) does it route the
browser through the egress proxy, so the browser's traffic is subject to the same scope
allowlist as every other request AND can reach allowlisted hosts at all (the contained
agent has no direct route off the private internal network — the proxy is its sole exit).
"""

from __future__ import annotations

import os
from typing import Any

# Set inside the contained container (mirrors containment.CONTAINED_ENV); read by name
# here so this scanner-side helper takes no dependency on the pentest package.
_CONTAINED_ENV = "ISITSECURE_CONTAINED"

# Chromium flags that keep headless Chrome alive under the container's constraints:
# - ``--disable-dev-shm-usage`` routes shared memory to the (256m tmpfs) /tmp instead of
#   the small /dev/shm, the fix for the ``ERR_INSUFFICIENT_RESOURCES`` renderer crashes a
#   heavy SPA triggers under the lockdown's read-only rootfs.
# - ``--disable-gpu`` — no GPU in the container; avoids a pointless init path.
_CONTAINED_CHROMIUM_ARGS = ("--disable-dev-shm-usage", "--disable-gpu")


def contained_browser_launch_kwargs() -> dict[str, Any]:
    """Extra ``chromium.launch`` kwargs for the contained lockdown (``{}`` on the host).

    When running contained: adds container-survival Chromium ``args`` and, when a proxy is
    set in the environment (``HTTPS_PROXY``/``HTTP_PROXY``), routes the browser through it
    (the contained agent's only route off the private internal network). OFF the lockdown
    it returns ``{}`` — so the host launch is untouched and scan stays byte-identical.
    """
    if not os.environ.get(_CONTAINED_ENV):
        return {}
    kwargs: dict[str, Any] = {"args": list(_CONTAINED_CHROMIUM_ARGS)}
    proxy = (
        os.environ.get("HTTPS_PROXY")
        or os.environ.get("https_proxy")
        or os.environ.get("HTTP_PROXY")
        or os.environ.get("http_proxy")
    )
    if proxy:
        kwargs["proxy"] = {"server": proxy}
    return kwargs
