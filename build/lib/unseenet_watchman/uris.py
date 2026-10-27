"""Links in a post, and the domain names to look up for them.

URI blocklists list domains, not whole URLs, so all that matters is the host of each
link. Hosts are lower-cased and IDNA-encoded; IP addresses and onion addresses are left
out (no URI list covers them). For each host the lookups are the host itself and its
parents down to two labels, at most three names: ``a.b.example.co.uk`` is looked up as
``a.b.example.co.uk``, ``b.example.co.uk`` and ``example.co.uk``. The lists themselves
answer for the registrable domain, so a few extra lookups are cheaper than shipping a
public-suffix list.
"""

from __future__ import annotations

import ipaddress
import re

# http(s) and www. links, also inside Markdown [text](url) and <url>
_URL = re.compile(r"(?i)\b(?:https?://|www\.)([^\s/?#<>()\[\]\"'`]+)")
MAX_HOSTS = 20          # per post: a post with more links is spam-shaped anyway
MAX_NAMES = 3           # lookups per host


def _clean_host(raw: str) -> str | None:
    host = raw.rsplit("@", 1)[-1]                 # user:pass@host
    if host.startswith("["):                       # [IPv6]
        return None
    host = host.split(":", 1)[0].strip(".").lower()
    if not host or "." not in host:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    if host.endswith(".onion"):
        return None
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not re.fullmatch(r"[a-z0-9.-]+", host) or ".." in host:
        return None
    return host


def hosts(text: str) -> list[str]:
    """The distinct hosts of the links in ``text``, in order, at most ``MAX_HOSTS``."""
    out: list[str] = []
    for m in _URL.finditer(text or ""):
        raw = m.group(1)
        if m.group(0).lower().startswith("www."):
            raw = "www." + raw
        h = _clean_host(raw.rstrip(".,;:!"))
        if h and h not in out:
            out.append(h)
            if len(out) >= MAX_HOSTS:
                break
    return out


def lookup_names(host: str) -> list[str]:
    """The names to look up for ``host``: itself and its parents down to two labels."""
    labels = host.split(".")
    if labels[0] == "www":
        labels = labels[1:]
    names = [".".join(labels[i:]) for i in range(len(labels) - 1)]
    return names[:MAX_NAMES]


def allowed(host: str, allow: set[str] | frozenset[str]) -> bool:
    """Whether ``host`` is, or is under, a domain in ``allow``."""
    return any(host == d or host.endswith("." + d) for d in allow)
