"""Campaign tags on shop links, added the moment a post is sent.

A shop's order page can say which post brought a buyer in only if the link they
followed said so. The tags are added here, at send time, rather than typed into
each post: half the posts have links the AI writer composes fresh on every
firing, and only the publisher knows the id of the copy going out.

Every link to one of the owner's shop hosts gets

    utm_source=x|nostr  utm_medium=social
    utm_campaign=<the post's id>  utm_content=<this sent copy's id>

For a recurring post the campaign is the template, which stays the same on every
firing, and the content is the occurrence, so a buyer is traced to one day's
tweet. A one-off post is its own campaign and its own copy.

A link that already carries any ``utm_`` parameter is the author's own tagging
and is left alone, as is every link to a host not on the list. The rest of the
text is untouched, so the link X turns into its preview card stays where it was.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

# A bare URL in post copy. It stops at whitespace and at the brackets and quotes
# copy wraps links in; trailing sentence punctuation is trimmed off afterwards.
_URL_RE = re.compile(r"https?://[^\s<>\"'()\[\]{}]+")
_TRAILING = ".,;:!?…"

_MEDIUM = "social"


def _hosts(hosts: Iterable[str]) -> frozenset[str]:
    return frozenset(h.strip().lower() for h in hosts if h and h.strip())


def _tag_one(url: str, hosts: frozenset[str], params: dict[str, str]) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    if (parts.hostname or "").lower() not in hosts:
        return url
    keys = [p.split("=", 1)[0].lower() for p in parts.query.split("&") if p]
    if any(k.startswith("utm_") for k in keys):
        return url
    query = "&".join(q for q in (parts.query, urlencode(params)) if q)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def tag_links(
    text: str, *, hosts: Iterable[str], source: str, campaign: str, content: str,
) -> str:
    """``text`` with every link to one of ``hosts`` carrying campaign tags."""
    allowed = _hosts(hosts)
    if not text or not allowed:
        return text
    params = {
        "utm_source": source,
        "utm_medium": _MEDIUM,
        "utm_campaign": campaign,
        "utm_content": content,
    }

    def _sub(m: re.Match[str]) -> str:
        url = m.group(0)
        tail = ""
        while url and url[-1] in _TRAILING:
            url, tail = url[:-1], url[-1] + tail
        return _tag_one(url, allowed, params) + tail

    return _URL_RE.sub(_sub, text)


def owner_hosts(link_tags: Any, default_hosts: Iterable[str]) -> list[str]:
    """The hosts an owner's posts are tagged for; empty means tagging is off.

    ``link_tags`` is the owner's saved setting, ``{"on": bool, "hosts": [...]}``.
    An owner who has saved nothing is tagged for the operator's default hosts.
    """
    if not isinstance(link_tags, dict):
        return list(default_hosts)
    if link_tags.get("on") is False:
        return []
    hosts = link_tags.get("hosts")
    if isinstance(hosts, list) and hosts:
        return [h for h in hosts if isinstance(h, str)]
    return list(default_hosts)
