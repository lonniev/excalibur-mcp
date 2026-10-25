"""Voice CRUD tool handlers.

Thin orchestration over ``db.voices``: validate adversarial tool input and keep
handlers npub-scoped (a patron only ever reaches their own Voice). These tools
are priceable (read/write, proof-gated) — they begin unpriced and the operator
sets a price in Pricing Studio. Invalid input ``raise ValueError`` and the
``catch_errors`` wrapper refunds any debit and returns ``tool_input_invalid``.

The Voice is a per-npub singleton: one profile blurb plus a list of "banned
construction" chips (``{text, on}``) the editor passes to ``refine_post_region``.
It also carries ``link_tags``, the owner's shop-link tagging (see ``utm.py``).
"""

from __future__ import annotations

import logging
import re
from typing import Any

from excalibur_mcp.db import voices as voices_db

logger = logging.getLogger(__name__)

_PROFILE_MAX = 4000
_BAN_MAX = 200
_BANS_MAX = 200
_HOSTS_MAX = 20
_HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


def _clean_profile(profile: Any) -> str:
    if profile is None:
        return ""
    if not isinstance(profile, str):
        raise ValueError("profile must be a string")
    if len(profile) > _PROFILE_MAX:
        raise ValueError(f"profile exceeds {_PROFILE_MAX} characters")
    return profile


def _clean_bans(bans: Any) -> list[dict[str, Any]]:
    """Normalize an adversarial ``bans`` input into a clean ``[{text, on}]`` list.

    Drops blank/oversized entries and de-dupes by text (case-insensitive,
    last-wins) so the stored list stays tidy. Each entry must be an object with a
    string ``text``; ``on`` coerces to a bool, defaulting to ``True``.
    """
    if bans is None:
        return []
    if not isinstance(bans, list):
        raise ValueError("bans must be a list")
    out: list[dict[str, Any]] = []
    seen: dict[str, int] = {}
    for entry in bans:
        if not isinstance(entry, dict):
            raise ValueError("each ban must be an object with text and on")
        text = entry.get("text")
        if not isinstance(text, str):
            raise ValueError("each ban must have a string text")
        text = text.strip()
        if not text:
            continue
        if len(text) > _BAN_MAX:
            raise ValueError(f"a ban exceeds {_BAN_MAX} characters")
        on = bool(entry.get("on", True))
        key = text.lower()
        if key in seen:
            out[seen[key]] = {"text": text, "on": on}
        else:
            seen[key] = len(out)
            out.append({"text": text, "on": on})
    if len(out) > _BANS_MAX:
        raise ValueError(f"too many bans (max {_BANS_MAX})")
    return out


def _clean_link_tags(link_tags: Any) -> dict[str, Any] | None:
    """Normalize ``{"on": bool, "hosts": [host, ...]}``; ``None`` keeps the saved one.

    Hosts are bare hostnames, lower-cased and de-duped. An empty host list with
    tagging on means the operator's default hosts."""
    if link_tags is None:
        return None
    if not isinstance(link_tags, dict):
        raise ValueError("link_tags must be an object with on and hosts")
    hosts = link_tags.get("hosts", [])
    if hosts is None:
        hosts = []
    if not isinstance(hosts, list):
        raise ValueError("link_tags.hosts must be a list of hostnames")
    clean: list[str] = []
    for host in hosts:
        if not isinstance(host, str):
            raise ValueError("each link_tags host must be a string")
        h = host.strip().lower()
        if not h:
            continue
        if not _HOST_RE.match(h):
            raise ValueError(f"not a hostname: {host[:80]!r}")
        if h not in clean:
            clean.append(h)
    if len(clean) > _HOSTS_MAX:
        raise ValueError(f"too many link_tags hosts (max {_HOSTS_MAX})")
    return {"on": bool(link_tags.get("on", True)), "hosts": clean}


def _shown(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "profile": row.get("profile") or "",
        "bans": row.get("bans") or [],
        "link_tags": row.get("link_tags"),
        "updated_at": row.get("updated_at"),
    }


async def get(npub: str) -> dict[str, Any]:
    """Read the patron's saved Voice. Returns an empty Voice (not an error) when
    none has been saved yet, so the editor can seed its own defaults."""
    row = await voices_db.get_voice(npub)
    if row is None:
        return {"success": True, "voice": {"profile": "", "bans": [], "link_tags": None}}
    return {"success": True, "voice": _shown(row)}


async def save(
    npub: str, *, profile: Any = "", bans: Any = None, link_tags: Any = None,
) -> dict[str, Any]:
    """Create or replace the patron's single Voice; returns the stored row."""
    clean_profile = _clean_profile(profile)
    clean_bans = _clean_bans(bans)
    clean_tags = _clean_link_tags(link_tags)
    row = await voices_db.upsert_voice(npub, clean_profile, clean_bans, clean_tags)
    return {"success": True, "voice": _shown(row)}
