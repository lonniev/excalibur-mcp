"""Voice CRUD tool handlers.

Thin orchestration over ``db.voices``: validate adversarial tool input and keep
handlers npub-scoped (a patron only ever reaches their own Voice). These tools
are *free* (proof-gated, no fare), so there is no debit to roll back — invalid
input simply ``raise ValueError`` and the standard error wrapper returns
``tool_input_invalid``.

The Voice is a per-npub singleton: one profile blurb plus a list of "banned
construction" chips (``{text, on}``) the editor passes to ``refine_post_region``.
"""

from __future__ import annotations

import logging
from typing import Any

from excalibur_mcp.db import voices as voices_db

logger = logging.getLogger(__name__)

_PROFILE_MAX = 4000
_BAN_MAX = 200
_BANS_MAX = 200


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


async def get(npub: str) -> dict[str, Any]:
    """Read the patron's saved Voice. Returns an empty Voice (not an error) when
    none has been saved yet, so the editor can seed its own defaults."""
    row = await voices_db.get_voice(npub)
    if row is None:
        return {"success": True, "voice": {"profile": "", "bans": []}}
    return {
        "success": True,
        "voice": {
            "profile": row.get("profile") or "",
            "bans": row.get("bans") or [],
            "updated_at": row.get("updated_at"),
        },
    }


async def save(npub: str, *, profile: Any = "", bans: Any = None) -> dict[str, Any]:
    """Create or replace the patron's single Voice; returns the stored row."""
    clean_profile = _clean_profile(profile)
    clean_bans = _clean_bans(bans)
    row = await voices_db.upsert_voice(npub, clean_profile, clean_bans)
    return {
        "success": True,
        "voice": {
            "profile": row.get("profile") or "",
            "bans": row.get("bans") or [],
            "updated_at": row.get("updated_at"),
        },
    }
