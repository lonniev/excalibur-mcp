"""Server-side 'Refine with Claude' for the editorial editor.

The operator's Anthropic key stays in the vault and never leaves the server.
The editor sends a flagged region + the surrounding tweet + the editor's
voice/bans, and gets back 3 alternative phrasings. The wheel meters the call
as a paid tollbooth fare — so the AI usage is billed in sats, not handed out
as a raw key (no browser exposure, no un-tolled usage).
"""

from __future__ import annotations

import json
import logging

import httpx

logger = logging.getLogger(__name__)

_MODEL = "claude-sonnet-4-6"
_ENDPOINT = "https://api.anthropic.com/v1/messages"
_TIMEOUT = 60.0
_MAX_TOKENS = 1000


def _build_prompt(
    region: str, full_text: str, instruction: str, voice: str, bans: list[str],
) -> tuple[str, str]:
    system = (
        "You are an editorial copy assistant working on a single tweet for X. "
        "You rewrite only the flagged region, keeping it consistent with the rest "
        "of the tweet. "
        + (f"Match this voice profile exactly: {voice}. " if voice.strip() else "")
        + (
            f"Hard constraints — never produce any of these AI tells: {'; '.join(bans)}. "
            if bans else ""
        )
        + "Keep it tight enough for X. Prefer plain verbs and concrete nouns. "
        "Respond ONLY with a JSON array of exactly 3 alternative strings for the "
        "region. No markdown, no preamble."
    )
    user = (
        f"FULL TWEET:\n{full_text}\n\n"
        f'FLAGGED REGION:\n"{region}"\n\n'
        "WHAT THE EDITOR WANTS:\n"
        + (instruction.strip() or "Make it sharper and more human. Remove any AI-sounding phrasing.")
    )
    return system, user


def _parse_suggestions(raw: str) -> list[str]:
    """Parse Claude's reply into up to 3 strings — JSON array first, then lines."""
    t = (raw or "").replace("```json", "").replace("```", "").strip()
    try:
        arr = json.loads(t)
        if isinstance(arr, list):
            return [str(x) for x in arr if str(x).strip()][:3]
    except (json.JSONDecodeError, TypeError):
        pass
    out: list[str] = []
    for line in t.splitlines():
        cleaned = line.lstrip(" \t-*0123456789.)\"'").strip()
        if cleaned:
            out.append(cleaned)
    return out[:3]


async def refine_region(
    *,
    api_key: str,
    region: str,
    full_text: str,
    instruction: str = "",
    voice: str = "",
    bans: list[str] | None = None,
) -> list[str]:
    """Call Anthropic server-side with the operator's key. Returns ≤3 suggestions.

    Raises on transport/HTTP errors so the caller can refund the fare.
    """
    system, user = _build_prompt(region, full_text, instruction, voice, bans or [])
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(
            _ENDPOINT,
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": _MODEL,
                "max_tokens": _MAX_TOKENS,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
        )
    resp.raise_for_status()
    data = resp.json()
    text = "".join(
        b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"
    )
    return _parse_suggestions(text)
