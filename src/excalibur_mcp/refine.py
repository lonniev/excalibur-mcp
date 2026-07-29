"""Server-side editorial refinement for the post editor.

The operator's LLM key stays in the vault and never leaves the server. The
editor sends a flagged region + the surrounding tweet + the editor's voice/bans,
and gets back 3 alternative phrasings. The wheel meters the call as a paid
tollbooth fare — so the AI usage is billed in sats, not handed out as a raw key
(no browser exposure, no un-tolled usage).

Which provider and model answer is ``tollbooth.llm_route``'s decision. Suggesting
three short rewrites is judgement rather than authorship, so this draws the
cheaper reader tier — unlike ``resolve.py``, which composes copy the owner
publishes under their own name.
"""

from __future__ import annotations

import json
import logging

import httpx
from tollbooth.llm_route import TIER_READER, build_messages_request, resolve_route

logger = logging.getLogger(__name__)

_TIER = TIER_READER
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
    """Parse the model's reply into up to 3 strings — JSON array first, then lines."""
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
    """Call the provider server-side with the operator's key. Returns ≤3 suggestions.

    The caller supplies ``api_key``, which is what names the provider ACCOUNT this
    work bills to — so giving refinement its own account later is a different key
    at the call site, not a change here.

    Raises on transport/HTTP errors so the caller can refund the fare.
    """
    system, user = _build_prompt(region, full_text, instruction, voice, bans or [])
    req = build_messages_request(
        resolve_route(api_key=api_key, tier=_TIER),
        system=system,
        user=user,
        max_tokens=_MAX_TOKENS,
        timeout_seconds=_TIMEOUT,
    )
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(
            req["url"], headers=req["headers"], json=req["json"],
        )
    resp.raise_for_status()
    data = resp.json()
    text = "".join(
        b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"
    )
    return _parse_suggestions(text)
