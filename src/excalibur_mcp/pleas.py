"""eXcalibur's pleas to its own human when an outside account it pays for runs dry.

The SDK's ``runtime.plead`` sends them: a DM to the operator's own npub, which
Pricing Studio shows, kept on the relays for days and repeated at most twice a
day per cause. This module only names the causes and words them, so the
scheduler, the resolver and the patron tools all say the same thing.

A plea is a courtesy. It never breaks the path that noticed the outage, so
every call here swallows its own failure.
"""

from __future__ import annotations

import logging
from typing import Any

from tollbooth.constants import ErrorCode

logger = logging.getLogger(__name__)

X_CREDITS = "x-credits"
LLM_CREDITS = "llm-credits"
LLM_MODEL = "llm-model"
LLM_ACCESS = "llm-access"

_X_CREDITS_TEXT = (
    "⚡ eXcalibur can't post to X\n\n"
    "X refused a post with 402: the API credits of the operator's X developer app "
    "are spent. Top them up in the X Developer Console (console.x.com → Billing → "
    "Credits).\n\n"
    "Every post that hit this is Paused, not lost. After the top-up, resume them; "
    "each waits for its next slot, so nothing goes out in a burst. The Calendar "
    "shows them greyed."
)
_X_POSTING_TEXT = "✅ eXcalibur is posting to X again."

_LLM_TEXT = {
    LLM_CREDITS: (
        "⚡ eXcalibur can't {capability}\n\n"
        "The account behind the operator's llm_api_key is out of credits. Top it up "
        "with your model router and service resumes by itself, no redeploy needed.\n\n"
        "Until then, scheduled posts send their fallback text instead of what the AI "
        "would have written, and patrons are not charged for it."
    ),
    LLM_MODEL: (
        "⚡ eXcalibur can't {capability}\n\n"
        "The provider no longer offers the model this service is configured for, "
        "usually a marketplace renaming or retiring it. Point TOLLBOOTH_LLM_MODEL_* at "
        "a current slug and restart. Retrying will not clear this on its own."
    ),
    LLM_ACCESS: (
        "⚡ eXcalibur can't {capability}\n\n"
        "Your AI provider rejected this service's access (auth or configuration). "
        "Check the operator's llm_api_key; service resumes once it is right."
    ),
}
_LLM_BACK_TEXT = "✅ eXcalibur's AI-written blocks are working again."

#: The LLM situations a plea answers, by the error code (or fallback reason) that names them.
_LLM_CAUSE = {
    ErrorCode.LLM_PROVIDER_UNFUNDED: LLM_CREDITS,
    ErrorCode.LLM_MODEL_UNKNOWN: LLM_MODEL,
    ErrorCode.LLM_PROVIDER_AUTH: LLM_ACCESS,
    "no_operator_llm_key": LLM_ACCESS,
}

#: A block's fallback reasons that only the operator's human can fix. A timeout or
#: a rate limit is the post's own budget or a passing blip, and is no plea.
LLM_PLEA_REASONS = frozenset(_LLM_CAUSE)


def llm_cause(error_code: str | None) -> str:
    """The plea cause for an LLM situation that no retry fixes."""
    return _LLM_CAUSE.get(error_code or "", LLM_ACCESS)


async def _call(runtime: Any, method: str, cause: str, text: str) -> None:
    try:
        await getattr(runtime, method)(cause, text)
    except Exception:  # noqa: BLE001 — a plea never breaks the path that noticed the outage
        logger.debug("%s %s skipped", method, cause, exc_info=True)


async def x_credits_spent(runtime: Any) -> None:
    await _call(runtime, "plead", X_CREDITS, _X_CREDITS_TEXT)


async def x_posting(runtime: Any) -> None:
    await _call(runtime, "plea_resolved", X_CREDITS, _X_POSTING_TEXT)


async def llm_down(runtime: Any, error_code: str | None, capability: str) -> None:
    cause = llm_cause(error_code)
    await _call(runtime, "plead", cause, _LLM_TEXT[cause].format(capability=capability))


async def llm_working(runtime: Any) -> None:
    for cause in (LLM_CREDITS, LLM_MODEL, LLM_ACCESS):
        await _call(runtime, "plea_resolved", cause, _LLM_BACK_TEXT)
