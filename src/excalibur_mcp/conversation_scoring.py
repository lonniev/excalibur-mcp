"""Scoring and query composition for conversation leads — pure, no I/O.

A lead is an X post whose author is asking something a patron could answer.
The score is a transparent 0–100 sum of named signals, so a patron can see
*why* a row ranks where it does and tune the weights per saved query. Nothing
here knows what the patron sells: the need phrases and spam markers are the
shape of a question and the shape of a shill, not a domain vocabulary.

Learned from the discovery spike (2026-10-04): the search window is 7 days;
``-has:links`` is safe because a photo is not a link; ``-has:cashtags`` cuts
most token-shill noise; bare domain nouns are the selector and a required
co-noun collapses the result set. ``?`` is not an X operator.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Weights — every number a patron may override, with bounds
# ---------------------------------------------------------------------------

DEFAULT_WEIGHTS: dict[str, int] = {
    "need": 40,           # a question/need phrase in the text
    "replies": 20,        # a live thread (reply_count >= replies_min)
    "band": 15,           # author followers within [followers_min, followers_max]
    "spam": -30,          # cashtag / bold-unicode / airdrop-shaped text
    "reply": -20,         # the post is itself a reply, not a top-level ask
    "replies_min": 3,
    "followers_min": 200,
    "followers_max": 20000,
    "decay_hours": 72,    # positive signals fade linearly to 0 over this span
}

# (lower, upper) bounds per key; unknown keys are rejected outright.
_WEIGHT_BOUNDS: dict[str, tuple[int, int]] = {
    "need": (-100, 100),
    "replies": (-100, 100),
    "band": (-100, 100),
    "spam": (-100, 100),
    "reply": (-100, 100),
    "replies_min": (0, 1000),
    "followers_min": (0, 10_000_000),
    "followers_max": (0, 10_000_000),
    "decay_hours": (1, 168),
}

NEED_PHRASES: tuple[str, ...] = (
    "how do i", "how do you", "how to", "anyone know", "does anyone", "is there a way",
    "looking for", "is this", "what do i do", "what should i", "should i", "any tips",
    "any advice", "any recommendations", "recommend", "what causes", "why is", "why are",
    "where do i", "where can i", "can someone", "help me",
)
_NEED_RE = re.compile("|".join(re.escape(p) for p in NEED_PHRASES), re.IGNORECASE)

SPAM_WORDS: tuple[str, ...] = ("airdrop", "presale", "giveaway", "whitelist", "100x")
_SPAM_RE = re.compile(
    r"\$[A-Za-z]{2,10}\b|" + "|".join(re.escape(w) for w in SPAM_WORDS), re.IGNORECASE,
)

# X's "safe defaults": drop reposts, posts carrying an external link (a photo is
# not a link), posts with cashtags, and non-English — unless the patron opts out.
SAFE_DEFAULTS = "-is:retweet -has:links -has:cashtags lang:en"
# X's own ceiling on a recent-search query. The patron's clause gets whatever
# is left after the parentheses, the safe defaults and ``-from:<own id>`` (X
# user ids run to 20 digits) — no tighter than the endpoint itself.
MAX_EFFECTIVE_QUERY = 512
_RESERVED = len("()") + 1 + len(SAFE_DEFAULTS) + 1 + len("-from:") + 20
MAX_CLAUSE = MAX_EFFECTIVE_QUERY - _RESERVED


def is_bold_unicode(text: str) -> bool:
    """True when the text carries Mathematical Alphanumeric Symbols — the
    styled-letter trick ``formatter.py`` produces on purpose and shills use to
    dodge keyword filters. Three or more is a styled run, not a stray glyph."""
    return sum(1 for ch in text if 0x1D400 <= ord(ch) <= 0x1D7FF) >= 3


def validate_weights(weights: Any) -> dict[str, int]:
    """Accept only allow-listed keys with integer values inside their bounds.

    Returns the overrides only (not merged with defaults) so a saved query
    stores what the patron changed. Tool input is adversarial: a float, a
    string, an unknown key or a min above its max are all errors.
    """
    if weights is None:
        return {}
    if not isinstance(weights, dict):
        raise ValueError("weights must be an object")
    out: dict[str, int] = {}
    for key, value in weights.items():
        if key not in _WEIGHT_BOUNDS:
            raise ValueError(f"unknown weight '{key}'")
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"weight '{key}' must be an integer")
        lo, hi = _WEIGHT_BOUNDS[key]
        if not lo <= value <= hi:
            raise ValueError(f"weight '{key}' must be between {lo} and {hi}")
        out[key] = value
    merged = {**DEFAULT_WEIGHTS, **out}
    if merged["followers_min"] > merged["followers_max"]:
        raise ValueError("followers_min must not exceed followers_max")
    return out


def effective_weights(*layers: dict[str, int] | None) -> dict[str, int]:
    """Defaults, then each layer in order (saved query, then the call)."""
    merged = dict(DEFAULT_WEIGHTS)
    for layer in layers:
        if layer:
            merged.update(layer)
    return merged


def compose_query(query: str, own_id: str, safe_defaults: bool = True) -> str:
    """The query X actually runs: the patron's clause, the safe defaults, and
    the patron's own account excluded so their posts never become their leads."""
    q = query.strip()
    parts = [f"({q})"]
    if safe_defaults:
        parts.append(SAFE_DEFAULTS)
    if own_id:
        parts.append(f"-from:{own_id}")
    effective = " ".join(parts)
    if len(effective) > MAX_EFFECTIVE_QUERY:
        raise ValueError(f"query exceeds {MAX_EFFECTIVE_QUERY} characters once composed")
    return effective


def _parse_when(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def score_tweet(
    tweet: dict[str, Any],
    author: dict[str, Any] | None,
    *,
    weights: dict[str, int] | None = None,
    now: datetime | None = None,
) -> tuple[int, list[str]]:
    """Score one post. Returns ``(score, signals)`` — the signals name every
    weight that fired, so the row explains itself.

    Positive signals decay linearly with the post's age over ``decay_hours``
    (a three-day-old ask has usually been answered); penalties do not fade,
    because a shill is a shill at any age. The result is clamped to 0..100.
    """
    w = effective_weights(weights)
    text = str(tweet.get("text") or "")
    metrics = tweet.get("public_metrics") or {}
    author = author or {}
    author_metrics = author.get("public_metrics") or {}
    signals: list[str] = []
    positive = 0
    negative = 0

    if _NEED_RE.search(text):
        positive += w["need"]
        signals.append("need")
    try:
        replies = int(metrics.get("reply_count") or 0)
    except (TypeError, ValueError):
        replies = 0
    if replies >= w["replies_min"]:
        positive += w["replies"]
        signals.append("thread")
    try:
        followers = int(author_metrics.get("followers_count") or 0)
    except (TypeError, ValueError):
        followers = 0
    if w["followers_min"] <= followers <= w["followers_max"]:
        positive += w["band"]
        signals.append("reachable")
    if _SPAM_RE.search(text) or is_bold_unicode(text):
        negative += w["spam"]
        signals.append("spam")
    is_reply = bool(tweet.get("in_reply_to_user_id")) or (
        tweet.get("conversation_id") and tweet.get("id")
        and str(tweet["conversation_id"]) != str(tweet["id"])
    )
    if is_reply:
        negative += w["reply"]
        signals.append("reply")

    posted = _parse_when(tweet.get("created_at"))
    factor = 1.0
    if posted is not None:
        current = now or datetime.now(timezone.utc)
        if posted.tzinfo is None:
            posted = posted.replace(tzinfo=timezone.utc)
        age_h = max(0.0, (current - posted).total_seconds() / 3600.0)
        factor = max(0.0, 1.0 - age_h / float(w["decay_hours"]))
        if factor < 1.0:
            signals.append("aged")

    score = int(round(positive * factor + negative))
    return max(0, min(100, score)), signals
