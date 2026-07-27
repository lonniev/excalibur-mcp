"""Publish a public Nostr note (kind 1) on behalf of a proven patron npub.

eXcalibur cannot author a note *as* the patron: a Nostr event must be signed by
the key it claims to come from, and the wheel never holds a patron nsec. So for
each note it mints a fresh, ephemeral "scribe" keypair, signs with it, and
``p``-tags the proven author npub. The p-tag makes the note render as a real
mention, threads it, and — the part that matters — places the note in the
claimed author's OWN mentions, so a patron who was scribed for can see it and
repudiate it. Verification is deferred out-of-band: an interested reader follows
up with the p-tagged author directly.

The scribe is a role, not an identity — a key minted for the job carries no
voice of its own. It is held in process only (never vaulted) and forgotten on
cold start. See issue #276 for the adopted design; retraction is best-effort and
must never be described as guaranteed.

Mirrors the self-contained raw-websocket approach in ``tollbooth`` modules
(``nostr_profile.py`` / ``bootstrap_relay.py``): relay I/O is synchronous, fanned
out one thread per relay, so total wall-clock is bounded by the slowest single
relay rather than their sum.
"""

from __future__ import annotations

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

_KIND_TEXT_NOTE = 1
# Per-relay socket timeout. Relays are queried in PARALLEL (one thread each),
# so a slow or dead relay never holds the whole publish hostage.
_TIMEOUT = 5

# In-process scribe-key registry: event_id -> ephemeral private key (hex). Held
# in warm memory ONLY — never vaulted, never actively cleaned up, forgotten on
# cold start. This is the best-effort NIP-09 delete handle: while the instance
# is warm the same scribe key can sign a retraction; after a cold start the key
# is gone and retraction is impossible. Deliberate (issue #276) — retraction is
# never promised in user-facing copy.
_SCRIBE_KEYS: dict[str, str] = {}


def _npub_to_hex(npub: str) -> str:
    from pynostr.key import PublicKey  # type: ignore[import-untyped]

    return PublicKey.from_npub(npub).hex()


def _compose_content(message: str, author_npub: str) -> str:
    """Annotate the note so the ephemeral scribe is visibly not the author.

    The ``nostr:npub…`` reference renders as a mention in NIP-27 clients and,
    paired with the matching ``p`` tag, lands the note in the author's own
    mentions — where they can see it and disown it.
    """
    return (
        f"{message}\n\n"
        f"— posted by eXcalibur on behalf of nostr:{author_npub}, "
        f"the author, who is reachable there for follow-up."
    )


def build_note_event(message: str, author_npub: str) -> tuple[dict, str, str]:
    """Build a signed kind-1 note scribed for ``author_npub``.

    Mints a FRESH ephemeral keypair, signs the note with it, and ``p``-tags the
    author. Returns ``(signed_event, scribe_pubkey_hex, scribe_privkey_hex)`` —
    the private key is returned so the caller can retain it in process; it is
    never persisted here.
    """
    from pynostr.event import Event  # type: ignore[import-untyped]
    from pynostr.key import PrivateKey  # type: ignore[import-untyped]

    author_hex = _npub_to_hex(author_npub)

    scribe = PrivateKey()  # fresh ephemeral keypair, one per note
    scribe_priv_hex = scribe.hex()
    scribe_pub_hex = scribe.public_key.hex()

    event = Event(
        content=_compose_content(message, author_npub),
        pubkey=scribe_pub_hex,
        kind=_KIND_TEXT_NOTE,
        created_at=int(time.time()),
        tags=[["p", author_hex]],
    )
    event.sign(scribe_priv_hex)
    return event.to_dict(), scribe_pub_hex, scribe_priv_hex


def publish_note(
    message: str, author_npub: str, relays: list[str] | None = None,
) -> dict:
    """Publish ``message`` as a public note scribed for ``author_npub``.

    Signs with a fresh ephemeral key, ``p``-tags the author, and fans the event
    out to the DPYC relay set in parallel. Succeeds if **at least one** relay
    accepts it; the response always carries per-relay accept/reject detail plus
    the accepted/attempted counts, so a one-relay publish never reads as a clean
    broadcast. Returns ``{success, event_id, author_npub, scribe_pubkey,
    accepted, attempted, relays:[{relay, accepted, error}]}`` or, on a setup
    failure, ``{success: False, error: ...}``.
    """
    try:
        signed, scribe_pub_hex, scribe_priv_hex = build_note_event(message, author_npub)
    except Exception as exc:
        return {"success": False, "error": f"Invalid author npub: {author_npub!r} ({exc})"}

    from tollbooth.relay_registry import RelayRegistryError, get_relays

    try:
        relay_urls = relays or get_relays()
    except RelayRegistryError as exc:
        return {"success": False, "error": f"No relays available: {exc}"}

    event_id = signed.get("id", "")
    payload = json.dumps(["EVENT", signed])

    ok = 0
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=len(relay_urls)) as pool:
        futures = {pool.submit(_publish_one, url, payload): url for url in relay_urls}
        for future in as_completed(futures, timeout=_TIMEOUT + 2):
            url = futures[future]
            try:
                accepted, err = future.result()
            except Exception as exc:
                results.append({"relay": url, "accepted": False, "error": str(exc)})
                continue
            if accepted:
                ok += 1
                results.append({"relay": url, "accepted": True, "error": None})
            else:
                results.append({"relay": url, "accepted": False, "error": err})

    # Retain the scribe key in warm memory so a retraction can be signed while
    # the instance lives (best-effort — see module docstring). Never vaulted.
    if event_id:
        _SCRIBE_KEYS[event_id] = scribe_priv_hex

    return {
        "success": ok > 0,
        "event_id": event_id,
        "author_npub": author_npub,
        "scribe_pubkey": scribe_pub_hex,
        "accepted": ok,
        "attempted": len(relay_urls),
        "relays": results,
    }


def _publish_one(relay_url: str, message: str) -> tuple[bool, str | None]:
    """Send one EVENT to a single relay. ``(accepted, error)`` — never raises.

    Parses the NIP-20 ack strictly: only ``["OK", <id>, true, …]`` counts as
    accepted, so a rejection like ``["OK", id, false, "rate-limited"]`` is not
    silently counted as published.
    """
    import websocket  # type: ignore[import-untyped]

    try:
        ws = websocket.create_connection(relay_url, timeout=_TIMEOUT)
        try:
            ws.settimeout(_TIMEOUT)
            ws.send(message)
            raw = ws.recv()
            try:
                ack = json.loads(raw)
                if (
                    isinstance(ack, list)
                    and len(ack) >= 3
                    and ack[0] == "OK"
                    and ack[2] is True
                ):
                    return (True, None)
                return (False, f"{relay_url}: {str(raw)[:120]}")
            except (json.JSONDecodeError, IndexError):
                return (False, f"{relay_url}: unparseable ack {str(raw)[:80]}")
        finally:
            ws.close()
    except Exception as exc:
        return (False, f"{relay_url}: {exc}")
