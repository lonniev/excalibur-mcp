"""X (Twitter) API v2 client with OAuth 2.0 Bearer token authentication.

All requests use a Bearer token obtained via the OAuth 2.0 Authorization
Code Flow with PKCE. No OAuth 1.0a signing — all endpoints are v2.
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from typing import Any

import httpx

logger = logging.getLogger(__name__)

X_API_BASE = "https://api.x.com/2"
ALLOWED_IMAGE_CONTENT_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp"}
MAX_IMAGE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
IMAGE_DOWNLOAD_TIMEOUT_SECONDS = 30

POSTIMG_UPLOAD_URL = "https://postimg.cc/json?q=a"
POSTIMG_UPLOAD_TIMEOUT_SECONDS = 30

# The X API's own budget. A bare httpx client allows 5s for EVERY phase, which
# is a thin margin for an outbound write — and was seen timing out on connect
# while reads from the same host succeeded. The image paths were given
# deliberate budgets; the API calls get one too.
X_API_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=30.0, pool=10.0)

# A publication reaches post_tweet having already spent minutes, and real
# money, resolving its content. Discarding all of that because a TCP connection
# didn't open is a bad trade, so a connect-phase failure is retried.
#
# ONLY the connect phase. A ReadTimeout means the request DID reach X and we
# merely never saw the answer — the tweet may already be live, and retrying
# would post it twice. That one is left to fail and be reported.
_CONNECT_ATTEMPTS = 3
_CONNECT_BACKOFF_S = 2.0


class PostImgUploadError(Exception):
    """Raised when uploading to postimg.cc fails."""

    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(detail)


async def upload_to_postimg(png_bytes: bytes, filename: str = "banner.png") -> str:
    """Upload PNG to postimg.cc, return direct image URL."""
    async with httpx.AsyncClient(timeout=POSTIMG_UPLOAD_TIMEOUT_SECONDS, follow_redirects=True) as client:
        try:
            response = await client.post(
                POSTIMG_UPLOAD_URL,
                data={
                    "token": "61aa06d6116f7331ad7b2ba9c7fb707ec9b182e8",
                    "upload_session": os.urandom(16).hex(),
                    "numfiles": "1",
                    "optsize": "0",
                    "upload_referer": "https://postimages.org/",
                },
                files={"file": (filename, png_bytes, "image/png")},
            )
        except httpx.HTTPError as exc:
            raise PostImgUploadError(f"PostImg upload failed: {exc}")

    if response.status_code != 200:
        raise PostImgUploadError(
            f"PostImg returned {response.status_code}: {response.text[:200]}"
        )

    try:
        data = response.json()
    except Exception:
        raise PostImgUploadError(f"PostImg returned non-JSON: {response.text[:200]}")

    url = data.get("url")
    if not url:
        raise PostImgUploadError(f"PostImg response missing 'url': {data}")

    return url


def _safe_json(response: Any) -> dict:
    """X's response body as a dict — never raising, so an error path can't die
    reporting an error. A gateway HTML page becomes ``{"raw": ...}``."""
    try:
        body = response.json()
        return body if isinstance(body, dict) else {"raw": str(body)[:400]}
    except Exception:  # noqa: BLE001 — a non-JSON body is still evidence
        return {"raw": (getattr(response, "text", "") or "")[:400]}


def _x_says(body: Any, fallback: str) -> str:
    """What X actually said, or *fallback* when it said nothing usable.

    X answers errors in two shapes — RFC-7807-ish (``title``/``detail``) and a
    legacy ``errors: [{message}]`` list — and a gateway can return neither. This
    reads all of them so a caller never has to guess.

    Guessing is what it replaces. The 402 branch below used to discard the parsed
    body and raise a sentence written months earlier: "X API subscription or
    access tier does not cover this request." On 2026-07-31 a post was paused
    carrying exactly that text while two siblings from the same account posted
    fine half an hour before — and nothing anywhere recorded why X singled that
    one out, because X's explanation was thrown away at the only point it
    existed. An operator asking "what is wrong with this post?" could not be
    answered from the record.
    """
    if not isinstance(body, dict):
        return fallback
    for key in ("detail", "title"):
        value = str(body.get(key) or "").strip()
        if value:
            return value
    errors = body.get("errors")
    if isinstance(errors, list):
        joined = "; ".join(
            str(e.get("message") or e.get("detail") or "").strip()
            for e in errors
            if isinstance(e, dict) and (e.get("message") or e.get("detail"))
        )
        if joined:
            return joined
    raw = str(body.get("raw") or "").strip()
    return raw or fallback


class XAPIError(Exception):
    """Raised when the X API returns an error response."""

    def __init__(self, status_code: int, detail: str, raw: dict | None = None):
        self.status_code = status_code
        self.detail = detail
        self.raw = raw or {}
        super().__init__(f"X API {status_code}: {detail}")


class MediaUploadError(XAPIError):
    """Raised when image download or media upload to X fails."""

    pass


@dataclass(frozen=True)
class XCredentials:
    """OAuth 2.0 Bearer token for X API access."""

    bearer_token: str


class XClient:
    """Async X API v2 client with OAuth 2.0 Bearer token auth."""

    def __init__(self, credentials: XCredentials) -> None:
        self._creds = credentials

    def _auth_header(self) -> str:
        return f"Bearer {self._creds.bearer_token}"

    async def download_image(self, image_url: str) -> tuple[bytes, str]:
        """Download an image from a URL."""
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=IMAGE_DOWNLOAD_TIMEOUT_SECONDS,
        ) as client:
            try:
                response = await client.get(image_url)
            except httpx.HTTPError as exc:
                raise MediaUploadError(
                    0, f"Failed to download image from {image_url}: {exc}"
                )

        if response.status_code != 200:
            raise MediaUploadError(
                response.status_code,
                f"Image download returned {response.status_code}",
            )

        content_type = response.headers.get("content-type", "").split(";")[0].strip()
        if content_type not in ALLOWED_IMAGE_CONTENT_TYPES:
            raise MediaUploadError(
                0,
                f"Unsupported image type: {content_type}. "
                f"Allowed: {ALLOWED_IMAGE_CONTENT_TYPES}",
            )

        image_bytes = response.content
        if len(image_bytes) > MAX_IMAGE_SIZE_BYTES:
            raise MediaUploadError(
                0,
                f"Image too large: {len(image_bytes)} bytes "
                f"(max {MAX_IMAGE_SIZE_BYTES} bytes / 5 MB)",
            )

        return image_bytes, content_type

    async def upload_media(self, image_bytes: bytes, content_type: str) -> str:
        """Upload image bytes to X via v2 media/upload.

        Returns media_id_string from the X response.
        """
        url = f"{X_API_BASE}/media/upload"

        async with httpx.AsyncClient(timeout=X_API_TIMEOUT) as client:
            response = await client.post(
                url,
                files={"media": ("image.jpg", image_bytes, content_type)},
                headers={"Authorization": self._auth_header()},
            )

        if response.status_code not in (200, 202):
            body = _safe_json(response)
            raise MediaUploadError(
                response.status_code,
                _x_says(body, f"Media upload failed: {response.status_code}"),
                body,
            )

        data = response.json()
        media_id = data.get("media_id_string") or data.get("id")
        if not media_id:
            raise MediaUploadError(0, "Media upload response missing media_id", data)

        return str(media_id)

    async def _post_retrying_connect(self, url: str, payload: dict) -> httpx.Response:
        """POST to X, retrying only when the connection never opened.

        Safe to repeat precisely because a connect-phase failure means the
        request never reached X. Anything that got as far as being sent is
        raised, so a tweet that may already be live is never sent twice.
        """
        last: Exception | None = None
        for attempt in range(_CONNECT_ATTEMPTS):
            try:
                async with httpx.AsyncClient(timeout=X_API_TIMEOUT) as client:
                    return await client.post(
                        url,
                        json=payload,
                        headers={"Authorization": self._auth_header()},
                    )
            except (httpx.ConnectTimeout, httpx.ConnectError) as exc:
                last = exc
                if attempt + 1 < _CONNECT_ATTEMPTS:
                    await asyncio.sleep(_CONNECT_BACKOFF_S * (attempt + 1))
        raise last  # type: ignore[misc]

    async def post_tweet(
        self, text: str, *, media_ids: list[str] | None = None
    ) -> dict:
        """Post a tweet to X."""
        url = f"{X_API_BASE}/tweets"

        payload: dict = {"text": text}
        if media_ids:
            payload["media"] = {"media_ids": media_ids}

        response = await self._post_retrying_connect(url, payload)

        if response.status_code == 429:
            body = _safe_json(response)
            raise XAPIError(429, _x_says(body, "Rate limited — try again later"), body)

        if response.status_code in (401, 403):
            body = _safe_json(response)
            raise XAPIError(
                response.status_code, _x_says(body, "Authentication failed"), body,
            )

        if response.status_code == 402:
            # X answers a 402 when the developer subscription / access tier behind
            # this account's credentials has lapsed or doesn't cover this write.
            # Not the x402 micropayment protocol, not a balance problem — a human
            # acts at developer.x.com, and the server maps this to the SDK's
            # upstream-subscription situation.
            #
            # WHICH write, and why, is X's to say and ours to carry: a post
            # refused for its own content and an account whose plan lapsed are
            # different problems with different fixes, and a fixed sentence made
            # them identical in the log.
            body = _safe_json(response)
            raise XAPIError(
                402, _x_says(body, "X declined this request and gave no reason"), body,
            )

        if response.status_code != 201:
            body = _safe_json(response)
            raise XAPIError(
                response.status_code,
                _x_says(body, f"Unexpected response: {response.status_code}"),
                body,
            )

        data = response.json()["data"]
        tweet_id = data["id"]

        return {
            "tweet_id": tweet_id,
            "tweet_url": f"https://x.com/i/status/{tweet_id}",
            "text_posted": text,
        }

    async def post_tweet_with_image(self, text: str, image_url: str) -> dict:
        """Download image, upload to X, and post tweet with media attached."""
        image_bytes, content_type = await self.download_image(image_url)
        media_id = await self.upload_media(image_bytes, content_type)
        result = await self.post_tweet(text, media_ids=[media_id])
        result["media_id"] = media_id
        return result

    async def get_me(self) -> dict:
        """Fetch the authenticated user's X profile (v2 ``/users/me``).

        Returns ``{id, username, name, profile_image_url}`` — used to show the
        real @handle on the editor's tweet-card preview. Pass
        ``include_public_metrics=True`` to also return ``followers_count``."""
        return await self._get_me(include_public_metrics=False)

    async def get_me_with_metrics(self) -> dict:
        """Like ``get_me`` plus ``followers_count`` from ``public_metrics``."""
        return await self._get_me(include_public_metrics=True)

    async def _get_me(self, *, include_public_metrics: bool) -> dict:
        url = f"{X_API_BASE}/users/me"
        fields = "profile_image_url,name,username"
        if include_public_metrics:
            fields += ",public_metrics"
        async with httpx.AsyncClient(timeout=X_API_TIMEOUT) as client:
            response = await client.get(
                url,
                params={"user.fields": fields},
                headers={"Authorization": self._auth_header()},
            )

        if response.status_code in (401, 403):
            body = _safe_json(response)
            raise XAPIError(
                response.status_code, _x_says(body, "Authentication failed"), body,
            )
        if response.status_code != 200:
            body = _safe_json(response)
            raise XAPIError(
                response.status_code,
                _x_says(body, f"Unexpected response: {response.status_code}"),
                body,
            )

        data = response.json().get("data", {})
        out = {
            "id": data.get("id", ""),
            "username": data.get("username", ""),
            "name": data.get("name", ""),
            "profile_image_url": data.get("profile_image_url", ""),
        }
        pm = data.get("public_metrics") or {}
        if isinstance(pm, dict) and "followers_count" in pm:
            out["followers_count"] = pm.get("followers_count")
        return out

    async def get_tweet_metrics(self, tweet_id: str) -> dict:
        """Fetch engagement metrics for a tweet the authenticated user authored.

        Requests ``public_metrics``, ``non_public_metrics``, and
        ``organic_metrics``. The non-public / organic fields are only available
        for ~30 days after creation under OAuth 2.0 user context — after that
        they are gone permanently. Prefer organic → non_public → public for
        impression / click counts.
        """
        tid = str(tweet_id or "").strip()
        if not tid or not tid.isdigit():
            raise XAPIError(0, f"Invalid tweet_id: {tweet_id!r}")

        url = f"{X_API_BASE}/tweets/{tid}"
        params = {
            "tweet.fields": (
                "public_metrics,non_public_metrics,organic_metrics,"
                "created_at,conversation_id"
            ),
        }
        async with httpx.AsyncClient(timeout=X_API_TIMEOUT) as client:
            response = await client.get(
                url,
                params=params,
                headers={"Authorization": self._auth_header()},
            )

        if response.status_code == 429:
            body = _safe_json(response)
            raise XAPIError(429, _x_says(body, "Rate limited — try again later"), body)
        if response.status_code in (401, 403):
            body = _safe_json(response)
            raise XAPIError(
                response.status_code, _x_says(body, "Authentication failed"), body,
            )
        if response.status_code == 404:
            body = _safe_json(response)
            raise XAPIError(404, _x_says(body, "Tweet not found"), body)
        if response.status_code != 200:
            body = _safe_json(response)
            raise XAPIError(
                response.status_code,
                _x_says(body, f"Unexpected response: {response.status_code}"),
                body,
            )

        raw = response.json()
        data = raw.get("data") or {}
        if not isinstance(data, dict):
            data = {}
        public = data.get("public_metrics") or {}
        non_public = data.get("non_public_metrics") or {}
        organic = data.get("organic_metrics") or {}

        def _pick(*dicts: dict, key: str) -> int | None:
            for d in dicts:
                if isinstance(d, dict) and d.get(key) is not None:
                    try:
                        return int(d[key])
                    except (TypeError, ValueError):
                        continue
            return None

        # Prefer organic (author-context full set) then non_public then public.
        impressions = _pick(organic, non_public, public, key="impression_count")
        return {
            "tweet_id": data.get("id") or tid,
            "conversation_id": data.get("conversation_id"),
            "created_at": data.get("created_at"),
            "impressions": impressions,
            "likes": _pick(organic, public, key="like_count"),
            "replies": _pick(organic, public, key="reply_count"),
            "reposts": _pick(organic, public, key="retweet_count"),
            "quotes": _pick(public, key="quote_count"),
            "bookmarks": _pick(public, key="bookmark_count"),
            "url_link_clicks": _pick(organic, non_public, key="url_link_clicks"),
            "user_profile_clicks": _pick(organic, non_public, key="user_profile_clicks"),
            "raw": raw if isinstance(raw, dict) else {"data": data},
        }
