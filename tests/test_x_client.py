"""Tests for the X API client (mocked — no real API calls)."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from excalibur_mcp.x_client import (
    ALLOWED_IMAGE_CONTENT_TYPES,
    MAX_IMAGE_SIZE_BYTES,
    MediaUploadError,
    XAPIError,
    XClient,
    XCredentials,
    _build_oauth1_header,
)


@pytest.fixture
def creds():
    return XCredentials(
        api_key="test-key",
        api_secret="test-secret",
        access_token="test-token",
        access_token_secret="test-token-secret",
    )


@pytest.fixture
def client(creds):
    return XClient(creds)


def _mock_response(status_code: int, body: dict) -> MagicMock:
    """Create a mock httpx response with sync .json()."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body
    resp.text = json.dumps(body)
    return resp


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------


class TestXCredentials:
    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("X_API_KEY", "k")
        monkeypatch.setenv("X_API_SECRET", "s")
        monkeypatch.setenv("X_ACCESS_TOKEN", "t")
        monkeypatch.setenv("X_ACCESS_TOKEN_SECRET", "ts")
        c = XCredentials.from_env()
        assert c.api_key == "k"
        assert c.access_token_secret == "ts"

    def test_from_env_missing(self, monkeypatch):
        monkeypatch.delenv("X_API_KEY", raising=False)
        with pytest.raises(KeyError):
            XCredentials.from_env()

    def test_frozen(self, creds):
        with pytest.raises(AttributeError):
            creds.api_key = "changed"


# ---------------------------------------------------------------------------
# OAuth 1.0a header
# ---------------------------------------------------------------------------


class TestOAuth1Header:
    def test_header_format(self):
        header = _build_oauth1_header(
            "POST", "https://api.x.com/2/tweets",
            "key", "secret", "token", "token_secret",
        )
        assert header.startswith("OAuth ")
        assert "oauth_consumer_key" in header
        assert "oauth_signature" in header
        assert "oauth_nonce" in header

    def test_different_nonces(self):
        h1 = _build_oauth1_header("POST", "https://example.com", "k", "s", "t", "ts")
        h2 = _build_oauth1_header("POST", "https://example.com", "k", "s", "t", "ts")
        assert h1 != h2  # nonce is random each time


# ---------------------------------------------------------------------------
# Image download
# ---------------------------------------------------------------------------


class TestDownloadImage:
    @pytest.mark.asyncio
    async def test_success(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "image/jpeg"}
        mock_resp.content = b"\xff\xd8" + b"\x00" * 100

        with patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            data, ct = await client.download_image("https://example.com/photo.jpg")
        assert ct == "image/jpeg"
        assert len(data) == 102

    @pytest.mark.asyncio
    async def test_unsupported_content_type(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/pdf"}
        mock_resp.content = b"%PDF"

        with patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            with pytest.raises(MediaUploadError) as exc_info:
                await client.download_image("https://example.com/doc.pdf")
            assert "Unsupported" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_oversized_image(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "image/png"}
        mock_resp.content = b"\x00" * (MAX_IMAGE_SIZE_BYTES + 1)

        with patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            with pytest.raises(MediaUploadError) as exc_info:
                await client.download_image("https://example.com/huge.png")
            assert "too large" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_http_error(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            with pytest.raises(MediaUploadError) as exc_info:
                await client.download_image("https://example.com/missing.jpg")
            assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# Media upload
# ---------------------------------------------------------------------------


class TestUploadMedia:
    @pytest.mark.asyncio
    async def test_success(self, client):
        mock_resp = _mock_response(200, {"media_id_string": "12345"})

        with patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_resp
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            media_id = await client.upload_media(b"\xff\xd8\x00", "image/jpeg")
        assert media_id == "12345"

    @pytest.mark.asyncio
    async def test_failure_status(self, client):
        mock_resp = _mock_response(400, {"error": "Bad Request"})

        with patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_resp
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            with pytest.raises(MediaUploadError) as exc_info:
                await client.upload_media(b"\x00", "image/jpeg")
            assert exc_info.value.status_code == 400

    @pytest.mark.asyncio
    async def test_uses_v1_upload_url(self, client):
        mock_resp = _mock_response(200, {"media_id_string": "99"})

        with patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_resp
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            await client.upload_media(b"\x00", "image/png")
            call_args = mock_instance.post.call_args
            assert "upload.twitter.com" in call_args.args[0]

    @pytest.mark.asyncio
    async def test_missing_media_id(self, client):
        mock_resp = _mock_response(200, {"something_else": "value"})

        with patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_resp
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            with pytest.raises(MediaUploadError) as exc_info:
                await client.upload_media(b"\x00", "image/jpeg")
            assert "media_id_string" in exc_info.value.detail


# ---------------------------------------------------------------------------
# API response handling
# ---------------------------------------------------------------------------


class TestPostTweet:
    @pytest.mark.asyncio
    async def test_success(self, client):
        mock_resp = _mock_response(201, {
            "data": {"id": "1234567890", "text": "Hello world"}
        })

        with patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_resp
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            result = await client.post_tweet("Hello world")

        assert result["tweet_id"] == "1234567890"
        assert "x.com" in result["tweet_url"]
        assert result["text_posted"] == "Hello world"

    @pytest.mark.asyncio
    async def test_rate_limit_429(self, client):
        mock_resp = _mock_response(429, {"detail": "Too Many Requests"})

        with patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_resp
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            with pytest.raises(XAPIError) as exc_info:
                await client.post_tweet("test")
            assert exc_info.value.status_code == 429

    @pytest.mark.asyncio
    async def test_auth_error_401(self, client):
        mock_resp = _mock_response(401, {"detail": "Unauthorized"})

        with patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_resp
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            with pytest.raises(XAPIError) as exc_info:
                await client.post_tweet("test")
            assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_forbidden_403(self, client):
        mock_resp = _mock_response(403, {"title": "Forbidden", "detail": "App-only"})

        with patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_resp
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            with pytest.raises(XAPIError) as exc_info:
                await client.post_tweet("test")
            assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_unexpected_status(self, client):
        mock_resp = _mock_response(500, {"error": "Internal Server Error"})

        with patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_resp
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            with pytest.raises(XAPIError) as exc_info:
                await client.post_tweet("test")
            assert exc_info.value.status_code == 500

    @pytest.mark.asyncio
    async def test_sends_authorization_header(self, client):
        """Verify OAuth header is sent with the request."""
        mock_resp = _mock_response(201, {"data": {"id": "999", "text": "hi"}})

        with patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_resp
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            await client.post_tweet("hi")

            call_kwargs = mock_instance.post.call_args
            headers = call_kwargs.kwargs.get("headers", {})
            assert "Authorization" in headers
            assert headers["Authorization"].startswith("OAuth ")


# ---------------------------------------------------------------------------
# Post tweet with media payload
# ---------------------------------------------------------------------------


class TestPostTweetWithMedia:
    @pytest.mark.asyncio
    async def test_includes_media_ids_in_payload(self, client):
        mock_resp = _mock_response(201, {"data": {"id": "555", "text": "pic"}})

        with patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_resp
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            await client.post_tweet("pic", media_ids=["12345"])
            call_kwargs = mock_instance.post.call_args.kwargs
            payload = call_kwargs["json"]
            assert payload["media"] == {"media_ids": ["12345"]}

    @pytest.mark.asyncio
    async def test_omits_media_when_none(self, client):
        mock_resp = _mock_response(201, {"data": {"id": "556", "text": "no pic"}})

        with patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_resp
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            await client.post_tweet("no pic")
            call_kwargs = mock_instance.post.call_args.kwargs
            payload = call_kwargs["json"]
            assert "media" not in payload


# ---------------------------------------------------------------------------
# post_tweet_with_image orchestration
# ---------------------------------------------------------------------------


class TestPostTweetWithImage:
    @pytest.mark.asyncio
    async def test_orchestrates_download_upload_post(self, client):
        """Verifies download → upload → post wiring."""
        with patch.object(
            client, "download_image", new_callable=AsyncMock
        ) as mock_dl, patch.object(
            client, "upload_media", new_callable=AsyncMock
        ) as mock_up, patch.object(
            client, "post_tweet", new_callable=AsyncMock
        ) as mock_post:
            mock_dl.return_value = (b"\xff\xd8", "image/jpeg")
            mock_up.return_value = "media_99"
            mock_post.return_value = {
                "tweet_id": "777",
                "tweet_url": "https://x.com/i/status/777",
                "text_posted": "hello",
            }

            result = await client.post_tweet_with_image(
                "hello", "https://example.com/img.jpg"
            )

        mock_dl.assert_called_once_with("https://example.com/img.jpg")
        mock_up.assert_called_once_with(b"\xff\xd8", "image/jpeg")
        mock_post.assert_called_once_with("hello", media_ids=["media_99"])
        assert result["tweet_id"] == "777"
        assert result["media_id"] == "media_99"
