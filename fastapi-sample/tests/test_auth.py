from typing import Any

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from pytest_mock import MockerFixture

from fastapi_sample.auth import _verify_token_impl
from fastapi_sample.settings import Settings


@pytest.fixture
def rsa_keys() -> tuple[str, str]:
    """テスト用のRSA秘密鍵と公開鍵を生成"""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return private_pem, public_pem


@pytest.fixture
def mock_payload() -> dict[str, Any]:
    """デコード後の期待されるペイロード"""
    return {
        "sub": "1234567890",
        "name": "John Doe",
        "iss": "https://example.com",
        "aud": ["test-audience"],
    }


@pytest.fixture
def valid_token(rsa_keys: tuple[str, str], mock_payload: dict[str, Any]) -> str:
    """有効なトークンを生成"""
    private_key, _ = rsa_keys
    return jwt.encode(mock_payload, private_key, algorithm="RS256")


@pytest.fixture
def settings(mock_payload: dict[str, Any]) -> Settings:
    """テスト用のSettings"""
    return Settings(
        authorization_url="https://example.com/auth",
        token_url="https://example.com/token",
        jwks_url="https://example.com/.well-known/jwks.json",
        issuer=mock_payload["iss"],
        audience=mock_payload["aud"],
    )


@pytest.mark.asyncio
async def test_verify_token_success(
    valid_token: str,
    mock_payload: dict[str, Any],
    rsa_keys: tuple[str, str],
    settings: Settings,
    mocker: MockerFixture,
):
    """有効なトークンでデコードが成功する場合"""
    _, public_key = rsa_keys

    # 署名キーのモック
    mock_signing_key = mocker.MagicMock()
    mock_signing_key.key = public_key

    # 関数を実行（実際のjwt.decodeが動作する）
    result = await _verify_token_impl(
        valid_token, settings=settings, signing_key=mock_signing_key
    )

    # アサーション
    assert result["sub"] == mock_payload["sub"]
    assert result["name"] == mock_payload["name"]
    assert result["iss"] == mock_payload["iss"]
    assert result["aud"] == mock_payload["aud"]


@pytest.mark.asyncio
async def test_verify_token_invalid_token(
    rsa_keys: tuple[str, str],
    mock_payload: dict[str, Any],
    settings: Settings,
    mocker: MockerFixture,
):
    """無効なトークンでデコードが失敗する場合"""
    _, public_key = rsa_keys
    invalid_token = "invalid.token.here"

    # 署名キーのモック
    mock_signing_key = mocker.MagicMock()
    mock_signing_key.key = public_key

    # HTTPExceptionが発生することを確認（実際のjwt.decodeがエラーを出す）
    with pytest.raises(HTTPException) as exc_info:
        await _verify_token_impl(
            invalid_token, settings=settings, signing_key=mock_signing_key
        )

    # ステータスコードを確認
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Token decode error"


@pytest.mark.asyncio
async def test_verify_token_invalid_signature(
    mock_payload: dict[str, Any],
    rsa_keys: tuple[str, str],
    settings: Settings,
    mocker: MockerFixture,
):
    """署名が間違っているトークンの場合"""
    _, public_key = rsa_keys

    # 別の秘密鍵で署名したトークンを生成（署名検証エラーになる）
    wrong_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    wrong_private_pem = wrong_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    wrong_token = jwt.encode(mock_payload, wrong_private_pem, algorithm="RS256")

    # 署名キーのモック
    mock_signing_key = mocker.MagicMock()
    mock_signing_key.key = public_key

    # HTTPExceptionが発生することを確認（署名検証エラー）
    with pytest.raises(HTTPException) as exc_info:
        await _verify_token_impl(
            wrong_token, settings=settings, signing_key=mock_signing_key
        )

    # ステータスコードを確認
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid token signature"


@pytest.mark.asyncio
async def test_verify_token_expired_token(
    mock_payload: dict[str, Any],
    rsa_keys: tuple[str, str],
    settings: Settings,
    mocker: MockerFixture,
):
    """トークンの有効期限切れエラーの場合"""
    private_key, public_key = rsa_keys

    # 過去の exp を持つペイロード
    import time

    expired_payload = mock_payload.copy()
    expired_payload["exp"] = int(time.time()) - 3600  # 1時間前に期限切れ

    expired_token = jwt.encode(expired_payload, private_key, algorithm="RS256")

    # 署名キーのモック
    mock_signing_key = mocker.MagicMock()
    mock_signing_key.key = public_key

    # HTTPExceptionが発生することを確認（期限切れエラー）
    with pytest.raises(HTTPException) as exc_info:
        await _verify_token_impl(
            expired_token, settings=settings, signing_key=mock_signing_key
        )

    # ステータスコードを確認
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Token has expired"


@pytest.mark.asyncio
async def test_verify_token_invalid_issuer(
    mock_payload: dict[str, Any],
    rsa_keys: tuple[str, str],
    settings: Settings,
    mocker: MockerFixture,
):
    """トークンのissuerが不正な場合"""
    private_key, public_key = rsa_keys

    # 間違ったissuerを持つペイロード
    invalid_issuer_payload = mock_payload.copy()
    invalid_issuer_payload["iss"] = "https://wrong-issuer.com"

    invalid_issuer_token = jwt.encode(
        invalid_issuer_payload, private_key, algorithm="RS256"
    )

    # 署名キーのモック
    mock_signing_key = mocker.MagicMock()
    mock_signing_key.key = public_key

    # HTTPExceptionが発生することを確認（issuerエラー）
    with pytest.raises(HTTPException) as exc_info:
        await _verify_token_impl(
            invalid_issuer_token, settings=settings, signing_key=mock_signing_key
        )

    # ステータスコードを確認
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid token issuer"


@pytest.mark.asyncio
async def test_verify_token_invalid_audience(
    mock_payload: dict[str, Any],
    rsa_keys: tuple[str, str],
    settings: Settings,
    mocker: MockerFixture,
):
    """トークンのaudienceが不正な場合"""
    private_key, public_key = rsa_keys

    # 間違ったaudienceを持つペイロード
    invalid_audience_payload = mock_payload.copy()
    invalid_audience_payload["aud"] = ["wrong-audience"]

    invalid_audience_token = jwt.encode(
        invalid_audience_payload, private_key, algorithm="RS256"
    )

    # 署名キーのモック
    mock_signing_key = mocker.MagicMock()
    mock_signing_key.key = public_key

    # HTTPExceptionが発生することを確認（audienceエラー）
    with pytest.raises(HTTPException) as exc_info:
        await _verify_token_impl(
            invalid_audience_token, settings=settings, signing_key=mock_signing_key
        )

    # ステータスコードを確認
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid token audience"
