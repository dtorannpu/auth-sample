import logging
from functools import lru_cache
from typing import Annotated, Any

import jwt
from fastapi import HTTPException
from fastapi.params import Depends
from fastapi.security import OAuth2AuthorizationCodeBearer
from jwt import PyJWK, PyJWKClient

from fastapi_sample.settings import Settings, get_settings

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _get_cached_oauth2_scheme(
    auth_url: str, token_url: str
) -> OAuth2AuthorizationCodeBearer:
    """OAuth2スキームをキャッシュして生成"""
    return OAuth2AuthorizationCodeBearer(
        authorizationUrl=auth_url,
        tokenUrl=token_url,
    )


def get_oauth2_scheme(
    settings: Annotated[Settings, Depends(get_settings)],
) -> OAuth2AuthorizationCodeBearer:
    """OAuth2スキームを取得する（キャッシュ済み）"""
    return _get_cached_oauth2_scheme(settings.authorization_url, settings.token_url)


@lru_cache(maxsize=1)
def _get_cached_jwks_client(jwks_url: str) -> PyJWKClient:
    """JWKSクライアントをキャッシュして生成"""
    return PyJWKClient(jwks_url)


def get_jwks_client(
    settings: Annotated[Settings, Depends(get_settings)],
) -> PyJWKClient:
    """JWKSクライアントを取得する（キャッシュ済み）"""
    return _get_cached_jwks_client(settings.jwks_url)


def get_signing_key(
    token: Annotated[str, Depends(get_oauth2_scheme)],
    jwks_client: Annotated[PyJWKClient, Depends(get_jwks_client)],
) -> PyJWK:
    """トークンから署名キーを取得する"""
    try:
        return jwks_client.get_signing_key_from_jwt(token)
    except jwt.exceptions.DecodeError as e:
        logger.warning(f"Failed to decode token: {e}")
        raise HTTPException(
            status_code=401,
            detail="Unable to decode token",
        )
    except jwt.exceptions.InvalidKeyError as e:
        logger.warning(f"Failed to get signing key from token: {e}")
        raise HTTPException(
            status_code=401,
            detail="Unable to verify token signature",
        )


async def _verify_token_impl(
    token: str,
    settings: Settings,
    signing_key: PyJWK,
) -> dict[str, Any]:
    """トークン検証のコアロジック"""
    try:
        jwks = signing_key.key
        payload = jwt.decode(
            token,
            jwks,
            algorithms=["RS256"],
            issuer=settings.issuer,
            audience=settings.audience,
        )
        return payload
    except jwt.ExpiredSignatureError as e:
        logger.warning(f"Token has expired: {e}")
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidIssuerError as e:
        logger.warning(f"Invalid token issuer: {e}")
        raise HTTPException(status_code=401, detail="Invalid token issuer")
    except jwt.InvalidAudienceError as e:
        logger.warning(f"Invalid token audience: {e}")
        raise HTTPException(status_code=401, detail="Invalid token audience")
    except jwt.InvalidSignatureError as e:
        logger.warning(f"Invalid token signature: {e}")
        raise HTTPException(status_code=401, detail="Invalid token signature")
    except jwt.DecodeError as e:
        logger.warning(f"Token decode error: {e}")
        raise HTTPException(status_code=401, detail="Token decode error")


async def verify_token(
    token: Annotated[str, Depends(get_oauth2_scheme)],
    settings: Annotated[Settings, Depends(get_settings)],
    signing_key: Annotated[PyJWK, Depends(get_signing_key)],
) -> dict[str, Any]:
    """FastAPI 依存性注入版"""
    return await _verify_token_impl(token, settings, signing_key)
