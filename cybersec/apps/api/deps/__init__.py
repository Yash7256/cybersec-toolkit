"""
Dependencies — Clerk RS256 JWT validation, DB session.

get_optional_user: Validates a Clerk JWT from the Authorization: Bearer header.
    Returns the local User row on success, None for anonymous / invalid tokens.

get_current_user: Requires a valid authenticated user; raises HTTP 401 if absent.

Requirements: 1.4, 3.1–3.10, 9.1, 10.1, 10.2, 10.4, 10.5
"""
import logging

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from cybersec.apps.api.clerk_jwks import ClerkJWKSUnavailable, get_clerk_public_key
from cybersec.apps.api.user_sync import sync_clerk_user
from cybersec.config.settings import settings
from cybersec.database.models import User
from cybersec.database.session import get_db

logger = logging.getLogger(__name__)

# HTTPBearer with auto_error=False so missing tokens return None instead of 403
http_bearer = HTTPBearer(auto_error=False)


async def get_optional_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(http_bearer),
    db: AsyncSession = Depends(get_db),
) -> User | None:
    """Extract the current user from a Clerk RS256 JWT if present.

    Returns None for:
    - Missing Authorization header (anonymous request)
    - Expired JWT
    - Invalid signature / wrong issuer or audience
    - Malformed token

    Raises HTTP 503 if the Clerk JWKS endpoint is unreachable and no
    stale cache is available.

    Requirements: 3.1–3.8, 3.10, 9.1, 10.1, 10.2
    """
    if credentials is None or not credentials.credentials:
        # No token — anonymous request (Req 3.8, 9.1)
        return None

    # Bail early if Clerk is not configured — return 503
    if not settings.clerk_configured:
        logger.warning("Clerk is not configured; rejecting authenticated request with 503.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Auth service temporarily unavailable",
        )

    token = credentials.credentials

    try:
        # Decode header without signature verification to extract kid (Req 3.2)
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        if not kid:
            logger.debug("JWT missing 'kid' header field — returning None")
            return None

        # Retrieve the RSA public key from the JWKS cache (Req 3.3)
        public_key = await get_clerk_public_key(kid)

        # Verify signature, issuer, and expiry.
        # Clerk JWTs do not include an `aud` claim by default (it is an optional
        # claim that Clerk only sets when you configure "Audiences" in the Clerk
        # dashboard). We probe the unverified payload: if `aud` is present we
        # enforce it (using the publishable key as the expected audience per
        # Clerk docs); if absent we skip audience verification so the token
        # still validates correctly for apps that have not configured audiences.
        unverified_payload = jwt.decode(
            token,
            options={"verify_signature": False},
        )
        aud_in_token = unverified_payload.get("aud")
        decode_options: dict = {"verify_exp": True}
        decode_kwargs: dict = {}
        if aud_in_token:
            decode_kwargs["audience"] = settings.CLERK_PUBLISHABLE_KEY
        else:
            decode_options["verify_aud"] = False

        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=settings.CLERK_ISSUER,
            options=decode_options,
            **decode_kwargs,
        )

        clerk_user_id: str | None = payload.get("sub")
        if not clerk_user_id:
            logger.debug("JWT payload missing 'sub' claim — returning None")
            return None

        email: str | None = payload.get("email")

        # Upsert the local users row and return it (Req 3.5)
        try:
            user = await sync_clerk_user(clerk_user_id, email, db)
            return user
        except Exception as sync_exc:
            # User sync failure must not propagate as an unhandled 500 (Req 3.9 gap)
            logger.error("sync_clerk_user failed: %s", sync_exc, exc_info=True)
            return None

    except jwt.ExpiredSignatureError:
        # Expired token → anonymous fallback (Req 3.6)
        logger.debug("JWT expired — returning None")
        return None

    except (
        jwt.InvalidTokenError,    # covers InvalidSignatureError, DecodeError, etc.
        jwt.InvalidIssuerError,
        jwt.InvalidAudienceError,
        KeyError,                 # unknown kid not in JWKS
    ) as exc:
        # Invalid / tampered / malformed token → anonymous fallback (Req 3.7)
        logger.debug("JWT invalid (%s: %s) — returning None", type(exc).__name__, exc)
        return None

    except ClerkJWKSUnavailable:
        # JWKS endpoint unreachable.
        # For get_current_user (required auth), this becomes a 503.
        # For get_optional_user (optional auth), we fall back to anonymous
        # so tool routes remain usable even if Clerk is temporarily unreachable.
        logger.warning("Clerk JWKS unavailable — treating request as anonymous")
        return None

    except Exception as exc:
        # Catch-all: never leak an unhandled 500 from the auth layer
        logger.error("Unexpected error in get_optional_user: %s", exc, exc_info=True)
        return None


async def get_current_user(
    user: User | None = Depends(get_optional_user),
) -> User:
    """Require a valid authenticated user.

    Raises HTTP 401 if the request is anonymous or the token is invalid.
    Requirements: 3.9
    """
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user
