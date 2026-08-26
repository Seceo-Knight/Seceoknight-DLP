"""
Signature and claim verification for SIEM SSO exchange tokens.

Ported from CyberSentinel-DLP (commit 074266b, gap-scan of August 26 2026).

ALGORITHM ROUTING
------------------
The token's own signed `alg` header selects how it is verified:

    RS*/PS*/ES*  ->  the SIEM's public key, fetched from SIEM_JWKS_URL and
                      selected by `kid` (app/core/sso_jwks.py)
    HS*          ->  the shared secret DLP_SSO_SECRET

Routing on the header is safe here only because the two paths use disjoint
key material: the classic downgrade attack -- take the published RSA public
key, sign HS256 with it as the "secret" -- fails because the HS256 path
never uses a key derived from the JWKS. It uses a secret the attacker does
not have.

The list passed to the verifier is always the single routed algorithm,
never the union, so a token cannot nominate a verifier that was not
intended for it, and `none` is unreachable by construction.

Retiring HS256 is deliberately a config action, not a code change: clear
DLP_SSO_SECRET and every symmetric token is refused from that moment.
Keeping both configured is the migration window, and is the SIEM's call to
close.

AUDIENCE
--------
`aud` is enforced strictly on the asymmetric path -- that is the new
contract for a SeceoKnight deployment turning this on. On the symmetric
path it is enforced only when the token actually carries the claim,
because SeceoKnight's own existing exchange contract never required one and
must not lock out an already-integrated SIEM the moment RS256 support is
deployed. Such an integration starts being checked the instant it starts
sending one; there is no switch to remember to flip.

CLOCK
-----
The exchange token lives ~30 seconds. Two machines a minute apart therefore
reject every login, with nothing in either log that names the clock as the
cause. SSO_CLOCK_LEEWAY_SECONDS absorbs that, and SSO_REQUIRE_EXP closes
the other side of it: python-jose does not require `exp` at all by
default, so a token that simply omits it would otherwise never expire.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Tuple

import structlog
from jose import jwt as jose_jwt
from jose.exceptions import ExpiredSignatureError, JWTError

from app.core import sso_jwks

logger = structlog.get_logger()


class SSOTokenError(Exception):
    """Token is unacceptable -- maps to 401."""

    def __init__(self, detail: str, expired: bool = False):
        super().__init__(detail)
        self.detail = detail
        self.expired = expired


class SSOUnavailable(Exception):
    """SSO cannot be performed at all right now -- maps to 503."""


def sso_configured() -> bool:
    from app.core.config import settings

    return bool(settings.DLP_SSO_SECRET or settings.SIEM_JWKS_URL)


async def verify_exchange_token(token: str) -> Tuple[Dict[str, Any], str]:
    """
    Verify an exchange token and return (claims, alg).

    Raises SSOTokenError for anything wrong with the token, SSOUnavailable
    when the DLP cannot verify it for reasons that are not the token's
    fault (JWKS unreachable with nothing cached).
    """
    from app.core.config import settings

    try:
        header = jose_jwt.get_unverified_header(token)
    except Exception as e:
        raise SSOTokenError("Invalid exchange token: unreadable header") from e

    alg = str(header.get("alg") or "").upper()
    kid = header.get("kid")

    if alg in sso_jwks.ASYMMETRIC_ALGS:
        if not settings.SIEM_JWKS_URL:
            raise SSOTokenError(
                f"Invalid exchange token: {alg} presented but no JWKS is configured"
            )
        try:
            key: Any = await sso_jwks.get_key(kid, settings.SIEM_JWKS_URL)
        except sso_jwks.JWKSKeyNotFound as e:
            # We can see the issuer's published keys and this is not one of
            # them. That is the token's problem, not ours -- 401, not 503.
            raise SSOTokenError(f"Invalid exchange token: {e}") from e
        except sso_jwks.JWKSUnavailable as e:
            # Not the token's fault, and not something a retry by the user
            # fixes -- say so honestly rather than reporting a bad token.
            logger.error("SSO exchange: cannot verify, JWKS unavailable",
                         kid=kid, error=str(e))
            raise SSOUnavailable(str(e)) from e
        enforce_aud = True
    elif alg in sso_jwks.SYMMETRIC_ALGS:
        if not settings.DLP_SSO_SECRET:
            raise SSOTokenError(
                "Invalid exchange token: symmetric signing is no longer accepted"
            )
        key = settings.DLP_SSO_SECRET
        # Legacy tolerance -- see the module docstring.
        try:
            enforce_aud = "aud" in (jose_jwt.get_unverified_claims(token) or {})
        except Exception:
            enforce_aud = False
    else:
        raise SSOTokenError(f"Invalid exchange token: unsupported algorithm {alg!r}")

    audience = (settings.SSO_AUDIENCE or "").strip()
    leeway = max(0, int(getattr(settings, "SSO_CLOCK_LEEWAY_SECONDS", 60) or 0))
    options: Dict[str, Any] = {
        "leeway": leeway,
        "require_exp": bool(getattr(settings, "SSO_REQUIRE_EXP", True)),
        "verify_aud": bool(audience and enforce_aud),
    }

    try:
        claims = jose_jwt.decode(
            token,
            key,
            # The routed algorithm ONLY. Never the union of both families:
            # that is what would let a token choose its own verifier.
            algorithms=[alg],
            audience=audience if (audience and enforce_aud) else None,
            options=options,
        )
    except ExpiredSignatureError as e:
        raise SSOTokenError("Exchange token has expired", expired=True) from e
    except JWTError as e:
        raise SSOTokenError(f"Invalid exchange token: {e}") from e

    # python-jose treats a MISSING aud as acceptable -- it only compares the
    # claim when the token happens to carry one. So passing an audience is
    # not by itself an audience check: a token with no aud at all sails
    # through. On the asymmetric path aud is mandatory, so the presence
    # test has to be ours. Checked against the VERIFIED claims, after the
    # signature.
    if enforce_aud and audience and not claims.get("aud"):
        raise SSOTokenError("Invalid exchange token: missing aud claim")

    # An exchange token is a hand-off, not a session: it should live
    # seconds. One claiming far longer is either a misconfiguration or an
    # attempt to obtain a durable credential, and it would also outlive the
    # nonce that makes it single-use -- nonce retention is capped so a
    # token cannot pin a Redis entry indefinitely, and without this bound
    # that cap is a replay window rather than a safeguard.
    max_age = int(getattr(settings, "SSO_MAX_TOKEN_AGE_SECONDS", 600) or 0)
    if max_age > 0:
        exp = claims.get("exp")
        try:
            remaining = int(exp) - int(time.time()) if exp else 0
        except (TypeError, ValueError):
            remaining = 0
        if remaining > max_age:
            raise SSOTokenError(
                f"Invalid exchange token: claims {remaining}s of validity, "
                f"maximum is {max_age}s"
            )

    return claims, alg
