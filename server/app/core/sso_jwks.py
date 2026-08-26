"""
JWKS retrieval and key selection for asymmetric SSO exchange tokens.

Ported from CyberSentinel-DLP (commits 074266b and f41a9db, gap-scan of
August 26 2026), merged into one file since SeceoKnight is adopting both at
once rather than migrating through the same two-step history.

WHY THIS EXISTS
---------------
The SSO exchange token was signed HS256 with DLP_SSO_SECRET -- a secret
shared with the SIEM. That means the DLP holds a key that can FORGE SIEM
tokens, not merely verify them, and with just-in-time provisioning enabled
a forged token does not just impersonate an existing user: it mints a DLP
account at whatever role the forger writes into the claims.

Under RS256 the DLP holds only the SIEM's PUBLIC key. A compromise of the
DLP config yields nothing that can sign anything, and the SIEM can rotate
keys without a coordinated flag day because each token names the key that
signs it in its `kid` header.

CACHE AND ROTATION
-------------------
The key set is cached for SSO_JWKS_CACHE_SECONDS. A token whose `kid` is
not in the cached set triggers ONE early refetch, rate-limited so an
attacker cannot turn unknown-kid tokens into a request amplifier against
the SIEM. That is what makes a rotation visible within seconds instead of
at the end of the cache window, without polling.

FAILURE POSTURE -- CLOSED
---------------------------
Every other cache in this codebase fails OPEN, because failing closed there
turns a dependency blip into an outage of a monitoring feature. This one is
different: it is an authentication decision, and a key set we could not
fetch is not evidence that a signature is good. Unreachable JWKS => the
login is refused, never accepted unverified.

CERTIFICATE PINNING
--------------------
The JWKS endpoint IS the trust anchor for every RS256 login: whoever can
answer for that URL serves their own public key and, from that moment,
mints SSO tokens the DLP accepts as genuine SIEM logins. A SIEM on an
internal network typically presents a self-signed certificate, so the
fetch fails closed against the system trust store by default -- correctly.
SIEM_JWKS_CA_BUNDLE is the escape hatch, and it is a pinned certificate,
never a disabled check: point it at the SIEM's own certificate (a
self-signed leaf works, it is its own issuer) or at the CA that signed it.
The DLP then stops trusting the SIEM the moment that certificate is
rotated -- that is the point, but put its expiry in a calendar, because the
failure mode is silent: "SSO stopped working".
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

import structlog

logger = structlog.get_logger()

# Asymmetric families we accept. Deliberately explicit: "none" must never be
# reachable, and an algorithm the SIEM does not use should not be an option.
ASYMMETRIC_ALGS = frozenset({
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512",
})

# Symmetric -- verified with the shared secret, kept for the migration window.
SYMMETRIC_ALGS = frozenset({"HS256", "HS384", "HS512"})

_keys: List[Dict[str, Any]] = []
_fetched_at: float = 0.0
_last_forced: float = 0.0
_source: str = ""

# Floor between forced refetches on an unknown kid.
_FORCE_REFRESH_MIN_INTERVAL = 30.0
_HTTP_TIMEOUT = 5.0


class JWKSUnavailable(RuntimeError):
    """The key set could not be obtained, so nothing can be verified."""


class JWKSKeyNotFound(JWKSUnavailable):
    """We HAVE the key set; it simply does not contain the key this token names.

    A distinct type because the two failures belong to different parties. An
    unfetchable key set is our outage and should say 503 so the caller retries.
    A token naming a key the issuer does not publish is a bad token and must
    say 401 -- reporting that as a server fault invites a client to retry a
    forgery forever, and hides a real rejection inside our own error budget.
    """


def reset_cache() -> None:
    """Drop the cached key set (tests, and config changes at runtime)."""
    global _keys, _fetched_at, _last_forced, _source
    _keys, _fetched_at, _last_forced, _source = [], 0.0, 0.0, ""


async def _fetch(url: str) -> List[Dict[str, Any]]:
    import httpx

    # TLS verification is never disabled here, only re-pointed -- see the
    # module docstring's CERTIFICATE PINNING section for why: this document
    # is the trust anchor for every RS256 login, so whoever can spoof this
    # response can mint SSO tokens the DLP will accept.
    from app.core.config import settings

    ca_bundle = (getattr(settings, "SIEM_JWKS_CA_BUNDLE", "") or "").strip()
    verify: Any = True
    if ca_bundle:
        if os.path.isfile(ca_bundle):
            verify = ca_bundle
        else:
            # Failing closed on a misconfigured path is deliberate: falling
            # back to the system store would silently restore the very
            # failure the operator set this to fix, and they would not find
            # out until an attacker did.
            raise JWKSUnavailable(
                f"SIEM_JWKS_CA_BUNDLE points at {ca_bundle}, which does not "
                "exist inside the container -- check the volume mount"
            )

    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, verify=verify) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        body = resp.json()

    keys = body.get("keys") if isinstance(body, dict) else None
    if not isinstance(keys, list) or not keys:
        raise JWKSUnavailable("JWKS document contains no keys")
    # Keep only well-formed public keys. A malformed entry must not shadow a
    # good one with the same kid further down the list.
    return [k for k in keys if isinstance(k, dict) and k.get("kty")]


async def _load(url: str, force: bool = False) -> List[Dict[str, Any]]:
    global _keys, _fetched_at, _last_forced, _source

    now = time.monotonic()
    if _source != url:
        # URL changed under us (config reload) -- the old key set is not ours.
        reset_cache()
        _source = url

    from app.core.config import settings
    ttl = max(30, int(getattr(settings, "SSO_JWKS_CACHE_SECONDS", 600) or 600))

    fresh = _keys and (now - _fetched_at) < ttl
    if fresh and not force:
        return _keys

    if force and _keys and (now - _last_forced) < _FORCE_REFRESH_MIN_INTERVAL:
        # Rate-limited: serve what we have rather than letting a stream of
        # unknown-kid tokens become an amplifier aimed at the SIEM.
        return _keys
    if force:
        _last_forced = now

    try:
        keys = await _fetch(url)
    except Exception as e:
        if _keys:
            # A stale-but-real key set still verifies genuine tokens. Serving
            # it beats refusing every login because the SIEM blipped.
            logger.warning("SSO JWKS refresh failed; using cached keys",
                           url=url, error=str(e))
            return _keys
        logger.error("SSO JWKS fetch failed and nothing is cached",
                     url=url, error=str(e))
        raise JWKSUnavailable(str(e)) from e

    _keys = keys
    _fetched_at = now
    logger.info("SSO JWKS loaded", url=url, key_count=len(keys),
                kids=[k.get("kid") for k in keys][:10])
    return _keys


async def get_key(kid: Optional[str], url: str) -> Dict[str, Any]:
    """
    The JWK that should verify a token, selected by `kid`.

    A token without a kid is accepted only when the key set holds exactly
    one key -- with several published, guessing which one signed it would
    mean trying them all, and "some key in the set verifies this" is a
    materially weaker statement than "the key the issuer named verifies
    this".
    """
    keys = await _load(url)

    if kid:
        for k in keys:
            if k.get("kid") == kid:
                return k
        # Unknown kid is the normal appearance of a rotation, not an attack.
        keys = await _load(url, force=True)
        for k in keys:
            if k.get("kid") == kid:
                logger.info("SSO JWKS picked up rotated key", kid=kid)
                return k
        raise JWKSKeyNotFound(f"no key matches kid {kid!r}")

    if len(keys) == 1:
        return keys[0]
    raise JWKSKeyNotFound(
        "token has no kid and the key set holds "
        f"{len(keys)} keys -- cannot choose one"
    )
