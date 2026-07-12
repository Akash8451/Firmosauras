"""Inline HS256 JWT verification + RBAC permission table (SCHEMA.md §5).

This is the SAME auth mechanism the Upload Gateway enforces — HS256-signed tokens
carrying a `role` claim (`admin` / `analyst` / `reader`), validated with the
shared `JWT_SECRET`. It is implemented with the stdlib only (no PyJWT dependency)
per the "inlined JWT" guidance, and is used by the Group 3 surfaces that need it
(the WebSocket notifier and the CVE HTTP endpoints).

NOTE (integration / Task 15): when a single shared auth module lands, these
helpers should be consolidated there so there is exactly one implementation. The
mechanism (HS256 + role claim + shared secret) is already identical — this is not
a second, competing scheme.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Iterable, Optional

# RBAC permission table (analysis-modules-rbac.md / SCHEMA.md §5).
ROLES = ("admin", "analyst", "reader")

_PERMISSIONS = {
    "admin": {"upload", "analyze", "view", "feedback", "manage_config"},
    "analyst": {"upload", "analyze", "view", "feedback"},
    "reader": {"view"},
}


class AuthError(Exception):
    """Raised when a token is missing, malformed, mis-signed, or expired."""


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def encode_jwt(claims: dict, secret: str, *, algorithm: str = "HS256") -> str:
    """Encode an HS256 JWT (used by tests + local token minting)."""
    if algorithm != "HS256":
        raise ValueError("only HS256 is supported")
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(sig)}"


def decode_jwt(token: str, secret: str, *, algorithms: Iterable[str] = ("HS256",)) -> dict:
    """Verify signature + expiry and return the claims. Raises AuthError on any problem."""
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError as exc:
        raise AuthError("malformed token") from exc

    try:
        header = json.loads(_b64url_decode(header_b64))
    except Exception as exc:
        raise AuthError("malformed header") from exc

    if header.get("alg") not in algorithms:
        raise AuthError(f"unexpected alg {header.get('alg')!r}")

    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    try:
        provided = _b64url_decode(sig_b64)
    except Exception as exc:
        raise AuthError("malformed signature") from exc
    if not hmac.compare_digest(expected, provided):
        raise AuthError("bad signature")

    try:
        claims = json.loads(_b64url_decode(payload_b64))
    except Exception as exc:
        raise AuthError("malformed payload") from exc

    exp = claims.get("exp")
    if exp is not None and time.time() > float(exp):
        raise AuthError("token expired")
    return claims


def _secret() -> Optional[str]:
    return os.getenv("JWT_SECRET")


def verify_token(token: Optional[str]) -> dict:
    """Verify a token using the env `JWT_SECRET`; return claims. Raises AuthError."""
    secret = _secret()
    if not secret:
        raise AuthError("JWT_SECRET not configured")
    if not token:
        raise AuthError("missing token")
    algo = os.getenv("JWT_ALGORITHM", "HS256")
    return decode_jwt(token, secret, algorithms=(algo,))


def role_of(claims: dict) -> str:
    role = claims.get("role")
    if role not in ROLES:
        raise AuthError(f"invalid role {role!r}")
    return role


def has_permission(role: str, permission: str) -> bool:
    return permission in _PERMISSIONS.get(role, set())


def require_permission(claims: dict, permission: str) -> str:
    """Return the role if it holds `permission`, else raise AuthError."""
    role = role_of(claims)
    if not has_permission(role, permission):
        raise AuthError(f"role {role!r} lacks permission {permission!r}")
    return role


def auth_enabled() -> bool:
    """Auth is enforced only when a JWT secret is configured (local dev may omit it)."""
    return bool(_secret())
