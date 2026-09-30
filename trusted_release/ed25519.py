"""Pure-Python Ed25519 signature scheme per RFC 8032 (stdlib only).

Intended for offline signing and verification. The implementation is
validated against the RFC 8032 test vectors (see ``tests``) and produces
signatures that OpenSSL can verify.
"""

from __future__ import annotations

import hashlib
import os

_p = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_d = (-121665 * pow(121666, _p - 2, _p)) % _p
_I = pow(2, (_p - 1) // 4, _p)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_d * y * y + 1, _p - 2, _p)
    x = pow(xx, (_p + 3) // 8, _p)
    if (x * x - xx) % _p != 0:
        x = (x * _I) % _p
    if x % 2 != 0:
        x = _p - x
    return x


_By = 4 * pow(5, _p - 2, _p) % _p
_B = (_xrecover(_By) % _p, _By)


def _edwards(P, Q):
    x1, y1 = P
    x2, y2 = Q
    dxy = _d * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * pow(1 + dxy, _p - 2, _p)
    y3 = (y1 * y2 + x1 * x2) * pow(1 - dxy, _p - 2, _p)
    return x3 % _p, y3 % _p


def _scalarmult(P, e: int):
    if e == 0:
        return 0, 1
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q


def _hint(message: bytes) -> int:
    return int.from_bytes(hashlib.sha512(message).digest(), "little")


def _expand(seed: bytes) -> tuple[int, bytes]:
    if len(seed) != 32:
        raise ValueError("Ed25519 secret seed must be exactly 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def _encode(point) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def public_from_secret(seed: bytes) -> bytes:
    a, _ = _expand(seed)
    return _encode(_scalarmult(_B, a))


def _decode(point_bytes: bytes):
    if len(point_bytes) != 32:
        return None
    y = int.from_bytes(point_bytes, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _p:
        return None
    try:
        x = _xrecover(y)
    except Exception:
        return None
    if x == 0 and sign:
        return None
    if x % 2 != sign:
        x = _p - x
    point = (x, y)
    if (-x * x + y * y - 1 - _d * x * x * y * y) % _p != 0:
        return None
    if _scalarmult(point, _L) != (0, 1):
        return None
    return point


def sign(seed: bytes, message: bytes) -> bytes:
    a, prefix = _expand(seed)
    A = _encode(_scalarmult(_B, a))
    r = _hint(prefix + message) % _L
    R = _encode(_scalarmult(_B, r))
    S = (r + _hint(R + A + message) * a) % _L
    return R + S.to_bytes(32, "little")


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    A = _decode(public_key)
    R = _decode(signature[:32])
    if A is None or R is None:
        return False
    S = int.from_bytes(signature[32:], "little")
    if S >= _L:
        return False
    h = _hint(signature[:32] + public_key + message) % _L
    return _scalarmult(_B, S) == _edwards(R, _scalarmult(A, h))


def generate_keypair() -> tuple[bytes, bytes]:
    seed = os.urandom(32)
    return seed, public_from_secret(seed)
