"""Pure-Python Ed25519 (RFC 8032), standard library only.

Suitable for offline signing/verification without third-party crypto
packages. Correctness is covered by the RFC 8032 test vectors in tests.
"""

from __future__ import annotations

import hashlib
import os

p = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
d = (-121665 * pow(121666, p - 2, p)) % p
I = pow(2, (p - 1) // 4, p)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(d * y * y + 1, p - 2, p)
    x = pow(xx, (p + 3) // 8, p)
    if (x * x - xx) % p != 0:
        x = (x * I) % p
    if x % 2 != 0:
        x = p - x
    return x


_By = 4 * pow(5, p - 2, p) % p
_Bx = _xrecover(_By)
B = (_Bx % p, _By % p)


def _edwards(P, Q):
    x1, y1 = P
    x2, y2 = Q
    dxy = d * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * pow(1 + dxy, p - 2, p)
    y3 = (y1 * y2 + x1 * x2) * pow(1 - dxy, p - 2, p)
    return x3 % p, y3 % p


def _scalarmult(P, e: int):
    if e == 0:
        return 0, 1
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q


def _hint(m: bytes) -> int:
    return int.from_bytes(hashlib.sha512(m).digest(), "little")


def _expanded_secret(sk_seed: bytes) -> tuple[int, bytes]:
    if len(sk_seed) != 32:
        raise ValueError("Ed25519 secret key seed must be 32 bytes")
    h = hashlib.sha512(sk_seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_from_secret(sk_seed: bytes) -> bytes:
    a, _ = _expanded_secret(sk_seed)
    A = _scalarmult(B, a)
    return _encode_point(A)


def _encode_point(P) -> bytes:
    x, y = P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decodepoint(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= p:
        return None
    try:
        x = _xrecover(y)
    except Exception:
        return None
    if x == 0 and sign:
        return None
    if x % 2 != sign:
        x = p - x
    P = (x, y)
    if not _on_curve(P):
        return None
    if _scalarmult(P, L) != (0, 1):
        return None
    return P


def _on_curve(P) -> bool:
    x, y = P
    return (-x * x + y * y - 1 - d * x * x * y * y) % p == 0


def sign(sk_seed: bytes, msg: bytes) -> bytes:
    a, prefix = _expanded_secret(sk_seed)
    A = _encode_point(_scalarmult(B, a))
    r = _hint(prefix + msg) % L
    R = _scalarmult(B, r)
    Rb = _encode_point(R)
    S = (r + _hint(Rb + A + msg) * a) % L
    return Rb + S.to_bytes(32, "little")


def verify(public_key: bytes, msg: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    A = _decodepoint(public_key)
    if A is None:
        return False
    R = _decodepoint(signature[:32])
    if R is None:
        return False
    S = int.from_bytes(signature[32:], "little")
    if S >= L:
        return False
    h = _hint(signature[:32] + public_key + msg) % L
    return _scalarmult(B, S) == _edwards(R, _scalarmult(A, h))


def generate_keypair() -> tuple[bytes, bytes]:
    seed = os.urandom(32)
    return seed, public_from_secret(seed)
