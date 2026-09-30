import binascii
import shutil
import subprocess

import pytest

from trusted_release import ed25519


# RFC 8032 section 7.1 vectors 2 and 3
VECTORS = [
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]


@pytest.mark.parametrize("seed_hex,pub_hex,msg_hex,sig_hex", VECTORS)
def test_rfc8032_vectors(seed_hex, pub_hex, msg_hex, sig_hex):
    seed = binascii.unhexlify(seed_hex)
    pub = binascii.unhexlify(pub_hex)
    msg = binascii.unhexlify(msg_hex)
    expected_sig = binascii.unhexlify(sig_hex)
    assert ed25519.public_from_secret(seed) == pub
    sig = ed25519.sign(seed, msg)
    assert sig == expected_sig
    assert ed25519.verify(pub, msg, sig)


OPENSSL = shutil.which("openssl")


def _spki_der(pub32: bytes) -> bytes:
    algo = b"\x30\x05\x06\x03\x2b\x65\x70"

    def tlen(n):
        if n < 0x80:
            return bytes([n])
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(b)]) + b

    bitstring = b"\x03" + tlen(1 + len(pub32)) + b"\x00" + pub32
    body = algo + bitstring
    return b"\x30" + tlen(len(body)) + body


@pytest.mark.skipif(OPENSSL is None, reason="openssl not available")
def test_openssl_verifies_our_signature(tmp_path):
    seed, pub = ed25519.generate_keypair()
    msg = b"interop check"
    sig = ed25519.sign(seed, msg)
    (tmp_path / "pub.der").write_bytes(_spki_der(pub))
    (tmp_path / "msg").write_bytes(msg)
    (tmp_path / "sig").write_bytes(sig)
    r = subprocess.run(
        [OPENSSL, "pkeyutl", "-verify", "-rawin", "-pubin",
         "-inkey", str(tmp_path / "pub.der"), "-keyform", "DER",
         "-in", str(tmp_path / "msg"), "-sigfile", str(tmp_path / "sig")],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr


def test_tamper_rejected():
    seed, pub = ed25519.generate_keypair()
    sig = ed25519.sign(seed, b"hello")
    assert not ed25519.verify(pub, b"hellp", sig)
    bad = bytearray(sig)
    bad[0] ^= 1
    assert not ed25519.verify(pub, b"hello", bytes(bad))
    assert not ed25519.verify(b"\x00" * 32, b"hello", sig)


def test_bad_lengths():
    assert not ed25519.verify(b"short", b"m", b"\x00" * 64)
    assert not ed25519.verify(b"\x00" * 32, b"m", b"short")
    with pytest.raises(ValueError):
        ed25519.public_from_secret(b"short")
