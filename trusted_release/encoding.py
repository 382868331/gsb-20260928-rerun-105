"""Canonical JSON serialization and SHA-256 content hashing."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(obj: Any) -> bytes:
    """Deterministic encoding: sorted keys, compact separators, UTF-8."""
    return json.dumps(
        obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def canonical_hash(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(obj)).hexdigest()


def digest_bytes(data: bytes, algo: str = "sha256") -> str:
    return algo + ":" + hashlib.new(algo, data).hexdigest()


def file_digest(path: str, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return algo + ":" + h.hexdigest()
