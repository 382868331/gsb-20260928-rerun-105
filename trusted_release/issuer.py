"""Issuer keys and rotation (versioned key directory).

Each issuer owns a directory of numbered key versions. Only the newest
version may sign; older keys stay on record so historical releases remain
viewable, but whether they are trusted is decided by the *current* trust
conditions at verification time (active status + applicability window).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from . import ed25519
from .encoding import canonical_json

KEYS_FILE = "keys.json"
SK_DIR = "private"


@dataclass
class KeyRecord:
    issuer_id: str
    key_version: int
    public_key: str          # base64 of 32-byte Ed25519 public key
    created_at: str
    status: str              # "active" | "rotated" | "revoked"
    scope: str               # applicable product/component scope
    role: str                # release approval role
    valid_from: str
    valid_to: str            # ISO timestamp or "" for open ended
    status_changed_at: str = ""

    def to_dict(self) -> dict:
        return {
            "issuer_id": self.issuer_id,
            "key_version": self.key_version,
            "public_key": self.public_key,
            "created_at": self.created_at,
            "status": self.status,
            "scope": self.scope,
            "role": self.role,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
            "status_changed_at": self.status_changed_at,
        }

    @staticmethod
    def from_dict(d: dict) -> "KeyRecord":
        return KeyRecord(
            issuer_id=d["issuer_id"],
            key_version=int(d["key_version"]),
            public_key=d["public_key"],
            created_at=d["created_at"],
            status=d["status"],
            scope=d["scope"],
            role=d.get("role", ""),
            valid_from=d["valid_from"],
            valid_to=d.get("valid_to", ""),
            status_changed_at=d.get("status_changed_at", ""),
        )


class IssuerKeyStore:
    def __init__(self, root: str):
        self.root = root
        self.keys_path = os.path.join(root, KEYS_FILE)
        os.makedirs(os.path.join(root, SK_DIR), exist_ok=True)
        if not os.path.exists(self.keys_path):
            self._write([])

    def _read(self) -> list[dict]:
        with open(self.keys_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _write(self, records: list[dict]) -> None:
        tmp = self.keys_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(
                json.dumps(records, indent=2, ensure_ascii=False, sort_keys=True)
            )
        os.replace(tmp, self.keys_path)

    def list_keys(self, issuer_id: str | None = None) -> list[KeyRecord]:
        records = [KeyRecord.from_dict(d) for d in self._read()]
        if issuer_id is not None:
            records = [r for r in records if r.issuer_id == issuer_id]
        return records

    def get_key(self, issuer_id: str, key_version: int) -> KeyRecord:
        for r in self.list_keys(issuer_id):
            if r.key_version == key_version:
                return r
        raise KeyError(f"key {issuer_id} v{key_version} not found")

    def latest_version(self, issuer_id: str) -> int | None:
        versions = [r.key_version for r in self.list_keys(issuer_id)]
        return max(versions) if versions else None

    def _secret_path(self, issuer_id: str, key_version: int) -> str:
        return os.path.join(self.root, SK_DIR, f"{issuer_id}.v{key_version}.key")

    def load_secret(self, issuer_id: str, key_version: int) -> bytes:
        path = self._secret_path(issuer_id, key_version)
        with open(path, "rb") as f:
            return f.read()

    def create_key(
        self,
        issuer_id: str,
        scope: str,
        now: str,
        valid_to: str = "",
        role: str = "",
    ) -> KeyRecord:
        """Rotate in a new active key; the previous one becomes 'rotated'."""
        records = self._read()
        versions = [
            d["key_version"] for d in records if d["issuer_id"] == issuer_id
        ]
        new_version = (max(versions) + 1) if versions else 1
        for d in records:
            if d["issuer_id"] == issuer_id and d["status"] == "active":
                d["status"] = "rotated"
                d["status_changed_at"] = now
        seed, pub = ed25519.generate_keypair()
        with open(self._secret_path(issuer_id, new_version), "wb") as f:
            f.write(seed)
        os.chmod(self._secret_path(issuer_id, new_version), 0o600)
        import base64

        rec = KeyRecord(
            issuer_id=issuer_id,
            key_version=new_version,
            public_key=base64.b64encode(pub).decode(),
            created_at=now,
            status="active",
            scope=scope,
            role=role,
            valid_from=now,
            valid_to=valid_to,
            status_changed_at=now,
        )
        records.append(rec.to_dict())
        self._write(records)
        return rec

    def set_status(
        self, issuer_id: str, key_version: int, status: str,
        status_changed_at: str = "",
    ) -> KeyRecord:
        if status not in ("active", "rotated", "revoked"):
            raise ValueError(f"bad status {status}")
        records = self._read()
        found = False
        for d in records:
            if d["issuer_id"] == issuer_id and d["key_version"] == key_version:
                d["status"] = status
                d["status_changed_at"] = status_changed_at
                found = True
        if not found:
            raise KeyError(f"key {issuer_id} v{key_version} not found")
        self._write(records)
        return self.get_key(issuer_id, key_version)
