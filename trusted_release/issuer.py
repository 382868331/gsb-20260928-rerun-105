"""Issuer key store with versioning and rotation.

Every issuer owns a sequence of numbered key versions. Creating a new key
rotates the issuer: the previously active key becomes ``rotated`` and the
new key becomes ``active``. Old public keys remain in the store so that the
history of releases can always be inspected; whether a historical
signature still validates is decided by the *current* trust conditions
(key status, validity window and revocation list) at verification time.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass

from . import ed25519

KEYS_FILE = "keys.json"
SECRET_DIR = "private"
STATUSES = ("active", "rotated", "revoked")


@dataclass(frozen=True)
class KeyRecord:
    issuer_id: str
    key_version: int
    public_key: str  # base64-encoded 32-byte Ed25519 public key
    created_at: str
    status: str       # active | rotated | revoked
    scope: str        # "*", "product:<name>" or an exact scope label
    valid_from: str
    valid_to: str     # ISO-8601 UTC timestamp, "" if open ended

    def to_dict(self) -> dict:
        return {
            "issuer_id": self.issuer_id,
            "key_version": self.key_version,
            "public_key": self.public_key,
            "created_at": self.created_at,
            "status": self.status,
            "scope": self.scope,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "KeyRecord":
        return cls(
            issuer_id=data["issuer_id"],
            key_version=int(data["key_version"]),
            public_key=data["public_key"],
            created_at=data["created_at"],
            status=data["status"],
            scope=data["scope"],
            valid_from=data["valid_from"],
            valid_to=data.get("valid_to", ""),
        )


class IssuerKeyStore:
    def __init__(self, root: str):
        self.root = root
        self.keys_path = os.path.join(root, KEYS_FILE)
        os.makedirs(os.path.join(root, SECRET_DIR), exist_ok=True)
        if not os.path.exists(self.keys_path):
            self._write_all([])

    # ----- persistence (atomic) -----
    def _read_all(self) -> list[dict]:
        with open(self.keys_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, list):
            raise ValueError("corrupt keystore: keys.json must be a list")
        return data

    def _write_all(self, records: list[dict]) -> None:
        tmp = self.keys_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(records, fh, indent=2, sort_keys=True, ensure_ascii=False)
        os.replace(tmp, self.keys_path)

    # ----- queries -----
    def list_keys(self, issuer_id: str | None = None) -> list[KeyRecord]:
        records = [KeyRecord.from_dict(d) for d in self._read_all()]
        if issuer_id is not None:
            records = [r for r in records if r.issuer_id == issuer_id]
        return records

    def get_key(self, issuer_id: str, key_version: int) -> KeyRecord:
        for record in self.list_keys(issuer_id):
            if record.key_version == key_version:
                return record
        raise KeyError(f"no key {issuer_id} v{key_version} in trust store")

    def latest_version(self, issuer_id: str) -> int | None:
        versions = [r.key_version for r in self.list_keys(issuer_id)]
        return max(versions) if versions else None

    def public_key_bytes(self, issuer_id: str, key_version: int) -> bytes:
        return base64.b64decode(
            self.get_key(issuer_id, key_version).public_key, validate=True
        )

    # ----- secret material -----
    def _secret_path(self, issuer_id: str, key_version: int) -> str:
        return os.path.join(
            self.root, SECRET_DIR, f"{issuer_id}.v{key_version}.key"
        )

    def load_secret(self, issuer_id: str, key_version: int) -> bytes:
        with open(self._secret_path(issuer_id, key_version), "rb") as fh:
            seed = fh.read()
        if len(seed) != 32:
            raise ValueError("invalid secret seed length")
        return seed

    # ----- rotation / status management -----
    def create_key(
        self,
        issuer_id: str,
        scope: str,
        now: str,
        valid_to: str = "",
    ) -> KeyRecord:
        """Issue a new active key version; demote the old one to rotated."""
        records = self._read_all()
        versions = [
            int(d["key_version"])
            for d in records
            if d["issuer_id"] == issuer_id
        ]
        new_version = (max(versions) + 1) if versions else 1
        for d in records:
            if d["issuer_id"] == issuer_id and d["status"] == "active":
                d["status"] = "rotated"

        seed, public = ed25519.generate_keypair()
        secret_path = self._secret_path(issuer_id, new_version)
        tmp = secret_path + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(seed)
        os.replace(tmp, secret_path)
        os.chmod(secret_path, 0o600)

        record = KeyRecord(
            issuer_id=issuer_id,
            key_version=new_version,
            public_key=base64.b64encode(public).decode("ascii"),
            created_at=now,
            status="active",
            scope=scope,
            valid_from=now,
            valid_to=valid_to,
        )
        records.append(record.to_dict())
        self._write_all(records)
        return record

    def set_status(
        self, issuer_id: str, key_version: int, status: str
    ) -> KeyRecord:
        if status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        records = self._read_all()
        for d in records:
            if d["issuer_id"] == issuer_id and d["key_version"] == key_version:
                d["status"] = status
                break
        else:
            raise KeyError(f"no key {issuer_id} v{key_version} in trust store")
        self._write_all(records)
        return self.get_key(issuer_id, key_version)
