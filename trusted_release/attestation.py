"""Release attestation signing and versioned revocation material."""

from __future__ import annotations

import base64
import json
import os

from . import ed25519
from .encoding import canonical_hash, canonical_json

ATTESTATION_TYPE = "trusted-release/attestation/v1"
APPROVAL_TYPE = "trusted-release/approval/v1"


def build_attestation(
    *,
    release_id: str,
    product: str,
    version: str,
    artifact_digest: str,
    build_spec_digest: str,
    issuer_id: str,
    key_version: int,
    scope: str,
    issued_at: str,
    expires_at: str,
    not_before: str,
) -> dict:
    """Attestation binds content + build spec + issuer + applicability.

    scope/product/version define the applicability range; expiry is carried
    in the signed payload so it cannot be altered by an attacker.
    """
    return {
        "type": ATTESTATION_TYPE,
        "release_id": release_id,
        "product": product,
        "version": version,
        "scope": scope,
        "artifact_digest": artifact_digest,
        "build_spec_digest": build_spec_digest,
        "issuer_id": issuer_id,
        "key_version": key_version,
        "issued_at": issued_at,
        "not_before": not_before,
        "expires_at": expires_at,
    }


def sign_attestation(attestation: dict, secret_seed: bytes) -> dict:
    payload = canonical_json(attestation)
    sig = ed25519.sign(secret_seed, payload)
    record = {
        "attestation": attestation,
        "signature": base64.b64encode(sig).decode("ascii"),
    }
    record["attestation_id"] = canonical_hash(record["attestation"])
    return record


def build_approval(
    *,
    candidate: dict,
    issuer_id: str,
    key_version: int,
    role: str,
    scope: str,
    issued_at: str,
    expires_at: str,
    not_before: str,
) -> dict:
    return {
        "type": APPROVAL_TYPE,
        "candidate_id": candidate["candidate_id"],
        "candidate_digest": candidate["candidate_digest"],
        "release_id": candidate["release_id"],
        "product": candidate["product"],
        "version": candidate["version"],
        "artifact_digest": candidate["artifact_digest"],
        "build_spec_digest": candidate["build_spec_digest"],
        "policy_id": candidate["policy"]["policy_id"],
        "policy_version": candidate["policy"]["policy_version"],
        "policy_digest": candidate["policy_digest"],
        "issuer_id": issuer_id,
        "key_version": key_version,
        "role": role,
        "scope": scope,
        "issued_at": issued_at,
        "not_before": not_before,
        "expires_at": expires_at,
    }


def verify_signature(attestation: dict, signature_b64: str, public_key: bytes) -> bool:
    try:
        sig = base64.b64decode(signature_b64, validate=True)
    except Exception:
        return False
    return ed25519.verify(public_key, canonical_json(attestation), sig)


class RevocationList:
    """Versioned revocation material (CRL) directory.

    File layout::

        crl/versions/<n>.json   immutable snapshot
        crl/current.json        pointer to the current snapshot

    Each snapshot is content-hashed and signed by the designated revocation
    issuer key. Re-verification always uses the *current* snapshot; older
    snapshots remain for historical inspection.
    """

    TYPE = "trusted-release/revocation-list/v1"

    def __init__(self, root: str):
        self.root = root
        self.ver_dir = os.path.join(root, "versions")
        os.makedirs(self.ver_dir, exist_ok=True)
        self.current_path = os.path.join(root, "current.json")
        if not os.path.exists(self.current_path):
            self._write_pointer(0, "")

    def _write_pointer(self, version: int, snapshot_id: str) -> None:
        pointer = {
            "type": "trusted-release/revocation-pointer/v1",
            "current_version": version,
            "current_snapshot_id": snapshot_id,
        }
        tmp = self.current_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(pointer, f, indent=2, sort_keys=True)
        os.replace(tmp, self.current_path)

    def _snapshot_path(self, version: int) -> str:
        return os.path.join(self.ver_dir, f"{version:06d}.json")

    def current_version_number(self) -> int:
        with open(self.current_path, "r", encoding="utf-8") as f:
            return int(json.load(f)["current_version"])

    def issue(
        self,
        *,
        revoked: dict[str, list[int]],
        reason: str,
        now: str,
        issuer_id: str,
        key_version: int,
        secret_seed: bytes,
    ) -> dict:
        """Publish a new signed CRL snapshot superseding all prior ones.

        revoked maps issuer_id -> list of revoked key versions. Revoking a
        key invalidates every attestation signed by that key, regardless of
        when the historical release was published.
        """
        new_version = self.current_version_number() + 1
        body = {
            "type": self.TYPE,
            "crl_version": new_version,
            "issued_at": now,
            "revoked": {
                issuer: sorted(set(versions))
                for issuer, versions in sorted(revoked.items())
            },
            "reason": reason,
            "issuer_id": issuer_id,
            "key_version": key_version,
        }
        signed = sign_attestation(body, secret_seed)
        snapshot = {
            "snapshot_id": canonical_hash(body),
            "body": body,
            "signature": signed["signature"],
        }
        tmp = self._snapshot_path(new_version) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2, ensure_ascii=False, sort_keys=True)
        os.replace(tmp, self._snapshot_path(new_version))
        self._write_pointer(new_version, snapshot["snapshot_id"])
        return snapshot

    def read_current(self) -> dict | None:
        n = self.current_version_number()
        if n == 0:
            return None
        with open(self._snapshot_path(n), "r", encoding="utf-8") as f:
            return json.load(f)

    def read_version(self, version: int) -> dict:
        with open(self._snapshot_path(version), "r", encoding="utf-8") as f:
            return json.load(f)

    def list_versions(self) -> list[int]:
        out = []
        for name in os.listdir(self.ver_dir):
            if name.endswith(".json"):
                out.append(int(name[:-5]))
        return sorted(out)
