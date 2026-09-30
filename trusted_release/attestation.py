"""Attestation construction/signing and versioned revocation lists.

An attestation is a signed statement binding, all in one payload:

* the artifact content digest and the build-specification digest;
* the signer identity (``issuer_id`` + ``key_version``);
* the applicability range (``scope``/``product``/``version``);
* the validity window (``not_before``/``expires_at``).

Because the digest, signer and scope live *inside* the signed payload, a
signature for another file can never validate the current file.
"""

from __future__ import annotations

import base64
import json
import os

from . import ed25519
from .encoding import canonical_hash, canonical_json

ATTESTATION_TYPE = "trusted-release/attestation/v1"
CRL_TYPE = "trusted-release/revocation-list/v1"
POINTER_TYPE = "trusted-release/revocation-pointer/v1"


def build_attestation(
    *,
    release_id: str,
    product: str,
    version: str,
    scope: str,
    artifact_digest: str,
    build_spec_digest: str,
    issuer_id: str,
    key_version: int,
    issued_at: str,
    not_before: str,
    expires_at: str,
) -> dict:
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
    signature = ed25519.sign(secret_seed, canonical_json(attestation))
    return {
        "attestation": attestation,
        "signature": base64.b64encode(signature).decode("ascii"),
        "attestation_id": canonical_hash(attestation),
    }


def verify_signature(attestation: dict, signature_b64: str, public_key: bytes) -> bool:
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, TypeError):
        return False
    return ed25519.verify(public_key, canonical_json(attestation), signature)


class RevocationList:
    """Signed, append-only, versioned revocation material.

    Layout::

        <root>/versions/000001.json   immutable signed snapshots
        <root>/current.json           pointer to the current snapshot

    Every snapshot supersedes previous ones and records the complete set of
    revoked (issuer, key version) pairs at that point. Old snapshots remain
    available for historical inspection; verification always consults the
    *current* snapshot. A snapshot is only trusted when its embedded
    signature and the current-version pointer both check out.
    """

    def __init__(self, root: str):
        self.root = root
        self.versions_dir = os.path.join(root, "versions")
        # Backwards-compatible alias used by tooling/tests.
        self.ver_dir = self.versions_dir
        os.makedirs(self.versions_dir, exist_ok=True)
        self.current_path = os.path.join(root, "current.json")
        if not os.path.exists(self.current_path):
            self._write_pointer(0, "")

    def _snapshot_path(self, version: int) -> str:
        return os.path.join(self.versions_dir, f"{version:06d}.json")

    def _write_pointer(self, version: int, snapshot_id: str) -> None:
        pointer = {
            "type": POINTER_TYPE,
            "current_version": version,
            "current_snapshot_id": snapshot_id,
        }
        tmp = self.current_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(pointer, fh, indent=2, sort_keys=True)
        os.replace(tmp, self.current_path)

    def current_version_number(self) -> int:
        with open(self.current_path, "r", encoding="utf-8") as fh:
            return int(json.load(fh)["current_version"])

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
        """Publish a new signed snapshot replacing all earlier snapshots."""
        new_version = self.current_version_number() + 1
        body = {
            "type": CRL_TYPE,
            "crl_version": new_version,
            "issued_at": now,
            "reason": reason,
            "issuer_id": issuer_id,
            "key_version": key_version,
            "revoked": {
                issuer: sorted(set(versions))
                for issuer, versions in sorted(revoked.items())
            },
        }
        signed = sign_attestation(body, secret_seed)
        snapshot = {
            "snapshot_id": canonical_hash(body),
            "body": body,
            "signature": signed["signature"],
        }
        path = self._snapshot_path(new_version)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(snapshot, fh, indent=2, sort_keys=True, ensure_ascii=False)
        os.replace(tmp, path)
        self._write_pointer(new_version, snapshot["snapshot_id"])
        return snapshot

    def read_version(self, version: int) -> dict:
        with open(self._snapshot_path(version), "r", encoding="utf-8") as fh:
            return json.load(fh)

    def read_current(self) -> dict | None:
        version = self.current_version_number()
        if version == 0:
            return None
        return self.read_version(version)

    def list_versions(self) -> list[int]:
        out = []
        for name in os.listdir(self.versions_dir):
            if name.endswith(".json"):
                out.append(int(name[:-5]))
        return sorted(out)
