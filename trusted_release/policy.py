"""Versioned, signed release policies.

A release policy declares which roles must approve a release and how many
independent signers each role requires, plus which issuer is assigned to
which role. Policies are stored as immutable, signed, numbered snapshots::

    policies/versions/NNNNNN.json   immutable snapshot
    policies/current.json           pointer to the current snapshot

Every approval pins the policy version it was given under, and a release
record embeds the exact policy snapshot it was finalized against, so a
policy change never retroactively alters the meaning of an old release.
"""

from __future__ import annotations

import json
import os

from .attestation import sign_attestation
from .encoding import canonical_hash

POLICY_TYPE = "trusted-release/release-policy/v1"


def build_policy_body(
    *,
    policy_version: int,
    roles: dict[str, int],
    assignments: dict[str, str],
    issued_at: str,
    issuer_id: str,
    key_version: int,
) -> dict:
    return {
        "type": POLICY_TYPE,
        "policy_version": policy_version,
        "roles": {r: int(n) for r, n in sorted(roles.items())},
        "assignments": dict(sorted(assignments.items())),
        "issued_at": issued_at,
        "issuer_id": issuer_id,
        "key_version": key_version,
    }


class PolicyStore:
    """Directory of signed, versioned, immutable policy snapshots."""

    def __init__(self, root: str):
        self.root = root
        self.ver_dir = os.path.join(root, "versions")
        os.makedirs(self.ver_dir, exist_ok=True)
        self.current_path = os.path.join(root, "current.json")
        if not os.path.exists(self.current_path):
            self._write_pointer(0, "")

    def _write_pointer(self, version: int, snapshot_id: str) -> None:
        pointer = {
            "type": "trusted-release/policy-pointer/v1",
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
        roles: dict[str, int],
        assignments: dict[str, str],
        now: str,
        issuer_id: str,
        key_version: int,
        secret_seed: bytes,
    ) -> dict:
        """Publish a new signed policy snapshot superseding prior ones.

        roles maps role name -> number of independent approvals required.
        assignments maps issuer_id -> role. An issuer may hold one role.
        """
        for role, count in roles.items():
            if int(count) < 1:
                raise ValueError(f"role {role} requires at least 1 approval")
        for issuer, role in assignments.items():
            if role not in roles:
                raise ValueError(
                    f"issuer {issuer} assigned to unknown role {role}"
                )
        new_version = self.current_version_number() + 1
        body = build_policy_body(
            policy_version=new_version,
            roles=roles,
            assignments=assignments,
            issued_at=now,
            issuer_id=issuer_id,
            key_version=key_version,
        )
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
        return self.read_version(n)

    def read_version(self, version: int) -> dict:
        with open(self._snapshot_path(version), "r", encoding="utf-8") as f:
            return json.load(f)

    def list_versions(self) -> list[int]:
        out = []
        for name in os.listdir(self.ver_dir):
            if name.endswith(".json"):
                out.append(int(name[:-5]))
        return sorted(out)

