"""Multi-signer release approvals.

An approval is a signed statement by one issuer that binds, atomically:

* the release candidate id (unique per publish attempt),
* the artifact digest and build-spec digest of that candidate,
* the release policy version the approval was given under.

Because the candidate id and policy version are inside the signed payload,
an approval can never be replayed onto a different candidate - not even one
with identical file contents but different release conditions - and cannot
be counted under a different policy version.
"""

from __future__ import annotations

import base64

from . import ed25519
from .encoding import canonical_hash, canonical_json

APPROVAL_TYPE = "trusted-release/approval/v1"


def build_approval(
    *,
    candidate_id: str,
    product: str,
    version: str,
    artifact_digest: str,
    build_spec_digest: str,
    policy_version: int,
    role: str,
    issuer_id: str,
    key_version: int,
    scope: str,
    issued_at: str,
    not_before: str,
    expires_at: str,
) -> dict:
    return {
        "type": APPROVAL_TYPE,
        "candidate_id": candidate_id,
        "product": product,
        "version": version,
        "artifact_digest": artifact_digest,
        "build_spec_digest": build_spec_digest,
        "policy_version": int(policy_version),
        "role": role,
        "issuer_id": issuer_id,
        "key_version": key_version,
        "scope": scope,
        "issued_at": issued_at,
        "not_before": not_before,
        "expires_at": expires_at,
    }


def sign_approval(approval: dict, secret_seed: bytes) -> dict:
    payload = canonical_json(approval)
    sig = ed25519.sign(secret_seed, payload)
    record = {
        "approval": approval,
        "signature": base64.b64encode(sig).decode("ascii"),
    }
    record["approval_id"] = canonical_hash(record["approval"])
    return record

