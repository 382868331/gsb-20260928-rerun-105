"""Release collections: interdependent artifacts approved as one unit.

A *collection* pins an explicit set of artifact versions plus the
dependency edges between them. The collection spec (members + dependency
declarations) is hashed into spec_digest; the candidate digest covers
spec + policy + nonce. Approvals bind the candidate digest, so replacing
any member artifact, build spec, or dependency declaration produces a new
candidate and every previously collected approval stops applying.

Dependency edges may be shared (several members depending on the same
member) and may be cyclic (A depends on B and B depends on A); both are
validated structurally, not rejected.
"""

from __future__ import annotations

import os

from .attestation import sign_attestation
from .encoding import canonical_hash
from .policy import ReleasePolicy

SPEC_TYPE = "trusted-release/collection-spec/v1"
CANDIDATE_TYPE = "trusted-release/collection-candidate/v1"
APPROVAL_TYPE = "trusted-release/collection-approval/v1"
RELEASE_TYPE = "trusted-release/collection/v1"


def normalize_dependency(dep: dict) -> dict:
    return {"product": str(dep["product"]), "version": str(dep["version"])}


def normalize_member(member: dict) -> dict:
    return {
        "product": str(member["product"]),
        "version": str(member["version"]),
        "artifact_digest": str(member["artifact_digest"]),
        "build_spec_digest": str(member["build_spec_digest"]),
        "depends_on": sorted(
            (normalize_dependency(d) for d in member.get("depends_on", [])),
            key=lambda d: (d["product"], d["version"]),
        ),
    }


def build_spec(*, name: str, version: str, members: list[dict]) -> dict:
    return {
        "type": SPEC_TYPE,
        "name": str(name),
        "version": str(version),
        "members": sorted(
            (normalize_member(m) for m in members),
            key=lambda m: (m["product"], m["version"]),
        ),
    }


def validate_spec(spec: dict) -> list[str]:
    """Structural validation; returns a list of problems (empty if sound).

    Every declared dependency must resolve to a member of the same
    collection. Cycles are legal and are *not* reported as problems.
    """
    errors: list[str] = []
    if spec.get("type") != SPEC_TYPE:
        errors.append(f"unexpected spec type: {spec.get('type')!r}")
    seen: set[tuple[str, str]] = set()
    members = spec.get("members", [])
    if not members:
        errors.append("collection has no members")
    for m in members:
        key = (m.get("product"), m.get("version"))
        if key in seen:
            errors.append(f"duplicate member {key[0]} {key[1]}")
        seen.add(key)
        for field in ("artifact_digest", "build_spec_digest"):
            if not m.get(field):
                errors.append(f"member {key[0]} {key[1]} missing {field}")
    for m in members:
        for dep in m.get("depends_on", []):
            target = (dep.get("product"), dep.get("version"))
            if target not in seen:
                errors.append(
                    f"member {m.get('product')} {m.get('version')} depends on "
                    f"{target[0]} {target[1]} which is not in the collection"
                )
    return errors


def find_cycles(spec: dict) -> list[list[str]]:
    """Return dependency cycles (informational; cycles are permitted)."""
    graph = {
        (m["product"], m["version"]): [
            (d["product"], d["version"]) for d in m.get("depends_on", [])
        ]
        for m in spec.get("members", [])
    }
    cycles: list[list[str]] = []
    stack: list[tuple[str, str]] = []
    state: dict[tuple[str, str], int] = {}

    def visit(node) -> None:
        state[node] = 1
        stack.append(node)
        for nxt in graph.get(node, []):
            if state.get(nxt) == 1:
                idx = stack.index(nxt)
                cycle = [f"{p}:{v}" for p, v in stack[idx:]] + [f"{nxt[0]}:{nxt[1]}"]
                if cycle not in cycles:
                    cycles.append(cycle)
            elif state.get(nxt) is None:
                visit(nxt)
        stack.pop()
        state[node] = 2

    for node in graph:
        if state.get(node) is None:
            visit(node)
    return cycles


def spec_digest(spec: dict) -> str:
    return canonical_hash(build_spec(
        name=spec["name"], version=spec["version"], members=spec["members"]
    ))


def build_candidate(
    *,
    spec: dict,
    policy: ReleasePolicy,
    now: str,
    nonce: str | None = None,
) -> dict:
    errors = validate_spec(spec)
    if errors:
        raise ValueError("invalid collection spec: " + "; ".join(errors))
    spec = build_spec(name=spec["name"], version=spec["version"],
                      members=spec["members"])
    policy_data = policy.to_dict()
    nonce = nonce or os.urandom(16).hex()
    candidate_digest = canonical_hash(
        {"spec": spec, "policy": policy_data, "nonce": nonce}
    )
    short = candidate_digest.split(":", 1)[1]
    return {
        "type": CANDIDATE_TYPE,
        "candidate_id": short[:24],
        "candidate_digest": candidate_digest,
        "nonce": nonce,
        "collection_release_id": f"{spec['name']}-{spec['version']}-{short[:12]}",
        "name": spec["name"],
        "version": spec["version"],
        "spec": spec,
        "spec_digest": spec_digest(spec),
        "policy": policy_data,
        "policy_digest": policy.digest,
        "created_at": now,
    }


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
    """An approval of the *whole* collection candidate.

    The signed payload binds the candidate digest (hence every member
    digest and every dependency declaration) plus the full policy version,
    so approvals can never be replayed against a modified collection.
    """
    return {
        "type": APPROVAL_TYPE,
        "candidate_id": candidate["candidate_id"],
        "candidate_digest": candidate["candidate_digest"],
        "collection_release_id": candidate["collection_release_id"],
        "name": candidate["name"],
        "version": candidate["version"],
        "spec_digest": candidate["spec_digest"],
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


def sign_approval(approval: dict, secret_seed: bytes) -> dict:
    signed = sign_attestation(approval, secret_seed)
    return {
        "approval": signed["attestation"],
        "signature": signed["signature"],
        "approval_id": signed["attestation_id"],
    }

