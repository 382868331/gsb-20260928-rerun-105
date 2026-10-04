"""High-level publish orchestration."""

from __future__ import annotations

import datetime
import os

from .attestation import (
    build_approval,
    build_attestation,
    build_set_approval,
    sign_attestation,
)
from .encoding import canonical_hash
from .issuer import IssuerKeyStore
from .policy import CANDIDATE_TYPE, SET_CANDIDATE_TYPE, SET_RELEASE_TYPE, ReleasePolicy
from .registry import Registry


def compute_set_digest(name: str, set_version: str, members: list[dict],
                       policy_data: dict, nonce: str) -> str:
    """Digest committing to every member digest and dependency declaration."""
    return canonical_hash(
        {
            "name": name,
            "set_version": set_version,
            "members": [
                {
                    "product": m["product"],
                    "version": m["version"],
                    "artifact_digest": m["artifact_digest"],
                    "build_spec_digest": m["build_spec_digest"],
                    "depends_on": sorted(m.get("depends_on", [])),
                }
                for m in members
            ],
            "policy": policy_data,
            "nonce": nonce,
        }
    )


def check_dependencies(members: list[dict]) -> tuple[list[str], list[list[str]]]:
    """Validate the dependency graph of a set.

    Returns (errors, cycles). Every declared dependency must resolve to a
    member of the same set (a set must be self-contained). Cycles are
    allowed and reported: dependencies declare co-usability, not build
    order.
    """
    errors: list[str] = []
    products = [m["product"] for m in members]
    if len(products) != len(set(products)):
        errors.append("duplicate product in set members")
    known = set(products)
    for m in members:
        for dep in m.get("depends_on", []):
            if dep not in known:
                errors.append(
                    f"member {m['product']} depends on {dep}, "
                    "which is not part of the set"
                )
    cycles: list[list[str]] = []
    graph = {m["product"]: sorted(m.get("depends_on", [])) for m in members}
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {p: WHITE for p in graph}
    stack: list[str] = []

    def visit(node: str) -> None:
        color[node] = GRAY
        stack.append(node)
        for nxt in graph.get(node, []):
            if nxt not in color:
                continue
            if color[nxt] == GRAY:
                cycle = stack[stack.index(nxt):] + [nxt]
                if cycle not in cycles:
                    cycles.append(cycle)
            elif color[nxt] == WHITE:
                visit(nxt)
        stack.pop()
        color[node] = BLACK

    for p in sorted(graph):
        if color[p] == WHITE:
            visit(p)
    return errors, cycles


def utc_now(offset_days: int = 0) -> str:
    base = datetime.datetime.now(datetime.timezone.utc)
    return (base + datetime.timedelta(days=offset_days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


class Publisher:
    def __init__(self, registry: Registry, keystore: IssuerKeyStore, crl=None):
        self.registry = registry
        self.keystore = keystore
        self.crl = crl

    def publish(
        self,
        *,
        artifact_path: str,
        build_spec_path: str,
        product: str,
        version: str,
        issuer_id: str,
        now: str,
        validity_days: int = 365,
        metadata: dict | None = None,
    ) -> dict:
        manifest = self.registry.register_artifact(
            source_path=artifact_path,
            product=product,
            version=version,
            build_spec_path=build_spec_path,
            now=now,
            metadata=metadata,
        )

        kv = self.keystore.latest_version(issuer_id)
        if kv is None:
            raise LookupError(f"issuer {issuer_id} has no keys")
        key = self.keystore.get_key(issuer_id, kv)
        if key.status != "active":
            raise RuntimeError(f"current key v{kv} of {issuer_id} is not active")
        seed = self.keystore.load_secret(issuer_id, kv)

        expires = self._shift(now, validity_days)
        release_id = (
            f"{product}-{version}-{manifest['artifact_digest'].split(':',1)[1][:12]}"
        )
        att = build_attestation(
            release_id=release_id,
            product=product,
            version=version,
            artifact_digest=manifest["artifact_digest"],
            build_spec_digest=manifest["build_spec_digest"],
            issuer_id=issuer_id,
            key_version=kv,
            scope=key.scope,
            issued_at=now,
            expires_at=expires,
            not_before=now,
        )
        signed = sign_attestation(att, seed)
        record = {
            "release_id": release_id,
            "type": "trusted-release/release/v1",
            "product": product,
            "version": version,
            "artifact_digest": manifest["artifact_digest"],
            "build_spec_digest": manifest["build_spec_digest"],
            "issuer_id": issuer_id,
            "key_version": kv,
            "issued_at": now,
            "expires_at": expires,
            "attestation": signed["attestation"],
            "signature": signed["signature"],
            "attestation_id": signed["attestation_id"],
        }
        record["record_id"] = canonical_hash(
            {k: record[k] for k in record if k != "record_id"}
        )
        self.registry.index_release(record)
        return record

    def create_candidate(
        self,
        *,
        artifact_path: str,
        build_spec_path: str,
        product: str,
        version: str,
        policy: dict | ReleasePolicy,
        now: str,
        metadata: dict | None = None,
    ) -> dict:
        policy_obj = policy if isinstance(policy, ReleasePolicy) else ReleasePolicy.from_dict(policy)
        policy_data = policy_obj.to_dict()
        manifest = self.registry.register_artifact(
            source_path=artifact_path,
            product=product,
            version=version,
            build_spec_path=build_spec_path,
            now=now,
            metadata=metadata,
        )
        nonce = os.urandom(16).hex()
        candidate_digest = canonical_hash(
            {
                "artifact_digest": manifest["artifact_digest"],
                "build_spec_digest": manifest["build_spec_digest"],
                "policy": policy_data,
                "product": product,
                "version": version,
                "nonce": nonce,
            }
        )
        return {
            "type": CANDIDATE_TYPE,
            "candidate_id": candidate_digest.split(":", 1)[1][:24],
            "candidate_digest": candidate_digest,
            "nonce": nonce,
            "release_id": f"{product}-{version}-{candidate_digest.split(':',1)[1][:12]}",
            "product": product,
            "version": version,
            "artifact_digest": manifest["artifact_digest"],
            "build_spec_digest": manifest["build_spec_digest"],
            "policy": policy_data,
            "policy_digest": canonical_hash(policy_data),
            "created_at": now,
        }

    def approve_candidate(
        self,
        candidate: dict,
        *,
        issuer_id: str,
        now: str,
        validity_days: int = 365,
    ) -> dict:
        kv = self.keystore.latest_version(issuer_id)
        if kv is None:
            raise LookupError(f"issuer {issuer_id} has no keys")
        key = self.keystore.get_key(issuer_id, kv)
        if key.status != "active":
            raise RuntimeError(f"current key v{kv} of {issuer_id} is not active")
        approval = build_approval(
            candidate=candidate,
            issuer_id=issuer_id,
            key_version=kv,
            role=key.role,
            scope=key.scope,
            issued_at=now,
            not_before=now,
            expires_at=self._shift(now, validity_days),
        )
        signed = sign_attestation(approval, self.keystore.load_secret(issuer_id, kv))
        return {
            "approval": signed["attestation"],
            "signature": signed["signature"],
            "approval_id": signed["attestation_id"],
        }

    def publish_candidate(self, candidate: dict, approvals: list[dict], *, now: str) -> dict:
        from .verifier import Verifier

        if self.crl is None:
            raise ValueError("a revocation list is required for policy-gated publishing")
        policy = ReleasePolicy.from_dict(candidate["policy"])
        if candidate.get("policy_digest") != policy.digest:
            raise ValueError("candidate policy digest mismatch")
        record = {
            "release_id": candidate["release_id"],
            "type": "trusted-release/release/v2",
            "candidate": candidate,
            "candidate_id": candidate["candidate_id"],
            "candidate_digest": candidate["candidate_digest"],
            "product": candidate["product"],
            "version": candidate["version"],
            "artifact_digest": candidate["artifact_digest"],
            "build_spec_digest": candidate["build_spec_digest"],
            "policy": policy.to_dict(),
            "policy_digest": policy.digest,
            "approvals": list(approvals),
            "released_at": now,
        }
        current = self.crl.read_current()
        if current is not None:
            record["crl_version_at_release"] = current["body"]["crl_version"]
        result = Verifier(self.keystore, self.crl).verify_release(
            record,
            artifact_path=self.registry.artifact_path(candidate["artifact_digest"]),
            build_spec_path=self.registry.artifact_path(candidate["build_spec_digest"]),
            now=now,
            as_of="release",
            expected_product=candidate["product"],
        )
        if not result.ok:
            raise ValueError(
                "candidate does not satisfy release policy: " + "; ".join(result.errors)
            )
        record["record_id"] = canonical_hash(
            {k: record[k] for k in record if k != "record_id"}
        )
        self.registry.index_release(record)
        return record

    @staticmethod
    def _shift(ts: str, days: int) -> str:
        dt = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc
        )
        return (dt + datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # ---------- release sets ----------
    def create_set_candidate(
        self,
        *,
        name: str,
        set_version: str,
        members: list[dict],
        policy: dict | ReleasePolicy,
        now: str,
    ) -> dict:
        """Register all member artifacts and build a set candidate.

        members: list of {product, version, artifact_path, build_spec_path,
        depends_on}. The candidate digest commits to every member digest
        and every dependency declaration, so replacing one artifact or one
        dependency edge yields a different set that old approvals cannot
        cover.
        """
        policy_obj = policy if isinstance(policy, ReleasePolicy) else ReleasePolicy.from_dict(policy)
        policy_data = policy_obj.to_dict()
        member_entries = []
        for m in members:
            manifest = self.registry.register_artifact(
                source_path=m["artifact_path"],
                product=m["product"],
                version=m["version"],
                build_spec_path=m["build_spec_path"],
                now=now,
            )
            member_entries.append(
                {
                    "product": m["product"],
                    "version": m["version"],
                    "artifact_digest": manifest["artifact_digest"],
                    "build_spec_digest": manifest["build_spec_digest"],
                    "depends_on": sorted(m.get("depends_on", [])),
                }
            )
        member_entries.sort(key=lambda e: e["product"])
        dep_errors, cycles = check_dependencies(member_entries)
        if dep_errors:
            raise ValueError("invalid release set: " + "; ".join(dep_errors))
        nonce = os.urandom(16).hex()
        set_digest = compute_set_digest(name, set_version, member_entries, policy_data, nonce)
        return {
            "type": SET_CANDIDATE_TYPE,
            "set_id": f"{name}-{set_version}-{set_digest.split(':', 1)[1][:12]}",
            "set_digest": set_digest,
            "nonce": nonce,
            "name": name,
            "set_version": set_version,
            "members": member_entries,
            "dependency_cycles": cycles,
            "policy": policy_data,
            "policy_digest": canonical_hash(policy_data),
            "created_at": now,
        }

    def approve_set_candidate(
        self,
        candidate: dict,
        *,
        issuer_id: str,
        now: str,
        validity_days: int = 365,
    ) -> dict:
        kv = self.keystore.latest_version(issuer_id)
        if kv is None:
            raise LookupError(f"issuer {issuer_id} has no keys")
        key = self.keystore.get_key(issuer_id, kv)
        if key.status != "active":
            raise RuntimeError(f"current key v{kv} of {issuer_id} is not active")
        approval = build_set_approval(
            candidate=candidate,
            issuer_id=issuer_id,
            key_version=kv,
            role=key.role,
            scope=key.scope,
            issued_at=now,
            not_before=now,
            expires_at=self._shift(now, validity_days),
        )
        signed = sign_attestation(approval, self.keystore.load_secret(issuer_id, kv))
        return {
            "approval": signed["attestation"],
            "signature": signed["signature"],
            "approval_id": signed["attestation_id"],
        }

    def publish_set_candidate(self, candidate: dict, approvals: list[dict], *, now: str) -> dict:
        """Finalize a set: verify quorum, then index the whole set atomically.

        Approvals are evaluated under the *current* trust conditions, so a
        policy change or a revocation that happened while approvals were
        being collected is fully re-interpreted here. Nothing is written to
        the trusted index unless the complete set passes.
        """
        from .verifier import Verifier

        if self.crl is None:
            raise ValueError("a revocation list is required for policy-gated set publishing")
        policy = ReleasePolicy.from_dict(candidate["policy"])
        if candidate.get("policy_digest") != policy.digest:
            raise ValueError("set candidate policy digest mismatch")
        record = {
            "type": SET_RELEASE_TYPE,
            "set_id": candidate["set_id"],
            "set_digest": candidate["set_digest"],
            "candidate": candidate,
            "name": candidate["name"],
            "set_version": candidate["set_version"],
            "members": candidate["members"],
            "policy": policy.to_dict(),
            "policy_digest": policy.digest,
            "approvals": list(approvals),
            "released_at": now,
        }
        current = self.crl.read_current()
        if current is not None:
            record["crl_version_at_release"] = current["body"]["crl_version"]
        member_files = {
            m["product"]: (
                self.registry.artifact_path(m["artifact_digest"]),
                self.registry.artifact_path(m["build_spec_digest"]),
            )
            for m in candidate["members"]
        }
        result = Verifier(self.keystore, self.crl).verify_set_release(
            record, member_files=member_files, now=now, as_of="release",
        )
        if not result.ok:
            raise ValueError(
                "set candidate does not satisfy release policy: " + "; ".join(result.errors)
            )
        record["record_id"] = canonical_hash(
            {k: record[k] for k in record if k != "record_id"}
        )
        self.registry.index_set_release(record)
        return record
