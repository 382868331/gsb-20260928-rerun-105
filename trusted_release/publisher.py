"""High-level publish orchestration."""

from __future__ import annotations

import datetime
import os

from .attestation import build_approval, build_attestation, sign_attestation
from .encoding import canonical_hash
from .issuer import IssuerKeyStore
from .policy import CANDIDATE_TYPE, ReleasePolicy
from .registry import Registry


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

    # ---------- release collections ----------
    def create_collection_candidate(
        self,
        *,
        name: str,
        version: str,
        members: list[dict],
        policy: "dict | ReleasePolicy",
        now: str,
    ) -> dict:
        """Register member artifacts and build a collection candidate.

        Each member is a dict with product/version and either
        artifact_path + build_spec_path (registered into the content
        store) or pre-computed artifact_digest + build_spec_digest, plus
        an optional depends_on list of {product, version} pins.
        """
        from . import collection as coll

        policy_obj = (
            policy if isinstance(policy, ReleasePolicy)
            else ReleasePolicy.from_dict(policy)
        )
        resolved = []
        for m in members:
            entry = {
                "product": m["product"],
                "version": m["version"],
                "depends_on": m.get("depends_on", []),
            }
            if "artifact_path" in m:
                manifest = self.registry.register_artifact(
                    source_path=m["artifact_path"],
                    product=m["product"],
                    version=m["version"],
                    build_spec_path=m["build_spec_path"],
                    now=now,
                )
                entry["artifact_digest"] = manifest["artifact_digest"]
                entry["build_spec_digest"] = manifest["build_spec_digest"]
            else:
                entry["artifact_digest"] = m["artifact_digest"]
                entry["build_spec_digest"] = m["build_spec_digest"]
            resolved.append(entry)
        spec = coll.build_spec(name=name, version=version, members=resolved)
        return coll.build_candidate(spec=spec, policy=policy_obj, now=now)

    def approve_collection(
        self,
        candidate: dict,
        *,
        issuer_id: str,
        now: str,
        validity_days: int = 365,
    ) -> dict:
        from . import collection as coll

        kv = self.keystore.latest_version(issuer_id)
        if kv is None:
            raise LookupError(f"issuer {issuer_id} has no keys")
        key = self.keystore.get_key(issuer_id, kv)
        if key.status != "active":
            raise RuntimeError(f"current key v{kv} of {issuer_id} is not active")
        approval = coll.build_approval(
            candidate=candidate,
            issuer_id=issuer_id,
            key_version=kv,
            role=key.role,
            scope=key.scope,
            issued_at=now,
            not_before=now,
            expires_at=self._shift(now, validity_days),
        )
        return coll.sign_approval(approval, self.keystore.load_secret(issuer_id, kv))

    def finalize_collection(
        self, candidate: dict, approvals: list[dict], *, now: str
    ) -> dict:
        """Publish a collection once its policy quorum is currently met.

        Approvals are re-interpreted against the *current* trust store and
        CRL at finalize time: keys rotated or revoked while approvals were
        being collected no longer count. Only after the whole collection
        verifies is it indexed (atomically, record file first); a failed
        or interrupted finalize exposes nothing.
        """
        from . import collection as coll
        from .verifier import Verifier

        if self.crl is None:
            raise ValueError("a revocation list is required for collection publishing")
        policy = ReleasePolicy.from_dict(candidate["policy"])
        if candidate.get("policy_digest") != policy.digest:
            raise ValueError("candidate policy digest mismatch")
        record = {
            "type": coll.RELEASE_TYPE,
            "collection_release_id": candidate["collection_release_id"],
            "candidate": candidate,
            "candidate_id": candidate["candidate_id"],
            "candidate_digest": candidate["candidate_digest"],
            "name": candidate["name"],
            "version": candidate["version"],
            "spec": candidate["spec"],
            "spec_digest": candidate["spec_digest"],
            "policy": policy.to_dict(),
            "policy_digest": policy.digest,
            "approvals": list(approvals),
            "released_at": now,
        }
        current = self.crl.read_current()
        if current is not None:
            record["crl_version_at_release"] = current["body"]["crl_version"]

        def resolve(digest: str):
            path = self.registry.artifact_path(digest)
            return path if self.registry.has_artifact(digest) else None

        result = Verifier(self.keystore, self.crl).verify_collection(
            record, resolve_content=resolve, now=now, as_of="release",
            expected_name=candidate["name"],
        )
        if not result.ok:
            raise ValueError(
                "collection does not satisfy release policy: "
                + "; ".join(result.errors)
            )
        record["record_id"] = canonical_hash(
            {k: record[k] for k in record if k != "record_id"}
        )
        self.registry.index_collection(record)
        return record
