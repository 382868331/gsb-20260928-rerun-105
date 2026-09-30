"""High-level publish orchestration.

Order of operations guarantees that a failed/interrupted publish never
leaves anything that could be treated as a trusted release in the index:

1. artifact + build spec are registered (content-addressed);
2. the attestation is built and signed; only then
3. is the release appended to the index (last, atomic step).
"""

from __future__ import annotations

import datetime

from .attestation import build_attestation, sign_attestation
from .encoding import canonical_hash
from .issuer import IssuerKeyStore
from .registry import Registry


def utc_now(offset_days: int = 0) -> str:
    base = datetime.datetime.now(datetime.timezone.utc)
    return (base + datetime.timedelta(days=offset_days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


class Publisher:
    def __init__(self, registry: Registry, keystore: IssuerKeyStore):
        self.registry = registry
        self.keystore = keystore

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
        # 1. register + bind (fails on unreadable/tampered input)
        manifest = self.registry.register_artifact(
            source_path=artifact_path,
            product=product,
            version=version,
            build_spec_path=build_spec_path,
            now=now,
            metadata=metadata,
        )

        # 2. sign with the issuer's CURRENT key
        kv = self.keystore.latest_version(issuer_id)
        if kv is None:
            raise LookupError(f"issuer {issuer_id} has no keys")
        key = self.keystore.get_key(issuer_id, kv)
        if key.status != "active":
            raise RuntimeError(
                f"current key v{kv} of {issuer_id} is not active"
            )
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
            {k: record[k] for k in record if k not in ("record_id",)}
        )

        # 3. index LAST (atomic) - nothing trusted exists before this point
        self.registry.index_release(record)
        return record

    @staticmethod
    def _shift(ts: str, days: int) -> str:
        dt = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc
        )
        return (dt + datetime.timedelta(days=days)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
