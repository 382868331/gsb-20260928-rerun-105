"""Publish orchestration with crash-safe ordering.

Ordering::

1. register artifact and bind its build specification (content addressed);
2. sign the attestation with the issuer's *current* active key;
3. append to the release index last, in a single atomic update.

Any failure before step 3 leaves no trusted index entry. A signing
failure (for example an invalid temporary signing seed) aborts the publish
entirely.
"""

from __future__ import annotations

import datetime

from .attestation import build_attestation, sign_attestation
from .encoding import canonical_hash
from .issuer import IssuerKeyStore
from .registry import Registry


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def shift_days(timestamp: str, days: int) -> str:
    dt = datetime.datetime.strptime(
        timestamp, "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=datetime.timezone.utc)
    return (dt + datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


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
        now: str | None = None,
        validity_days: int = 365,
        metadata: dict | None = None,
    ) -> dict:
        now = now or utc_now()

        # 1. register + bind; raises early on missing/tampered input
        manifest = self.registry.register_artifact(
            source_path=artifact_path,
            product=product,
            version=version,
            build_spec_path=build_spec_path,
            now=now,
            metadata=metadata,
        )

        # 2. sign with the current active key of the named issuer
        key_version = self.keystore.latest_version(issuer_id)
        if key_version is None:
            raise LookupError(f"issuer {issuer_id!r} has no signing key")
        key = self.keystore.get_key(issuer_id, key_version)
        if key.status != "active":
            raise RuntimeError(
                f"current key v{key_version} of issuer {issuer_id!r} is "
                f"{key.status}, not active"
            )
        seed = self.keystore.load_secret(issuer_id, key_version)

        artifact_hex = manifest["artifact_digest"].split(":", 1)[1]
        release_id = f"{product}-{version}-{artifact_hex[:12]}"
        expires_at = shift_days(now, validity_days)
        attestation = build_attestation(
            release_id=release_id,
            product=product,
            version=version,
            scope=key.scope,
            artifact_digest=manifest["artifact_digest"],
            build_spec_digest=manifest["build_spec_digest"],
            issuer_id=issuer_id,
            key_version=key_version,
            issued_at=now,
            not_before=now,
            expires_at=expires_at,
        )
        signed = sign_attestation(attestation, seed)  # raises on bad seed

        record = {
            "type": "trusted-release/release/v1",
            "release_id": release_id,
            "product": product,
            "version": version,
            "artifact_digest": manifest["artifact_digest"],
            "build_spec_digest": manifest["build_spec_digest"],
            "issuer_id": issuer_id,
            "key_version": key_version,
            "issued_at": now,
            "expires_at": expires_at,
            "attestation": signed["attestation"],
            "signature": signed["signature"],
            "attestation_id": signed["attestation_id"],
        }
        record["record_id"] = canonical_hash(
            {k: v for k, v in record.items() if k != "record_id"}
        )

        # 3. index LAST, atomically: nothing trusted exists before this
        self.registry.index_release(record)
        return record
