"""Offline verification against the *current* trust conditions.

A successful verification proves all three at once:

1. **Content** - the presented artifact hashes to the signed artifact
   digest and the presented build spec hashes to the signed build digest;
2. **Signer** - the signature verifies under a key of the named issuer that
   is currently trusted (status, validity window and current CRL checked);
3. **Scope** - the key scope covers the attested product and the signed
   scope matches the key scope.

Historical release records always remain inspectable, but re-verification
uses the keystore/CRL state configured at verification time: rotated or
revoked keys and expired attestations no longer validate by default.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .attestation import verify_signature
from .encoding import file_digest
from .issuer import IssuerKeyStore


@dataclass(frozen=True)
class TrustPolicy:
    """Trust conditions applied at verification time.

    ``trust_rotated=False`` (default): only currently ``active`` keys may
    validate, so a historical release signed by a since-rotated key fails
    re-verification even though its record stays viewable.
    """

    trust_rotated: bool = False


@dataclass
class VerificationResult:
    ok: bool
    release_id: str
    errors: list[str] = field(default_factory=list)
    checks: dict = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.ok


def scope_covers(key_scope: str, product: str) -> bool:
    if key_scope in ("*", ""):
        return True
    if key_scope.startswith("product:"):
        return key_scope.split(":", 1)[1] == product
    return key_scope == product


def _norm_ts(value: str) -> str:
    return (value or "").replace("+00:00", "Z")


class Verifier:
    def __init__(self, keystore: IssuerKeyStore, crl, policy: TrustPolicy | None = None):
        self.keys = keystore
        self.crl = crl
        self.policy = policy or TrustPolicy()

    def verify_release(
        self,
        release_record: dict,
        *,
        artifact_path: str,
        build_spec_path: str | None = None,
        now: str,
        expected_product: str | None = None,
    ) -> VerificationResult:
        errors: list[str] = []
        checks: dict = {}
        attestation = release_record.get("attestation") or {}
        signature = release_record.get("signature", "")
        release_id = attestation.get(
            "release_id", release_record.get("release_id", "?")
        )

        # ---------- 1. content binding ----------
        actual_artifact_digest = file_digest(artifact_path)
        signed_artifact_digest = attestation.get("artifact_digest", "")
        content_ok = actual_artifact_digest == signed_artifact_digest
        checks["artifact_digest"] = {
            "ok": content_ok,
            "expected": signed_artifact_digest,
            "actual": actual_artifact_digest,
        }
        if not content_ok:
            errors.append(
                "artifact content mismatch: presented file does not match "
                "the signed digest (content substituted)"
            )

        # Defend against attestation/release record mix-and-match.
        record_release_id = release_record.get("release_id")
        if (
            record_release_id is not None
            and attestation.get("release_id") != record_release_id
        ):
            errors.append(
                "attestation mismatch: signed release_id does not belong "
                "to this release record"
            )
        record_digest = release_record.get("artifact_digest")
        if record_digest is not None and record_digest != signed_artifact_digest:
            errors.append(
                "attestation mismatch: release record artifact digest "
                "differs from the signed attestation"
            )
        if (
            release_record.get("build_spec_digest") is not None
            and release_record["build_spec_digest"]
            != attestation.get("build_spec_digest", "")
        ):
            errors.append(
                "attestation mismatch: release record build-spec digest "
                "differs from the signed attestation"
            )

        build_ok = True
        if build_spec_path is not None:
            actual_spec_digest = file_digest(build_spec_path)
            signed_spec_digest = attestation.get("build_spec_digest", "")
            build_ok = actual_spec_digest == signed_spec_digest
            checks["build_spec_digest"] = {
                "ok": build_ok,
                "expected": signed_spec_digest,
                "actual": actual_spec_digest,
            }
            if not build_ok:
                errors.append(
                    "build spec mismatch: presented build spec does not "
                    "match the signed digest"
                )

        if (
            expected_product is not None
            and attestation.get("product") != expected_product
        ):
            errors.append(
                f"product mismatch: expected {expected_product}, "
                f"attested {attestation.get('product')}"
            )

        # ---------- 2. signer trust under CURRENT conditions ----------
        issuer_id = attestation.get("issuer_id")
        key_version_raw = attestation.get("key_version")
        key = None
        try:
            key_version = int(key_version_raw)
            key = self.keys.get_key(issuer_id, key_version)
        except (TypeError, ValueError, KeyError):
            key_version = key_version_raw
            errors.append(
                "signer key not found in current trust store: "
                f"{issuer_id} v{key_version_raw}"
            )

        sig_ok = False
        status_ok = False
        window_ok = True
        scope_ok = False
        crl_ok = True

        if key is not None:
            sig_ok = verify_signature(
                attestation, signature, self.keys.public_key_bytes(
                    issuer_id, key_version
                )
            )
            checks["signature"] = {
                "ok": sig_ok,
                "issuer_id": issuer_id,
                "key_version": key_version,
            }
            if not sig_ok:
                errors.append("signature verification failed")

            if key.status == "active":
                status_ok = True
            elif key.status == "rotated" and self.policy.trust_rotated:
                status_ok = True
            else:
                errors.append(
                    "signing key is not currently trusted "
                    f"(status={key.status})"
                )
            checks["key_status"] = {"ok": status_ok, "status": key.status}

            now_ts = _norm_ts(now)
            if key.valid_from and _norm_ts(key.valid_from) > now_ts:
                window_ok = False
                errors.append("signing key not yet valid (valid_from in future)")
            if key.valid_to and _norm_ts(key.valid_to) <= now_ts:
                window_ok = False
                errors.append("signing key applicability window ended (valid_to)")

            not_before = _norm_ts(attestation.get("not_before", ""))
            expires_at = _norm_ts(attestation.get("expires_at", ""))
            if not_before and now_ts < not_before:
                window_ok = False
                errors.append("attestation not yet valid (not_before)")
            if expires_at and now_ts >= expires_at:
                window_ok = False
                errors.append("attestation expired (now >= expires_at)")
            checks["time_window"] = {"ok": window_ok, "now": now}

            snapshot = self._load_trusted_crl(now, errors)
            revoked = snapshot["body"].get("revoked", {}) if snapshot else {}
            crl_version = (
                snapshot["body"].get("crl_version", 0) if snapshot else 0
            )
            if key_version in revoked.get(issuer_id, []):
                crl_ok = False
                errors.append(
                    f"signing key revoked by current CRL v{crl_version}"
                )
            checks["revocation"] = {"ok": crl_ok, "crl_version": crl_version}

            # ---------- 3. applicability scope ----------
            scope_ok = key.scope == attestation.get("scope") and scope_covers(
                key.scope, attestation.get("product", "")
            )
            checks["scope"] = {
                "ok": scope_ok,
                "key_scope": key.scope,
                "attestation_scope": attestation.get("scope"),
                "product": attestation.get("product"),
            }
            if not scope_ok:
                errors.append(
                    "applicability scope mismatch: key scope does not cover "
                    "the attestation scope/product"
                )

        ok = not errors and all(
            (content_ok, build_ok, sig_ok, status_ok, window_ok, crl_ok, scope_ok)
        )
        return VerificationResult(
            ok=ok, release_id=release_id, errors=errors, checks=checks
        )

    def _load_trusted_crl(self, now: str, errors: list[str]) -> dict | None:
        if self.crl is None:
            return None
        snapshot = self.crl.read_current()
        if snapshot is None:
            return None
        body = snapshot.get("body") or {}
        try:
            crl_key = self.keys.get_key(
                body["issuer_id"], int(body["key_version"])
            )
        except (KeyError, TypeError, ValueError):
            errors.append("CRL signer key missing from current trust store")
            return None

        sig_ok = verify_signature(
            body,
            snapshot.get("signature", ""),
            self.keys.public_key_bytes(body["issuer_id"], body["key_version"]),
        )
        pointer_version = self.crl.current_version_number()
        if not sig_ok or pointer_version != body.get("crl_version"):
            errors.append(
                "current revocation list failed signature/version check"
            )
            return None

        trusted_status = crl_key.status == "active" or (
            crl_key.status == "rotated" and self.policy.trust_rotated
        )
        if not trusted_status:
            errors.append(
                f"CRL signing key not currently trusted (status={crl_key.status})"
            )
            return None

        if crl_key.valid_to and _norm_ts(now) >= _norm_ts(crl_key.valid_to):
            errors.append("CRL signing key applicability window ended")
            return None
        return snapshot


def export_bundle(release_record: dict, path: str) -> None:
    """Write a self-contained signed release bundle for offline transfer."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(release_record, fh, indent=2, sort_keys=True, ensure_ascii=False)


def load_bundle(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
