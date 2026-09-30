"""Offline verification against *current* trust conditions.

A successful verification simultaneously proves:

1. Content  - the bytes presented hash to the signed artifact digest, and
              the presented build spec hashes to the signed build digest;
2. Signer   - the signature verifies under a currently trusted key of the
              named issuer (status, key window, CRL all checked);
3. Scope    - the key's declared scope covers the attested product and the
              attestation's scope matches the key scope.

Historical releases can always be inspected, but re-verification is judged
with the *current* keys and the *current* revocation list: rotated/revoked
keys and expired attestations no longer validate.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .attestation import verify_signature
from .encoding import file_digest
from .issuer import IssuerKeyStore


@dataclass
class TrustPolicy:
    # When False (default), only keys currently "active" may validate.
    # Rotated keys remain in history but fail re-verification.
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
    if key_scope == "*" or key_scope == "":
        return True
    if key_scope.startswith("product:"):
        return key_scope.split(":", 1)[1] == product
    return key_scope == product


class Verifier:
    def __init__(
        self,
        keystore: IssuerKeyStore,
        crl,
        policy: TrustPolicy | None = None,
    ):
        self.keys = keystore
        self.crl = crl
        self.policy = policy or TrustPolicy()

    def _parse_ts(self, s: str) -> str:
        # ISO timestamps sort lexicographically; keep as normalized string.
        return s.replace("+00:00", "Z")

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
        att = release_record.get("attestation", {})
        signature = release_record.get("signature", "")
        rid = att.get("release_id", release_record.get("release_id", "?"))

        # ---------- 1. content binding ----------
        actual_artifact_digest = file_digest(artifact_path)
        signed_artifact_digest = att.get("artifact_digest", "")
        content_ok = actual_artifact_digest == signed_artifact_digest
        checks["artifact_digest"] = {
            "expected": signed_artifact_digest,
            "actual": actual_artifact_digest,
            "ok": content_ok,
        }
        if not content_ok:
            errors.append(
                "artifact content mismatch: presented file does not match "
                "signed digest (content substituted)"
            )

        # The attestation must actually be the one embedded in the release
        # record (defends against attestation/release mix-and-match).
        record_rid = release_record.get("release_id")
        if record_rid is not None and att.get("release_id") != record_rid:
            errors.append(
                "attestation mismatch: attestation release_id does not "
                "belong to this release record"
            )
        if (
            release_record.get("artifact_digest") is not None
            and release_record.get("artifact_digest") != signed_artifact_digest
        ):
            errors.append(
                "attestation mismatch: release record artifact digest "
                "differs from attestation"
            )

        build_ok = True
        if build_spec_path is not None:
            actual_spec_digest = file_digest(build_spec_path)
            signed_spec_digest = att.get("build_spec_digest", "")
            build_ok = actual_spec_digest == signed_spec_digest
            checks["build_spec_digest"] = {
                "expected": signed_spec_digest,
                "actual": actual_spec_digest,
                "ok": build_ok,
            }
            if not build_ok:
                errors.append(
                    "build spec mismatch: presented build spec does not match "
                    "signed digest"
                )

        if expected_product is not None and att.get("product") != expected_product:
            errors.append(
                f"product mismatch: expected {expected_product}, "
                f"attested {att.get('product')}"
            )

        # ---------- 2. current signer trust ----------
        issuer_id = att.get("issuer_id")
        key_version = att.get("key_version")
        key = None
        try:
            key = self.keys.get_key(issuer_id, int(key_version))
        except Exception as exc:
            errors.append(f"signer key not found in current trust store: {exc}")

        sig_ok = False
        status_ok = False
        window_ok = True
        crl_ok = True
        if key is not None:
            import base64

            sig_ok = verify_signature(
                att, signature, base64.b64decode(key.public_key)
            )
            checks["signature"] = {"ok": sig_ok, "signer": issuer_id,
                                   "key_version": key_version}
            if not sig_ok:
                errors.append("signature verification failed")

            # Current status: rotated/revoked keys fail unless policy opts in.
            if key.status == "active":
                status_ok = True
            elif key.status == "rotated" and self.policy.trust_rotated:
                status_ok = True
            else:
                errors.append(
                    f"signing key is not currently trusted "
                    f"(status={key.status})"
                )
            checks["key_status"] = {"ok": status_ok, "status": key.status}

            n = self._parse_ts(now)
            if key.valid_from and self._parse_ts(key.valid_from) > n:
                window_ok = False
                errors.append("key not yet valid (valid_from in the future)")
            if key.valid_to and self._parse_ts(key.valid_to) <= n:
                window_ok = False
                errors.append("key applicability window has ended (valid_to)")

            not_before = self._parse_ts(att.get("not_before", ""))
            expires = self._parse_ts(att.get("expires_at", ""))
            if not_before and n < not_before:
                window_ok = False
                errors.append("attestation not yet valid (not_before)")
            if expires and n >= expires:
                window_ok = False
                errors.append("attestation expired (now >= expires_at)")
            checks["time_window"] = {"ok": window_ok, "now": now}

            # ---------- current revocation material ----------
            # The CRL is itself signed; an unsigned/tampered/expired-authority
            # CRL must not be trusted (fail closed).
            snapshot = self._load_trusted_crl(now, errors)
            revoked = {}
            crl_version = 0
            if snapshot is not None:
                revoked = snapshot["body"].get("revoked", {})
                crl_version = snapshot["body"]["crl_version"]
            if int(key_version) in revoked.get(issuer_id, []):
                crl_ok = False
                errors.append(
                    f"signing key revoked by current CRL v{crl_version}"
                )
            checks["revocation"] = {"ok": crl_ok,
                                    "crl_version": crl_version}

        # ---------- 3. applicability scope ----------
        scope_ok = False
        if key is not None:
            scope_ok = (
                key.scope == att.get("scope")
                and scope_covers(key.scope, att.get("product", ""))
            )
            checks["scope"] = {
                "ok": scope_ok,
                "key_scope": key.scope if key else None,
                "attestation_scope": att.get("scope"),
                "product": att.get("product"),
            }
            if not scope_ok:
                errors.append(
                    "applicability scope mismatch: key scope does not cover "
                    "attestation scope/product"
                )

        ok = (
            content_ok
            and build_ok
            and sig_ok
            and status_ok
            and window_ok
            and crl_ok
            and scope_ok
            and not errors
        )
        return VerificationResult(ok=ok, release_id=rid,
                                  errors=errors, checks=checks)

    def _load_trusted_crl(self, now: str, errors: list[str]):
        if self.crl is None:
            return None
        snapshot = self.crl.read_current()
        if snapshot is None:
            return None
        body = snapshot["body"]
        crl_issuer = body.get("issuer_id")
        crl_kv = body.get("key_version")
        try:
            crl_key = self.keys.get_key(crl_issuer, int(crl_kv))
        except Exception as exc:
            errors.append(f"CRL signer key missing from trust store: {exc}")
            return None
        import base64

        sig_ok = verify_signature(
            body, snapshot["signature"],
            base64.b64decode(crl_key.public_key),
        )
        ptr = self.crl.current_version_number()
        if not sig_ok or ptr != body.get("crl_version"):
            errors.append("current revocation list failed signature/version check")
            return None
        if crl_key.status not in ("active",) and not (
            crl_key.status == "rotated" and self.policy.trust_rotated
        ):
            errors.append(
                f"CRL signing key not currently trusted (status={crl_key.status})"
            )
            return None
        n = self._parse_ts(now)
        valid_to = self._parse_ts(crl_key.valid_to) if crl_key.valid_to else ""
        if valid_to and n >= valid_to:
            errors.append("CRL signing key applicability window ended")
            return None
        return snapshot


def export_bundle(release_record: dict, path: str) -> None:
    """Export a self-contained release attestation bundle for offline use."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(release_record, f, indent=2, ensure_ascii=False, sort_keys=True)


def load_bundle(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
