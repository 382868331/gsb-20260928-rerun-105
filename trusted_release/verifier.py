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
        evaluation: str = "current",
    ) -> VerificationResult:
        if release_record.get("type") == "trusted-release/release/v2" or (
            "approvals" in release_record
            and "attestation" not in release_record
        ):
            return self.verify_release_v2(
                release_record,
                artifact_path=artifact_path,
                build_spec_path=build_spec_path,
                now=now,
                expected_product=expected_product,
                evaluation=evaluation,
            )
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

    # ---------- multi-approval (v2) releases ----------
    def verify_release_v2(
        self,
        release_record: dict,
        *,
        artifact_path: str,
        build_spec_path: str | None = None,
        now: str,
        expected_product: str | None = None,
        evaluation: str = "current",
    ) -> VerificationResult:
        """Verify a multi-signer release under current and/or release-time
        trust conditions.

        evaluation: "current" (default), "release_time" or "both". The
        result's ok flag reflects the requested evaluation; the report
        always contains both evaluations so an offline auditor can compare
        the conclusion at release time with the conclusion under the
        current trust conditions. The release record itself is never
        modified.
        """
        errors: list[str] = []
        checks: dict = {}
        rid = release_record.get("release_id", "?")

        # ---------- content binding ----------
        actual_artifact_digest = file_digest(artifact_path)
        signed_artifact_digest = release_record.get("artifact_digest", "")
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
        build_ok = True
        if build_spec_path is not None:
            actual_spec_digest = file_digest(build_spec_path)
            signed_spec_digest = release_record.get("build_spec_digest", "")
            build_ok = actual_spec_digest == signed_spec_digest
            checks["build_spec_digest"] = {
                "expected": signed_spec_digest,
                "actual": actual_spec_digest,
                "ok": build_ok,
            }
            if not build_ok:
                errors.append(
                    "build spec mismatch: presented build spec does not "
                    "match signed digest"
                )
        if expected_product is not None and (
            release_record.get("product") != expected_product
        ):
            errors.append(
                f"product mismatch: expected {expected_product}, "
                f"released {release_record.get('product')}"
            )

        # ---------- trust evaluations ----------
        evaluations: dict = {}
        snap = release_record.get("trust_snapshot") or {}
        evaluations["release_time"] = self._evaluate_approval_set(
            release_record,
            now=snap.get("captured_at", release_record.get("issued_at", now)),
            key_lookup=self._snapshot_key_lookup(snap),
            crl_snapshot=snap.get("crl_snapshot"),
        )
        evaluations["current"] = self._evaluate_approval_set(
            release_record,
            now=now,
            key_lookup=self._current_key_lookup(),
            crl_snapshot="__current__",
        )
        checks["evaluations"] = evaluations

        if evaluation == "release_time":
            gate = evaluations["release_time"]
        elif evaluation == "both":
            gate = {
                "ok": evaluations["release_time"]["ok"]
                and evaluations["current"]["ok"]
            }
        else:
            gate = evaluations["current"]
        for label, ev in evaluations.items():
            for e in ev["errors"]:
                errors.append(f"[{label}] {e}")
        checks["approvals"] = evaluations[
            "release_time" if evaluation == "release_time" else "current"
        ]["approvals"]

        ok = (
            content_ok
            and build_ok
            and gate["ok"]
            and not any(
                "product mismatch" in e for e in errors
            )
        )
        return VerificationResult(ok=ok, release_id=rid,
                                  errors=errors, checks=checks)

    def _current_key_lookup(self):
        def lookup(issuer_id: str, key_version: int):
            try:
                return self.keys.get_key(issuer_id, int(key_version)).to_dict()
            except Exception:
                return None

        return lookup

    @staticmethod
    def _snapshot_key_lookup(snap: dict):
        keys = (snap or {}).get("keys", {})

        def lookup(issuer_id: str, key_version: int):
            return keys.get(issuer_id, {}).get(str(int(key_version)))

        return lookup

    def _evaluate_approval_set(
        self,
        record: dict,
        *,
        now: str,
        key_lookup,
        crl_snapshot,
    ) -> dict:
        """Grade every approval and decide the quorum.

        Returns a report with one verdict per approval (why it counts or
        why it is excluded) and the per-role quorum tally. A signer can
        fill at most one slot: additional approvals by the same issuer are
        flagged duplicate_signer and never counted twice.
        """
        errors: list[str] = []
        verdicts: list[dict] = []

        # ----- policy snapshot embedded in the record -----
        policy_snap = record.get("policy_snapshot") or {}
        policy_body = policy_snap.get("body") or {}
        policy_ok = self._check_embedded_policy(
            record, policy_snap, policy_body, key_lookup, errors
        )
        roles = policy_body.get("roles", {})
        assignments = policy_body.get("assignments", {})

        # ----- revocation material for this evaluation -----
        revoked: dict = {}
        crl_version = 0
        if crl_snapshot == "__current__":
            crl_errors: list[str] = []
            snap = self._load_trusted_crl(now, crl_errors)
            errors.extend(crl_errors)
            if snap is not None:
                revoked = snap["body"].get("revoked", {})
                crl_version = snap["body"]["crl_version"]
        elif isinstance(crl_snapshot, dict):
            body = crl_snapshot.get("body", {})
            revoked = body.get("revoked", {})
            crl_version = body.get("crl_version", 0)

        counted_signers: set[str] = set()
        role_counts = {role: 0 for role in roles}
        n = self._parse_ts(now)

        for entry in record.get("approvals", []):
            appr = entry.get("approval", {})
            issuer = appr.get("issuer_id")
            kver = appr.get("key_version")
            reasons: list[str] = []

            # --- binding: candidate, content, policy version ---
            if appr.get("candidate_id") != record.get("candidate_id"):
                reasons.append("candidate_mismatch")
            if appr.get("artifact_digest") != record.get("artifact_digest"):
                reasons.append("artifact_digest_mismatch")
            if appr.get("build_spec_digest") != record.get(
                "build_spec_digest"
            ):
                reasons.append("build_spec_digest_mismatch")
            if appr.get("product") != record.get("product") or appr.get(
                "version"
            ) != record.get("version"):
                reasons.append("product_version_mismatch")
            if int(appr.get("policy_version", -1)) != int(
                record.get("policy_version", -2)
            ):
                reasons.append("policy_version_mismatch")

            # --- role membership per the pinned policy ---
            assigned_role = assignments.get(issuer)
            if assigned_role is None:
                reasons.append("issuer_not_in_policy")
            elif assigned_role != appr.get("role"):
                reasons.append("role_mismatch")

            # --- signer key trust ---
            key = key_lookup(issuer, kver) if issuer is not None else None
            if key is None:
                reasons.append("unknown_key")
            else:
                import base64

                if not verify_signature(
                    appr, entry.get("signature", ""),
                    base64.b64decode(key["public_key"]),
                ):
                    reasons.append("bad_signature")
                status = key.get("status")
                if status == "active":
                    pass
                elif status == "rotated" and self.policy.trust_rotated:
                    pass
                else:
                    reasons.append(f"key_not_active:{status}")
                if key.get("valid_from") and self._parse_ts(
                    key["valid_from"]
                ) > n:
                    reasons.append("key_not_yet_valid")
                if key.get("valid_to") and self._parse_ts(
                    key["valid_to"]
                ) <= n:
                    reasons.append("key_window_ended")
                if key.get("scope") != appr.get("scope") or not scope_covers(
                    key.get("scope", ""), appr.get("product", "")
                ):
                    reasons.append("scope_mismatch")
                if int(kver) in revoked.get(issuer, []):
                    reasons.append(f"key_revoked:crl_v{crl_version}")

            # --- approval validity window ---
            not_before = self._parse_ts(appr.get("not_before", ""))
            expires = self._parse_ts(appr.get("expires_at", ""))
            if not_before and n < not_before:
                reasons.append("approval_not_yet_valid")
            if expires and n >= expires:
                reasons.append("approval_expired")

            # --- one slot per signer ---
            if issuer in counted_signers:
                reasons.append("duplicate_signer")

            counted = not reasons and policy_ok
            if counted:
                counted_signers.add(issuer)
                role_counts[assigned_role] += 1
            verdicts.append(
                {
                    "approval_id": entry.get("approval_id"),
                    "issuer_id": issuer,
                    "key_version": kver,
                    "role": appr.get("role"),
                    "counted": counted,
                    "reasons": reasons or ["ok"],
                }
            )

        quorum = {}
        quorum_ok = policy_ok
        for role, required in roles.items():
            satisfied = role_counts.get(role, 0) >= int(required)
            quorum[role] = {
                "required": int(required),
                "counted": role_counts.get(role, 0),
                "satisfied": satisfied,
            }
            if not satisfied:
                quorum_ok = False
                errors.append(
                    f"role {role}: {role_counts.get(role, 0)} of "
                    f"{required} required approvals counted"
                )
        if not policy_ok:
            errors.append("embedded policy snapshot is not trustworthy")

        return {
            "ok": quorum_ok,
            "now": now,
            "policy_version": record.get("policy_version"),
            "crl_version": crl_version,
            "approvals": verdicts,
            "quorum": quorum,
            "errors": errors,
        }

    def _check_embedded_policy(
        self,
        record: dict,
        policy_snap: dict,
        policy_body: dict,
        key_lookup,
        errors: list[str],
    ) -> bool:
        """The record must embed the exact policy it claims, signed by the
        policy issuer, and its version must match the record's pin."""
        import base64

        if not policy_body:
            errors.append("release record carries no policy snapshot")
            return False
        if int(policy_body.get("policy_version", -1)) != int(
            record.get("policy_version", -2)
        ):
            errors.append(
                "embedded policy version does not match record policy_version"
            )
            return False
        signer = policy_body.get("issuer_id")
        kver = policy_body.get("key_version")
        key = key_lookup(signer, kver)
        if key is None:
            # Policy issuers are long-lived; fall back to the current store
            # even when evaluating a release-time snapshot.
            key = self._current_key_lookup()(signer, kver)
        if key is None:
            errors.append("policy signer key not found")
            return False
        if not verify_signature(
            policy_body, policy_snap.get("signature", ""),
            base64.b64decode(key["public_key"]),
        ):
            errors.append("embedded policy snapshot signature invalid")
            return False
        return True

def export_bundle(release_record: dict, path: str) -> None:
    """Export a self-contained release attestation bundle for offline use."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(release_record, f, indent=2, ensure_ascii=False, sort_keys=True)


def load_bundle(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
