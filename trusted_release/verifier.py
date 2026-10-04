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
from .encoding import canonical_hash, canonical_json, file_digest
from .issuer import IssuerKeyStore
from .policy import ReleasePolicy


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
        as_of: str = "current",
    ) -> VerificationResult:
        errors: list[str] = []
        checks: dict = {}
        att = release_record.get("attestation", {})
        signature = release_record.get("signature", "")
        rid = att.get("release_id", release_record.get("release_id", "?"))
        if release_record.get("type") == "trusted-release/release/v2":
            return self._verify_policy_release(
                release_record, artifact_path=artifact_path,
                build_spec_path=build_spec_path, now=now,
                expected_product=expected_product, as_of=as_of,
            )

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
            snapshot = self._load_trusted_crl(now, errors, as_of=as_of)
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

    def _load_trusted_crl(self, now: str, errors: list[str], as_of: str = "current"):
        if self.crl is None:
            return None
        snapshot = self._read_crl_snapshot(now, as_of, None)
        if snapshot is None:
            return None
        return self._validate_crl_snapshot(snapshot, now, errors, as_of)

    def _read_crl_snapshot(self, now: str, as_of: str, record: dict | None):
        if as_of == "release" and record is not None and record.get("crl_version_at_release"):
            return self.crl.read_version(int(record["crl_version_at_release"]))
        if as_of == "release" and record is not None:
            target = self._parse_ts(record.get("released_at", now))
            chosen = None
            for version in self.crl.list_versions():
                snap = self.crl.read_version(version)
                if self._parse_ts(snap["body"].get("issued_at", "")) <= target:
                    chosen = snap
            return chosen
        if as_of not in ("current", "release"):
            target = self._parse_ts(as_of)
            chosen = None
            for version in self.crl.list_versions():
                snap = self.crl.read_version(version)
                if self._parse_ts(snap["body"].get("issued_at", "")) <= target:
                    chosen = snap
            return chosen
        return self.crl.read_current()

    def _validate_crl_snapshot(self, snapshot, now: str, errors: list[str], as_of: str):
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
        if not sig_ok or (as_of == "current" and ptr != body.get("crl_version")):
            errors.append("current revocation list failed signature/version check")
            return None
        if not self._key_status_ok(crl_key, now, as_of):
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

    def _key_status_ok(self, key, now: str, as_of: str) -> bool:
        changed_at = self._parse_ts(key.status_changed_at) if key.status_changed_at else ""
        if changed_at and changed_at > self._parse_ts(now):
            return True
        if key.status == "active":
            return True
        if key.status == "rotated":
            return self.policy.trust_rotated
        return False

    def _crl_for(self, record: dict, now: str, as_of: str, errors: list[str]):
        snapshot = self._read_crl_snapshot(now, as_of, record)
        if snapshot is None:
            if self.crl is not None and self.crl.list_versions():
                errors.append("no revocation snapshot available for requested evaluation time")
            return {}, 0
        valid = self._validate_crl_snapshot(snapshot, now, errors, as_of)
        if valid is None:
            return {}, 0
        return valid["body"].get("revoked", {}), valid["body"]["crl_version"]

    def _verify_policy_release(self, record: dict, *, artifact_path: str,
                               build_spec_path: str | None, now: str,
                               expected_product: str | None,
                               as_of: str) -> VerificationResult:
        errors: list[str] = []
        checks: dict = {}
        rid = record.get("release_id", "?")
        candidate = record.get("candidate", {})
        try:
            policy = ReleasePolicy.from_dict(record.get("policy", candidate.get("policy", {})))
        except Exception as exc:
            return VerificationResult(False, rid, [f"invalid release policy: {exc}"], {})
        policy_data = policy.to_dict()
        if candidate.get("policy") != policy_data or record.get("policy") != policy_data:
            errors.append("policy mismatch: release and candidate policies differ")
        if record.get("policy_digest") != policy.digest or candidate.get("policy_digest") != policy.digest:
            errors.append("policy digest mismatch")
        expected_candidate_digest = canonical_hash({
            "artifact_digest": candidate.get("artifact_digest"),
            "build_spec_digest": candidate.get("build_spec_digest"),
            "policy": policy_data,
            "product": candidate.get("product"),
            "version": candidate.get("version"),
            "nonce": candidate.get("nonce"),
        })
        if candidate.get("candidate_digest") != expected_candidate_digest:
            errors.append("candidate digest mismatch")
        actual_artifact = file_digest(artifact_path)
        content_ok = actual_artifact == record.get("artifact_digest") == candidate.get("artifact_digest")
        checks["artifact_digest"] = {"expected": record.get("artifact_digest"), "actual": actual_artifact, "ok": content_ok}
        if not content_ok:
            errors.append("artifact content mismatch: presented file does not match signed digest")
        build_ok = True
        if build_spec_path is not None:
            actual_spec = file_digest(build_spec_path)
            build_ok = actual_spec == record.get("build_spec_digest") == candidate.get("build_spec_digest")
            checks["build_spec_digest"] = {"expected": record.get("build_spec_digest"), "actual": actual_spec, "ok": build_ok}
            if not build_ok:
                errors.append("build spec mismatch: presented build spec does not match signed digest")
        if expected_product is not None and record.get("product") != expected_product:
            errors.append(f"product mismatch: expected {expected_product}, attested {record.get('product')}")
        effective_now = record.get("released_at", now) if as_of == "release" else now
        revoked, crl_version = self._crl_for(record, effective_now, as_of, errors)
        approval_checks = []
        counted = {role: set() for role in policy.requirements}
        seen_issuers: set[str] = set()
        import base64
        for envelope in sorted(record.get("approvals", []), key=lambda x: x.get("approval_id", "")):
            approval = envelope.get("approval", {})
            issuer_id = approval.get("issuer_id")
            key_version = approval.get("key_version")
            check = {"approval_id": envelope.get("approval_id", ""), "issuer": issuer_id,
                     "key_version": key_version, "role": approval.get("role"),
                     "ok": False, "counted": False, "reasons": []}
            key = None
            try:
                key = self.keys.get_key(issuer_id, int(key_version))
            except Exception as exc:
                check["reasons"].append(f"key not found: {exc}")
            if key is not None:
                sig_ok = verify_signature(approval, envelope.get("signature", ""), base64.b64decode(key.public_key))
                check["signature_ok"] = sig_ok
                if not sig_ok:
                    check["reasons"].append("signature verification failed")
                if not self._key_status_ok(key, effective_now, as_of):
                    check["reasons"].append(f"not currently trusted (status={key.status})")
                n = self._parse_ts(effective_now)
                if key.valid_from and self._parse_ts(key.valid_from) > n:
                    check["reasons"].append("key not yet valid")
                if key.valid_to and self._parse_ts(key.valid_to) <= n:
                    check["reasons"].append("key applicability window has ended")
                if approval.get("not_before") and n < self._parse_ts(approval["not_before"]):
                    check["reasons"].append("approval not yet valid")
                if approval.get("expires_at") and n >= self._parse_ts(approval["expires_at"]):
                    check["reasons"].append("approval expired")
                if int(key_version) in revoked.get(issuer_id, []):
                    check["reasons"].append(f"revoked by CRL v{crl_version}")
                if key.scope != approval.get("scope") or not scope_covers(key.scope, record.get("product", "")):
                    check["reasons"].append("scope mismatch")
                if key.role != approval.get("role"):
                    check["reasons"].append("role mismatch")
            bindings = {
                "candidate_id": candidate.get("candidate_id"),
                "candidate_digest": candidate.get("candidate_digest"),
                "release_id": record.get("release_id"),
                "product": record.get("product"),
                "version": record.get("version"),
                "artifact_digest": record.get("artifact_digest"),
                "build_spec_digest": record.get("build_spec_digest"),
                "policy_id": policy.policy_id,
                "policy_version": policy.policy_version,
                "policy_digest": policy.digest,
            }
            for field_name, expected in bindings.items():
                if approval.get(field_name) != expected:
                    check["reasons"].append(f"approval binding mismatch: {field_name}")
            if issuer_id in seen_issuers:
                check["reasons"].append("duplicate issuer cannot be counted twice")
            valid_role = approval.get("role") in policy.requirements
            if not valid_role:
                check["reasons"].append("role not required by policy")
            check["ok"] = not check["reasons"]
            if check["ok"] and issuer_id not in seen_issuers:
                counted[approval["role"]].add(issuer_id)
                check["counted"] = True
            seen_issuers.add(issuer_id)
            approval_checks.append(check)
        counts = {role: len(issuers) for role, issuers in counted.items()}
        checks.update({"approvals": approval_checks, "approval_counts": counts,
                       "policy_requirements": policy.requirements, "crl_version": crl_version})
        for role, required in policy.requirements.items():
            if counts.get(role, 0) < required:
                errors.append(f"insufficient valid distinct issuers for role {role}: have {counts.get(role, 0)}, need {required}")
        return VerificationResult(not errors, rid, errors, checks)


    def verify_collection(
        self,
        record: dict,
        *,
        resolve_content,
        now: str,
        as_of: str = "current",
        expected_name: str | None = None,
    ) -> VerificationResult:
        """Verify a whole release collection under current trust conditions.

        resolve_content(digest) -> path or None locates member bytes for
        the offline receiver. The result lists exactly which trust basis
        is missing: absent member content, dangling dependency edges,
        revoked/rotated approver keys, or unmet policy roles.
        """
        import base64

        from . import collection as coll

        rid = record.get("collection_release_id", "?")
        errors: list[str] = []
        checks: dict = {}
        if record.get("type") != coll.RELEASE_TYPE:
            return VerificationResult(
                False, rid, [f"not a collection release: {record.get('type')!r}"], {}
            )
        candidate = record.get("candidate", {})
        spec = record.get("spec", candidate.get("spec", {}))

        try:
            policy = ReleasePolicy.from_dict(
                record.get("policy", candidate.get("policy", {}))
            )
        except Exception as exc:
            return VerificationResult(
                False, rid, [f"invalid release policy: {exc}"], {}
            )
        policy_data = policy.to_dict()
        if candidate.get("policy") != policy_data or record.get("policy") != policy_data:
            errors.append("policy mismatch: release and candidate policies differ")
        if (
            record.get("policy_digest") != policy.digest
            or candidate.get("policy_digest") != policy.digest
        ):
            errors.append("policy digest mismatch")

        # ---------- collection spec integrity ----------
        actual_spec_digest = coll.spec_digest(spec) if spec.get("members") else ""
        spec_ok = (
            actual_spec_digest == record.get("spec_digest")
            == candidate.get("spec_digest")
        )
        checks["spec_digest"] = {
            "expected": record.get("spec_digest"),
            "actual": actual_spec_digest,
            "ok": spec_ok,
        }
        if not spec_ok:
            errors.append("collection spec digest mismatch (spec tampered)")
        spec_errors = coll.validate_spec(spec)
        errors.extend(spec_errors)
        cycles = coll.find_cycles(spec) if not spec_errors else []
        checks["dependency_cycles"] = cycles

        expected_candidate_digest = canonical_hash(
            {
                "spec": coll.build_spec(
                    name=spec.get("name", ""),
                    version=spec.get("version", ""),
                    members=spec.get("members", []),
                ),
                "policy": policy_data,
                "nonce": candidate.get("nonce"),
            }
        )
        if (
            candidate.get("candidate_digest") != expected_candidate_digest
            or record.get("candidate_digest") != expected_candidate_digest
        ):
            errors.append("candidate digest mismatch")
        if expected_name is not None and record.get("name") != expected_name:
            errors.append(
                f"collection name mismatch: expected {expected_name}, "
                f"attested {record.get('name')}"
            )

        # ---------- member content ----------
        missing: list[str] = []
        member_checks = []
        members_ok = True
        for m in spec.get("members", []):
            label = f"{m.get('product')}:{m.get('version')}"
            entry = {"member": label, "artifact_ok": False,
                     "build_spec_ok": False, "reasons": []}
            for field, key in (("artifact_digest", "artifact_ok"),
                               ("build_spec_digest", "build_spec_ok")):
                digest = m.get(field, "")
                path = resolve_content(digest)
                if path is None:
                    entry["reasons"].append(f"content missing for {field} {digest}")
                    missing.append(f"member {label} {field} not present locally")
                    continue
                actual = file_digest(path)
                if actual != digest:
                    entry["reasons"].append(
                        f"{field} mismatch: expected {digest}, got {actual}"
                    )
                else:
                    entry[key] = True
            if entry["reasons"]:
                members_ok = False
                errors.append(f"member {label}: " + "; ".join(entry["reasons"]))
            member_checks.append(entry)
        checks["members"] = member_checks

        # ---------- approvals re-interpreted under current trust ----------
        effective_now = record.get("released_at", now) if as_of == "release" else now
        revoked, crl_version = self._crl_for(record, effective_now, as_of, errors)
        approval_checks = []
        counted = {role: set() for role in policy.requirements}
        seen_issuers: set[str] = set()
        envelopes = sorted(
            record.get("approvals", []), key=lambda x: x.get("approval_id", "")
        )
        for envelope in envelopes:
            approval = envelope.get("approval", {})
            issuer_id = approval.get("issuer_id")
            key_version = approval.get("key_version")
            check = {"approval_id": envelope.get("approval_id", ""),
                     "issuer": issuer_id, "key_version": key_version,
                     "role": approval.get("role"), "ok": False,
                     "counted": False, "reasons": []}
            key = None
            try:
                key = self.keys.get_key(issuer_id, int(key_version))
            except Exception as exc:
                check["reasons"].append(f"key not found: {exc}")
            if key is not None:
                sig_ok = verify_signature(
                    approval, envelope.get("signature", ""),
                    base64.b64decode(key.public_key),
                )
                check["signature_ok"] = sig_ok
                if not sig_ok:
                    check["reasons"].append("signature verification failed")
                if not self._key_status_ok(key, effective_now, as_of):
                    check["reasons"].append(
                        f"not currently trusted (status={key.status})"
                    )
                n = self._parse_ts(effective_now)
                if key.valid_from and self._parse_ts(key.valid_from) > n:
                    check["reasons"].append("key not yet valid")
                if key.valid_to and self._parse_ts(key.valid_to) <= n:
                    check["reasons"].append("key applicability window has ended")
                if approval.get("not_before") and n < self._parse_ts(approval["not_before"]):
                    check["reasons"].append("approval not yet valid")
                if approval.get("expires_at") and n >= self._parse_ts(approval["expires_at"]):
                    check["reasons"].append("approval expired")
                if int(key_version) in revoked.get(issuer_id, []):
                    check["reasons"].append(f"revoked by CRL v{crl_version}")
                if key.scope != approval.get("scope") or not scope_covers(
                    key.scope, record.get("name", "")
                ):
                    check["reasons"].append("scope mismatch")
                if key.role != approval.get("role"):
                    check["reasons"].append("role mismatch")
            bindings = {
                "candidate_id": candidate.get("candidate_id"),
                "candidate_digest": candidate.get("candidate_digest"),
                "collection_release_id": record.get("collection_release_id"),
                "name": record.get("name"),
                "version": record.get("version"),
                "spec_digest": record.get("spec_digest"),
                "policy_id": policy.policy_id,
                "policy_version": policy.policy_version,
                "policy_digest": policy.digest,
            }
            for field_name, expected in bindings.items():
                if approval.get(field_name) != expected:
                    check["reasons"].append(f"approval binding mismatch: {field_name}")
            if issuer_id in seen_issuers:
                check["reasons"].append("duplicate issuer cannot be counted twice")
            if approval.get("role") not in policy.requirements:
                check["reasons"].append("role not required by policy")
            check["ok"] = not check["reasons"]
            if check["ok"] and issuer_id not in seen_issuers:
                counted[approval["role"]].add(issuer_id)
                check["counted"] = True
            seen_issuers.add(issuer_id)
            approval_checks.append(check)
        counts = {role: len(issuers) for role, issuers in counted.items()}
        for role, required in policy.requirements.items():
            if counts.get(role, 0) < required:
                msg = (
                    f"insufficient valid distinct issuers for role {role}: "
                    f"have {counts.get(role, 0)}, need {required}"
                )
                errors.append(msg)
                missing.append(msg)
                for check in approval_checks:
                    if not check["ok"]:
                        missing.append(
                            f"approval from {check['issuer']} not counted: "
                            + "; ".join(check["reasons"])
                        )
        checks.update({
            "approvals": approval_checks,
            "approval_counts": counts,
            "policy_requirements": policy.requirements,
            "crl_version": crl_version,
            "missing_trust": missing,
        })
        ok = not errors and members_ok
        return VerificationResult(ok, rid, errors, checks)


def export_bundle(release_record: dict, path: str) -> None:


    """Export a self-contained release attestation bundle for offline use."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(release_record, f, indent=2, ensure_ascii=False, sort_keys=True)


def load_bundle(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
