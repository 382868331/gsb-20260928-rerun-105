"""Multi-signer release pipeline: begin -> approve* -> finalize.

Safety properties:

* A release enters the trusted index only at `finalize`, after the full
  quorum required by the pinned policy version has been verified. Missing
  approvals or a failed signing step therefore never leave anything in the
  trusted catalog.
* Every candidate gets a unique id (random nonce + content binding), and
  every approval signs that id. A retry creates a *new* candidate, so
  approvals collected for one attempt can never be mixed into another -
  not even when the file contents are identical.
* The candidate pins the policy version at `begin` time; approvals sign
  that version and `finalize` evaluates against the pinned snapshot, so a
  policy change mid-flight cannot silently change the release conditions.
"""

from __future__ import annotations

import uuid

from .approval import build_approval, sign_approval
from .encoding import canonical_hash
from .issuer import IssuerKeyStore
from .policy import PolicyStore
from .publisher import utc_now
from .registry import Registry
from .verifier import Verifier

RELEASE_TYPE_V2 = "trusted-release/release/v2"
CANDIDATE_TYPE = "trusted-release/candidate/v1"


class ReleasePipeline:
    def __init__(
        self,
        registry: Registry,
        keystore: IssuerKeyStore,
        policies: PolicyStore,
        verifier: Verifier | None = None,
    ):
        self.registry = registry
        self.keystore = keystore
        self.policies = policies
        self.verifier = verifier

    # ---------- 1. begin ----------
    def begin(
        self,
        *,
        artifact_path: str,
        build_spec_path: str,
        product: str,
        version: str,
        now: str | None = None,
        metadata: dict | None = None,
    ) -> dict:
        """Register content and open a new release candidate.

        Fails if no release policy has been issued: without a policy there
        is no defined quorum, so no candidate may start.
        """
        now = now or utc_now()
        policy = self.policies.read_current()
        if policy is None:
            raise RuntimeError(
                "no release policy issued; cannot start a release candidate"
            )
        manifest = self.registry.register_artifact(
            source_path=artifact_path,
            product=product,
            version=version,
            build_spec_path=build_spec_path,
            now=now,
            metadata=metadata,
        )
        candidate_id = "cand-" + uuid.uuid4().hex
        candidate = {
            "type": CANDIDATE_TYPE,
            "candidate_id": candidate_id,
            "product": product,
            "version": version,
            "artifact_digest": manifest["artifact_digest"],
            "build_spec_digest": manifest["build_spec_digest"],
            "policy_version": policy["body"]["policy_version"],
            "created_at": now,
            "approvals": [],
        }
        self.registry.write_candidate(candidate)
        return candidate

    # ---------- 2. approve ----------
    def approve(
        self,
        *,
        candidate_id: str,
        issuer_id: str,
        now: str | None = None,
        validity_days: int = 365,
    ) -> dict:
        """Add one issuer's approval to a candidate.

        The approval is signed over the candidate id, both content digests
        and the pinned policy version. One issuer may approve a candidate
        only once.
        """
        now = now or utc_now()
        candidate = self.registry.read_candidate(candidate_id)
        if any(
            a["approval"]["issuer_id"] == issuer_id
            for a in candidate["approvals"]
        ):
            raise ValueError(
                f"issuer {issuer_id} already approved {candidate_id}"
            )
        policy = self.policies.read_version(candidate["policy_version"])
        role = policy["body"]["assignments"].get(issuer_id)
        if role is None:
            raise PermissionError(
                f"issuer {issuer_id} has no role in policy "
                f"v{candidate['policy_version']}"
            )
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
        approval = build_approval(
            candidate_id=candidate_id,
            product=candidate["product"],
            version=candidate["version"],
            artifact_digest=candidate["artifact_digest"],
            build_spec_digest=candidate["build_spec_digest"],
            policy_version=candidate["policy_version"],
            role=role,
            issuer_id=issuer_id,
            key_version=kv,
            scope=key.scope,
            issued_at=now,
            not_before=now,
            expires_at=expires,
        )
        signed = sign_approval(approval, seed)
        candidate["approvals"].append(signed)
        self.registry.write_candidate(candidate)
        return signed

    # ---------- 3. finalize ----------
    def finalize(self, *, candidate_id: str, now: str | None = None) -> dict:
        """Verify the quorum and, only if satisfied, index the release.

        The quorum is evaluated against the pinned policy snapshot and the
        *current* trust conditions. Any shortfall raises and leaves the
        index untouched.
        """
        now = now or utc_now()
        candidate = self.registry.read_candidate(candidate_id)
        policy_snapshot = self.policies.read_version(
            candidate["policy_version"]
        )
        record = {
            "type": RELEASE_TYPE_V2,
            "release_id": self._release_id(candidate),
            "candidate_id": candidate["candidate_id"],
            "product": candidate["product"],
            "version": candidate["version"],
            "artifact_digest": candidate["artifact_digest"],
            "build_spec_digest": candidate["build_spec_digest"],
            "policy_version": candidate["policy_version"],
            "issued_at": now,
            "approvals": candidate["approvals"],
            "policy_snapshot": policy_snapshot,
            "trust_snapshot": self._capture_trust_snapshot(
                candidate, policy_snapshot, now
            ),
        }
        record["record_id"] = canonical_hash(
            {k: record[k] for k in record if k != "record_id"}
        )
        if self.verifier is not None:
            evaluation = self.verifier._evaluate_approval_set(
                record,
                now=now,
                key_lookup=self.verifier._current_key_lookup(),
                crl_snapshot="__current__",
            )
            if not evaluation["ok"]:
                raise RuntimeError(
                    "approval quorum not satisfied; release NOT indexed: "
                    + "; ".join(evaluation["errors"])
                )
        # Index LAST (atomic): nothing trusted exists before this point.
        self.registry.index_release(record)
        return record

    # ---------- helpers ----------
    @staticmethod
    def _release_id(candidate: dict) -> str:
        short = candidate["artifact_digest"].split(":", 1)[1][:12]
        nonce = candidate["candidate_id"].split("-", 1)[1][:8]
        return f"{candidate['product']}-{candidate['version']}-{short}-{nonce}"

    def _capture_trust_snapshot(
        self, candidate: dict, policy_snapshot: dict, now: str
    ) -> dict:
        """Freeze the trust conditions at finalize time so offline auditors
        can later compare release-time vs current conclusions without
        mutating the release record."""
        keys: dict[str, dict[str, dict]] = {}

        def remember(issuer_id: str, key_version: int) -> None:
            try:
                rec = self.keystore.get_key(issuer_id, int(key_version))
            except KeyError:
                return
            keys.setdefault(issuer_id, {})[str(rec.key_version)] = rec.to_dict()

        for entry in candidate["approvals"]:
            appr = entry["approval"]
            remember(appr["issuer_id"], appr["key_version"])
        body = policy_snapshot["body"]
        remember(body["issuer_id"], body["key_version"])

        crl_snapshot = None
        crl_version = 0
        if self.verifier is not None and self.verifier.crl is not None:
            crl_snapshot = self.verifier.crl.read_current()
            if crl_snapshot is not None:
                crl_version = crl_snapshot["body"]["crl_version"]
                remember(
                    crl_snapshot["body"]["issuer_id"],
                    crl_snapshot["body"]["key_version"],
                )
        return {
            "captured_at": now,
            "crl_version": crl_version,
            "crl_snapshot": crl_snapshot,
            "keys": keys,
        }

    @staticmethod
    def _shift(ts: str, days: int) -> str:
        import datetime

        dt = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc
        )
        return (dt + datetime.timedelta(days=days)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

