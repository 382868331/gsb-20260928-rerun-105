"""Release set scenarios: shared/cyclic dependencies, partial approvals,
resume after interruption, and offline set integrity verification."""

import pytest

from trusted_release import (
    IssuerKeyStore,
    Publisher,
    Registry,
    RevocationList,
    Verifier,
)
from trusted_release.policy import ReleasePolicy

NOW = "2026-01-01T00:00:00Z"
LATER = "2026-02-01T00:00:00Z"

POLICY = ReleasePolicy("set-standard", 1, {"build": 1, "qa": 1})


@pytest.fixture()
def store(tmp_path):
    reg = Registry(str(tmp_path / "registry"))
    keys = IssuerKeyStore(str(tmp_path / "issuers"))
    crl = RevocationList(str(tmp_path / "crl"))
    keys.create_key("sec", scope="*", now=NOW)
    keys.create_key("builder", scope="*", role="build", now=NOW)
    keys.create_key("qa-team", scope="*", role="qa", now=NOW)

    def make(name, content):
        art = tmp_path / (name + ".bin")
        art.write_bytes(content)
        spec = tmp_path / (name + ".BUILD")
        spec.write_bytes(b"build " + content)
        return str(art), str(spec)

    files = {
        "libbase": make("libbase", b"libbase v1"),
        "libmid": make("libmid", b"libmid v1"),
        "app": make("app", b"app v1"),
    }
    members = [
        {"product": "libbase", "version": "1.0",
         "artifact_path": files["libbase"][0],
         "build_spec_path": files["libbase"][1], "depends_on": []},
        {"product": "libmid", "version": "1.0",
         "artifact_path": files["libmid"][0],
         "build_spec_path": files["libmid"][1], "depends_on": ["libbase"]},
        {"product": "app", "version": "1.0",
         "artifact_path": files["app"][0],
         "build_spec_path": files["app"][1],
         "depends_on": ["libmid", "libbase"]},
    ]
    return tmp_path, reg, keys, crl, members, files


def _candidate(store, members=None, policy=POLICY, name="suite",
               set_version="2026.1"):
    _, reg, keys, crl, default_members, _ = store
    pub = Publisher(reg, keys, crl)
    return pub.create_set_candidate(
        name=name, set_version=set_version,
        members=members if members is not None else default_members,
        policy=policy, now=NOW,
    )


def _approve(store, candidate, issuer, now=NOW):
    _, reg, keys, crl, _, _ = store
    return Publisher(reg, keys, crl).approve_set_candidate(
        candidate, issuer_id=issuer, now=now)


def _finalize(store, candidate, approvals, now=LATER):
    _, reg, keys, crl, _, _ = store
    return Publisher(reg, keys, crl).publish_set_candidate(
        candidate, approvals, now=now)


def _member_files(store, record):
    _, reg, _, _, _, _ = store
    return {
        m["product"]: (reg.artifact_path(m["artifact_digest"]),
                       reg.artifact_path(m["build_spec_digest"]))
        for m in record["members"]
    }


def test_shared_dependency_set_full_flow(store):
    _, reg, keys, crl, members, files = store
    candidate = _candidate(store)
    app = next(m for m in candidate["members"] if m["product"] == "app")
    assert app["depends_on"] == ["libbase", "libmid"]
    approvals = [_approve(store, candidate, "builder"),
                 _approve(store, candidate, "qa-team")]
    record = _finalize(store, candidate, approvals)
    result = Verifier(keys, crl).verify_set_release(
        record, member_files=_member_files(store, record), now=LATER)
    assert result.ok, result.errors
    idx = reg.read_index()
    assert idx["sets"][0]["set_id"] == record["set_id"]
    assert len(idx["sets"][0]["members"]) == 3


def test_cyclic_dependencies_allowed_and_reported(store):
    _, reg, keys, crl, members, _ = store
    cyclic = [dict(m) for m in members]
    cyclic[0]["depends_on"] = ["app"]  # libbase <-> app cycle
    candidate = _candidate(store, members=cyclic)
    approvals = [_approve(store, candidate, "builder"),
                 _approve(store, candidate, "qa-team")]
    record = _finalize(store, candidate, approvals)
    result = Verifier(keys, crl).verify_set_release(
        record, member_files=_member_files(store, record), now=LATER)
    assert result.ok, result.errors
    assert result.checks["dependency_cycles"]


def test_missing_dependency_declaration_rejected(store):
    _, reg, keys, crl, members, _ = store
    bad = [dict(m) for m in members]
    bad[2]["depends_on"] = ["ghost-lib"]
    with pytest.raises(ValueError, match="ghost-lib"):
        _candidate(store, members=bad)


def test_partial_approval_then_resume_after_interruption(store):
    _, reg, keys, crl, members, _ = store
    candidate = _candidate(store)
    first = _approve(store, candidate, "builder", now=NOW)
    with pytest.raises(ValueError, match="insufficient valid distinct"):
        _finalize(store, candidate, [first])
    assert reg.read_index().get("sets", []) == []
    second = _approve(store, candidate, "qa-team", now=LATER)
    record = _finalize(store, candidate, [first, second])
    assert reg.read_index()["sets"][0]["set_id"] == record["set_id"]


def test_member_replacement_invalidates_old_approvals(store):
    tmp_path, reg, keys, crl, members, files = store
    candidate_v1 = _candidate(store)
    old_approvals = [_approve(store, candidate_v1, "builder"),
                     _approve(store, candidate_v1, "qa-team")]
    art, spec = files["libmid"]
    with open(art, "wb") as f:
        f.write(b"libmid v1.0.1 patched")
    candidate_v2 = _candidate(store)
    assert candidate_v2["set_digest"] != candidate_v1["set_digest"]
    with pytest.raises(ValueError, match="insufficient valid distinct"):
        _finalize(store, candidate_v2, old_approvals)
    assert reg.read_index().get("sets", []) == []


def test_dependency_change_invalidates_old_approvals(store):
    _, reg, keys, crl, members, _ = store
    candidate_v1 = _candidate(store)
    old_approvals = [_approve(store, candidate_v1, "builder"),
                     _approve(store, candidate_v1, "qa-team")]
    changed = [dict(m) for m in members]
    changed[1]["depends_on"] = []
    candidate_v2 = _candidate(store, members=changed)
    with pytest.raises(ValueError, match="insufficient valid distinct"):
        _finalize(store, candidate_v2, old_approvals)


def test_policy_change_invalidates_old_approvals(store):
    _, reg, keys, crl, members, _ = store
    candidate_v1 = _candidate(store)
    old_approvals = [_approve(store, candidate_v1, "builder"),
                     _approve(store, candidate_v1, "qa-team")]
    policy_v2 = ReleasePolicy("set-standard", 2, {"build": 1, "qa": 1})
    candidate_v2 = _candidate(store, policy=policy_v2)
    with pytest.raises(ValueError, match="insufficient valid distinct"):
        _finalize(store, candidate_v2, old_approvals)


def test_revocation_during_collection_reinterprets_approvals(store):
    _, reg, keys, crl, members, _ = store
    candidate = _candidate(store)
    first = _approve(store, candidate, "builder", now=NOW)
    seed = keys.load_secret("sec", 1)
    crl.issue(revoked={"builder": [1]}, reason="key compromise", now=LATER,
              issuer_id="sec", key_version=1, secret_seed=seed)
    keys.set_status("builder", 1, "revoked", LATER)
    second = _approve(store, candidate, "qa-team", now=LATER)
    with pytest.raises(ValueError, match="insufficient valid distinct"):
        _finalize(store, candidate, [first, second], now=LATER)
    assert reg.read_index().get("sets", []) == []


def test_old_set_remains_verifiable_after_newer_set(store):
    _, reg, keys, crl, members, files = store
    c1 = _candidate(store, set_version="2026.1")
    a1 = [_approve(store, c1, "builder"), _approve(store, c1, "qa-team")]
    r1 = _finalize(store, c1, a1)
    art, spec = files["app"]
    with open(art, "wb") as f:
        f.write(b"app v2")
    c2 = _candidate(store, set_version="2026.2")
    a2 = [_approve(store, c2, "builder"), _approve(store, c2, "qa-team")]
    r2 = _finalize(store, c2, a2)
    v = Verifier(keys, crl)
    assert v.verify_set_release(r1, member_files=_member_files(store, r1),
                                now=LATER).ok
    assert v.verify_set_release(r2, member_files=_member_files(store, r2),
                                now=LATER).ok
    assert len(reg.read_index()["sets"]) == 2


def test_offline_verify_reports_missing_member(store):
    tmp_path, reg, keys, crl, members, files = store
    candidate = _candidate(store)
    approvals = [_approve(store, candidate, "builder"),
                 _approve(store, candidate, "qa-team")]
    record = _finalize(store, candidate, approvals)
    partial = {"app": files["app"], "libmid": files["libmid"]}
    result = Verifier(keys, crl).verify_set_release(
        record, member_files=partial, now=LATER)
    assert not result.ok
    assert any("missing trusted basis" in e and "libbase" in e
               for e in result.errors)
    assert result.checks["members"]["libbase"]["missing"] is True
    assert result.checks["members"]["app"]["ok"] is True


def test_offline_verify_detects_member_substitution(store):
    tmp_path, reg, keys, crl, members, files = store
    candidate = _candidate(store)
    approvals = [_approve(store, candidate, "builder"),
                 _approve(store, candidate, "qa-team")]
    record = _finalize(store, candidate, approvals)
    evil = tmp_path / "evil.bin"
    evil.write_bytes(b"trojaned libmid")
    substituted = dict(files)
    substituted["libmid"] = (str(evil), files["libmid"][1])
    result = Verifier(keys, crl).verify_set_release(
        record, member_files=substituted, now=LATER)
    assert not result.ok
    assert any("libmid" in e and "mismatch" in e for e in result.errors)
