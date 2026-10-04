"""Release collection scenarios: shared/cyclic dependencies, partial
approval with resume, and trust re-interpretation during collection."""

import pytest

from trusted_release import (
    IssuerKeyStore,
    Publisher,
    Registry,
    RevocationList,
    Verifier,
)
from trusted_release.collection import find_cycles, validate_spec
from trusted_release.collection_report import build_collection_comparison
from trusted_release.policy import ReleasePolicy

NOW = "2026-01-01T00:00:00Z"
LATER = "2026-02-01T00:00:00Z"


@pytest.fixture()
def store(tmp_path):
    reg = Registry(str(tmp_path / "registry"))
    keys = IssuerKeyStore(str(tmp_path / "issuers"))
    crl = RevocationList(str(tmp_path / "crl"))
    keys.create_key("sec", scope="*", now=NOW)
    keys.create_key("build", scope="*", role="build", now=NOW)
    keys.create_key("qa", scope="*", role="qa", now=NOW)

    def make(name, content):
        p = tmp_path / name
        p.write_bytes(content)
        return str(p)

    files = {
        "app": (make("app-2.0.tar", b"app binary v2"), make("APP.BUILD", b"build app")),
        "lib": (make("lib-1.3.tar", b"lib binary v1.3"), make("LIB.BUILD", b"build lib")),
        "plugA": (make("plugA-1.0.tar", b"plugin A"), make("PA.BUILD", b"build A")),
        "plugB": (make("plugB-1.0.tar", b"plugin B"), make("PB.BUILD", b"build B")),
    }
    return tmp_path, reg, keys, crl, files


def _members(files, lib_version="1.3"):
    app_art, app_spec = files["app"]
    lib_art, lib_spec = files["lib"]
    pa_art, pa_spec = files["plugA"]
    pb_art, pb_spec = files["plugB"]
    return [
        {"product": "app", "version": "2.0",
         "artifact_path": app_art, "build_spec_path": app_spec,
         "depends_on": [{"product": "lib", "version": lib_version}]},
        {"product": "lib", "version": "1.3",
         "artifact_path": lib_art, "build_spec_path": lib_spec},
        {"product": "plugA", "version": "1.0",
         "artifact_path": pa_art, "build_spec_path": pa_spec,
         "depends_on": [{"product": "plugB", "version": "1.0"},
                        {"product": "lib", "version": "1.3"}]},
        {"product": "plugB", "version": "1.0",
         "artifact_path": pb_art, "build_spec_path": pb_spec,
         "depends_on": [{"product": "plugA", "version": "1.0"}]},
    ]


POLICY = ReleasePolicy("standard", 1, {"build": 1, "qa": 1})


def _candidate(store, **kw):
    _, reg, keys, crl, files = store
    members = kw.pop("members", _members(files))
    policy = kw.pop("policy", POLICY)
    return Publisher(reg, keys).create_collection_candidate(
        name="platform", version="2026.10", members=members,
        policy=policy, now=NOW, **kw,
    )


def _approve(store, candidate, issuer, now=NOW):
    _, reg, keys, _, _ = store
    return Publisher(reg, keys).approve_collection(
        candidate, issuer_id=issuer, now=now
    )


def _resolver(reg):
    def resolve(digest):
        path = reg.artifact_path(digest)
        return path if reg.has_artifact(digest) else None
    return resolve


def _finalize(store, candidate, approvals, now=LATER):
    _, reg, keys, crl, _ = store
    return Publisher(reg, keys, crl).finalize_collection(
        candidate, approvals, now=now
    )


def test_shared_and_cyclic_dependencies_publish_and_verify(store):
    tmp_path, reg, keys, crl, _ = store
    candidate = _candidate(store)
    spec = candidate["spec"]
    # app and plugA share the lib dependency; plugA <-> plugB is cyclic.
    assert validate_spec(spec) == []
    cycles = find_cycles(spec)
    assert any("plugA:1.0" in c and "plugB:1.0" in c for c in cycles)

    approvals = [_approve(store, candidate, "build"),
                 _approve(store, candidate, "qa")]
    record = _finalize(store, candidate, approvals)
    result = Verifier(keys, crl).verify_collection(
        record, resolve_content=_resolver(reg), now=LATER
    )
    assert result.ok, result.errors
    assert result.checks["dependency_cycles"]
    idx = reg.read_index()
    assert idx["collections"][0]["collection_release_id"] == (
        record["collection_release_id"]
    )
    assert idx["collections"][0]["member_count"] == 4


def test_dangling_dependency_rejected(store):
    _, reg, keys, _, files = store
    members = _members(files, lib_version="9.9")  # no such member
    with pytest.raises(ValueError, match="not in the collection"):
        _candidate(store, members=members)


def test_member_replacement_invalidates_old_approvals(store):
    tmp_path, reg, keys, crl, files = store
    candidate_v1 = _candidate(store)
    old_approvals = [_approve(store, candidate_v1, "build"),
                     _approve(store, candidate_v1, "qa")]
    # Replace one artifact: same product/version, new content.
    replaced = tmp_path / "app-2.0-hotfix.tar"
    replaced.write_bytes(b"app binary v2 HOTFIX")
    files["app"] = (str(replaced), files["app"][1])
    candidate_v2 = _candidate(store)
    assert candidate_v2["candidate_digest"] != candidate_v1["candidate_digest"]
    with pytest.raises(ValueError, match="insufficient valid distinct issuers"):
        _finalize(store, candidate_v2, old_approvals)
    # Fresh approvals on the new candidate work.
    new_approvals = [_approve(store, candidate_v2, "build"),
                     _approve(store, candidate_v2, "qa")]
    record = _finalize(store, candidate_v2, new_approvals)
    assert Verifier(keys, crl).verify_collection(
        record, resolve_content=_resolver(reg), now=LATER
    ).ok


def test_dependency_declaration_change_invalidates_old_approvals(store):
    _, reg, keys, crl, files = store
    candidate_v1 = _candidate(store)
    old_approvals = [_approve(store, candidate_v1, "build"),
                     _approve(store, candidate_v1, "qa")]
    members = _members(files)
    members[0]["depends_on"] = []  # drop app -> lib edge
    candidate_v2 = _candidate(store, members=members)
    assert candidate_v2["spec_digest"] != candidate_v1["spec_digest"]
    with pytest.raises(ValueError, match="insufficient valid distinct issuers"):
        _finalize(store, candidate_v2, old_approvals)


def test_partial_approval_then_resume(store):
    _, reg, keys, crl, _ = store
    candidate = _candidate(store)
    build_only = [_approve(store, candidate, "build")]
    # First finalize attempt: quorum not met, nothing is exposed.
    with pytest.raises(ValueError, match="role qa"):
        _finalize(store, candidate, build_only)
    assert reg.read_index().get("collections", []) == []
    # Resume later: the missing approval arrives, finalize succeeds.
    approvals = build_only + [_approve(store, candidate, "qa", now=LATER)]
    record = _finalize(store, candidate, approvals)
    assert Verifier(keys, crl).verify_collection(
        record, resolve_content=_resolver(reg), now=LATER
    ).ok


def test_policy_change_during_collection_reinterprets_approvals(store):
    _, reg, keys, crl, _ = store
    candidate_v1 = _candidate(store)
    old_approvals = [_approve(store, candidate_v1, "build"),
                     _approve(store, candidate_v1, "qa")]
    # Policy version bumps while approvals are being collected.
    policy_v2 = ReleasePolicy("standard", 2, {"build": 1, "qa": 1})
    candidate_v2 = _candidate(store, policy=policy_v2)
    with pytest.raises(ValueError, match="insufficient valid distinct issuers"):
        _finalize(store, candidate_v2, old_approvals)


def test_revocation_during_collection_reinterprets_approvals(store):
    _, reg, keys, crl, _ = store
    candidate = _candidate(store)
    approvals = [_approve(store, candidate, "build"),
                 _approve(store, candidate, "qa")]
    # build's key is revoked after it approved but before finalize.
    seed = keys.load_secret("sec", 1)
    crl.issue(revoked={"build": [1]}, reason="compromised", now=LATER,
              issuer_id="sec", key_version=1, secret_seed=seed)
    keys.set_status("build", 1, "revoked", LATER)
    with pytest.raises(ValueError, match="role build"):
        _finalize(store, candidate, approvals, now=LATER)
    # A replacement build issuer approves; quorum is met again.
    keys.create_key("build2", scope="*", role="build", now=LATER)
    approvals = approvals + [
        Publisher(reg, keys).approve_collection(
            candidate, issuer_id="build2", now=LATER)
    ]
    record = _finalize(store, candidate, approvals, now=LATER)
    result = Verifier(keys, crl).verify_collection(
        record, resolve_content=_resolver(reg), now=LATER
    )
    assert result.ok, result.errors
    counted = [a["issuer"] for a in result.checks["approvals"] if a["counted"]]
    assert sorted(counted) == ["build2", "qa"]


def test_interrupted_finalize_exposes_nothing_and_old_collection_survives(store):
    _, reg, keys, crl, _ = store
    candidate_v1 = _candidate(store)
    approvals_v1 = [_approve(store, candidate_v1, "build"),
                    _approve(store, candidate_v1, "qa")]
    record_v1 = _finalize(store, candidate_v1, approvals_v1)

    # A second release attempt is interrupted (quorum never met).
    candidate_v2 = _candidate(store, policy=ReleasePolicy("standard", 2,
                                                          {"build": 1, "qa": 1}))
    with pytest.raises(ValueError):
        _finalize(store, candidate_v2, [], now=LATER)
    collections = reg.read_index()["collections"]
    assert [c["collection_release_id"] for c in collections] == [
        record_v1["collection_release_id"]
    ]
    # The old collection is still fully verifiable afterwards.
    result = Verifier(keys, crl).verify_collection(
        record_v1, resolve_content=_resolver(reg), now=LATER
    )
    assert result.ok, result.errors


def test_offline_verify_reports_exactly_what_is_missing(store):
    _, reg, keys, crl, _ = store
    candidate = _candidate(store)
    record = _finalize(store, candidate, [_approve(store, candidate, "build"),
                                          _approve(store, candidate, "qa")])

    def broken_resolver(digest):
        path = reg.artifact_path(digest)
        if not reg.has_artifact(digest):
            return None
        # Pretend the lib artifact never arrived at the receiver.
        with open(path, "rb") as f:
            if f.read() == b"lib binary v1.3":
                return None
        return path

    result = Verifier(keys, crl).verify_collection(
        record, resolve_content=broken_resolver, now=LATER
    )
    assert not result.ok
    assert any("lib:1.3" in m for m in result.checks["missing_trust"])

    # And when a required role approval is absent from the bundle:
    record["approvals"] = [a for a in record["approvals"]
                           if a["approval"]["role"] != "qa"]
    result = Verifier(keys, crl).verify_collection(
        record, resolve_content=_resolver(reg), now=LATER
    )
    assert not result.ok
    assert any("role qa" in e for e in result.errors)


def test_collection_comparison_reports_content_dependencies_and_approval_gaps(store):
    tmp_path, reg, keys, crl, files = store
    old_candidate = _candidate(store)
    old_record = _finalize(
        store, old_candidate,
        [_approve(store, old_candidate, "build"),
         _approve(store, old_candidate, "qa")],
    )

    replaced = tmp_path / "app-2.0-hotfix.tar"
    replaced.write_bytes(b"app binary v2 HOTFIX")
    files["app"] = (str(replaced), files["app"][1])
    new_candidate = _candidate(store)

    report = build_collection_comparison(old_record, new_candidate)
    assert report["old_collection"]["collection_release_id"] == (
        old_record["collection_release_id"]
    )
    assert report["new_collection"]["kind"] == "collection_candidate"
    assert report["new_collection"]["spec_digest"] == new_candidate["spec_digest"]

    replacements = report["content_changes"]["replaced"]
    assert [item["member"] for item in replacements] == ["app:2.0"]
    assert replacements[0]["changed_fields"] == ["artifact_digest"]
    assert any(item["member"] == "lib:1.3"
               for item in report["content_changes"]["unchanged"])

    shared = report["dependency_changes"]["shared_dependencies"]
    assert any(item["member"] == "lib:1.3" and
               item["depended_on_by"] == ["app:2.0", "plugA:1.0"]
               for item in shared)
    assert any("plugA:1.0" in cycle and "plugB:1.0" in cycle
               for cycle in report["dependency_changes"]["new_cycles"])

    assessed = report["old_approval_assessment"]
    assert {item["role"] for item in assessed} == {"build", "qa"}
    assert all(not item["applicable_to_new_collection"] for item in assessed)
    assert all(item["carryover_count"] == 0 for item in assessed)
    gaps = {item["role"]: item for item in report["required_new_approvals"]}
    assert gaps["build"]["missing_new_approvals"] == 1
    assert gaps["qa"]["missing_new_approvals"] == 1
    assert gaps["build"]["usable_old_approvals"] == 0
    assert not report["inheritance"]["published_collections_modified"]

    # The old published record remains byte-for-byte intact and verifiable.
    assert Verifier(keys, crl).verify_collection(
        old_record, resolve_content=_resolver(reg), now=LATER
    ).ok


def test_collection_comparison_between_two_releases_does_not_inherit_approvals(store):
    _, reg, keys, crl, files = store
    old_candidate = _candidate(store)
    old_record = _finalize(
        store, old_candidate,
        [_approve(store, old_candidate, "build"),
         _approve(store, old_candidate, "qa")],
    )

    # A new release gets fresh approvals on its own new candidate.
    members = _members(files)
    members[0]["depends_on"] = []
    new_candidate = _candidate(store, members=members)
    new_record = _finalize(
        store, new_candidate,
        [_approve(store, new_candidate, "build"),
         _approve(store, new_candidate, "qa")],
    )
    report = build_collection_comparison(old_record, new_record)
    assert report["dependency_changes"]["removed"] == [
        {"from": "app:2.0", "to": "lib:1.3"}
    ]
    assert all(not item["applicable_to_new_collection"]
               for item in report["old_approval_assessment"])
    assert all(item["missing_new_approvals"] == 0
               for item in report["required_new_approvals"])
    assert len(reg.read_index()["collections"]) == 2
    assert Verifier(keys, crl).verify_collection(
        old_record, resolve_content=_resolver(reg), now=LATER
    ).ok
