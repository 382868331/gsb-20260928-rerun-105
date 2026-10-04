"""Collection version comparison reports: content/dependency/policy
diffs, stale-approval explanation, and read-only guarantees."""

import json

import pytest

from trusted_release import (
    IssuerKeyStore,
    Publisher,
    Registry,
    RevocationList,
)
from trusted_release.compare import compare_collections
from trusted_release.policy import ReleasePolicy

NOW = "2026-01-01T00:00:00Z"
LATER = "2026-02-01T00:00:00Z"
REPORT_TIME = "2026-03-01T00:00:00Z"

POLICY = ReleasePolicy("standard", 1, {"build": 1, "qa": 1})


@pytest.fixture()
def store(tmp_path):
    reg = Registry(str(tmp_path / "registry"))
    keys = IssuerKeyStore(str(tmp_path / "issuers"))
    crl = RevocationList(str(tmp_path / "crl"))
    keys.create_key("sec", scope="*", now=NOW)
    keys.create_key("build", scope="*", role="build", now=NOW)
    keys.create_key("qa", scope="*", role="qa", now=NOW)
    keys.create_key("secops", scope="*", role="secops", now=NOW)

    def make(name, content):
        p = tmp_path / name
        p.write_bytes(content)
        return str(p)

    files = {
        "app": (make("app.tar", b"app binary v2"), make("APP.BUILD", b"build app")),
        "lib": (make("lib.tar", b"lib binary v1.3"), make("LIB.BUILD", b"build lib")),
        "plugA": (make("pa.tar", b"plugin A"), make("PA.BUILD", b"build A")),
        "plugB": (make("pb.tar", b"plugin B"), make("PB.BUILD", b"build B")),
    }
    return tmp_path, reg, keys, crl, files


def _members(files, app_content=None):
    app_art, app_spec = files["app"]
    lib_art, lib_spec = files["lib"]
    pa_art, pa_spec = files["plugA"]
    pb_art, pb_spec = files["plugB"]
    return [
        {"product": "app", "version": "2.0",
         "artifact_path": app_art, "build_spec_path": app_spec,
         "depends_on": [{"product": "lib", "version": "1.3"}]},
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


def _publish(store, members, policy=POLICY, version="2026.10", now=LATER):
    _, reg, keys, crl, _ = store
    pub = Publisher(reg, keys)
    candidate = pub.create_collection_candidate(
        name="platform", version=version, members=members,
        policy=policy, now=NOW,
    )
    issuers = {"build": "build", "qa": "qa", "secops": "secops"}
    approvals = [
        pub.approve_collection(candidate, issuer_id=issuers[role], now=NOW)
        for role in policy.requirements
    ]
    return Publisher(reg, keys, crl).finalize_collection(
        candidate, approvals, now=now
    )


def test_compare_single_artifact_replacement(store):
    tmp_path, reg, keys, crl, files = store
    old = _publish(store, _members(files))
    # Replace exactly one artifact: app gets a hotfix.
    app_art, app_spec = files["app"]
    with open(app_art, "wb") as f:
        f.write(b"app binary v2 HOTFIX")
    new = _publish(store, _members(files), version="2026.11")

    old_snapshot = json.dumps(old, sort_keys=True)
    new_snapshot = json.dumps(new, sort_keys=True)
    report = compare_collections(old, new, now=REPORT_TIME)

    assert report["type"] == "trusted-release/collection-compare/v1"
    # Report links to both collection summaries.
    assert report["old"]["collection_release_id"] == old["collection_release_id"]
    assert report["new"]["collection_release_id"] == new["collection_release_id"]
    assert report["old"]["spec_digest"] == old["spec_digest"]
    assert report["new"]["candidate_digest"] == new["candidate_digest"]

    cc = report["content_changes"]
    assert cc["added"] == [] and cc["removed"] == []
    assert [r["product"] for r in cc["replaced"]] == ["app"]
    assert cc["replaced"][0]["artifact_changed"] is True
    assert cc["replaced"][0]["build_spec_changed"] is False
    assert len(cc["unchanged"]) == 3

    # Every old approval is explained as stale; none is inherited.
    stale = report["approval_analysis"]["stale_approvals"]
    assert len(stale) == len(old["approvals"])
    assert all("candidate_digest" in s["reason"] for s in stale)
    assert {s["role"] for s in stale} == {"build", "qa"}
    assert new["approvals"] is not report["approval_analysis"]["stale_approvals"]

    # New policy roles must be collected fresh.
    to_collect = report["approval_analysis"]["approvals_to_collect"]
    assert {t["role"] for t in to_collect} == {"build", "qa"}
    assert all(t["required"] == 1 for t in to_collect)

    # Read-only: neither published record was rewritten.
    assert json.dumps(old, sort_keys=True) == old_snapshot
    assert json.dumps(new, sort_keys=True) == new_snapshot


def test_compare_dependency_and_policy_changes(store):
    _, _, _, _, files = store
    old = _publish(store, _members(files))
    # New collection: drop the plugA<->plugB cycle, add app->plugA edge,
    # and require an extra secops role under a new policy version.
    members = _members(files)
    for m in members:
        if m["product"] == "plugB":
            m["depends_on"] = []
        if m["product"] == "app":
            m["depends_on"].append({"product": "plugA", "version": "1.0"})
    new_policy = ReleasePolicy("standard", 2, {"build": 1, "qa": 1, "secops": 1})
    new = _publish(store, members, policy=new_policy, version="2026.11")

    report = compare_collections(old, new, now=REPORT_TIME)
    dc = report["dependency_changes"]
    assert "app:2.0 -> plugA:1.0" in dc["added_edges"]
    assert "plugB:1.0 -> plugA:1.0" in dc["removed_edges"]
    # Shared dependency on lib is visible on both sides.
    assert any(s["product"] == "lib" for s in dc["shared_dependencies_old"])
    assert any(s["product"] == "lib" for s in dc["shared_dependencies_new"])
    # Cycle existed before, gone after.
    assert any("plugA:1.0" in c for c in dc["cycles_old"])
    assert dc["cycles_new"] == []

    pc = report["policy_changes"]
    assert pc["policy_version"] == {"old": 1, "new": 2}
    assert pc["requirements_added"] == {"secops": 1}
    assert pc["requirements_unchanged"] == {"build": 1, "qa": 1}

    stale = report["approval_analysis"]["stale_approvals"]
    assert any("policy_digest" in s["reason"] for s in stale)
    roles = {t["role"] for t in report["approval_analysis"]["approvals_to_collect"]}
    assert roles == {"build", "qa", "secops"}


def test_compare_rejects_non_collection_record(store):
    _, _, _, _, files = store
    record = _publish(store, _members(files))
    with pytest.raises(ValueError, match="not a collection release"):
        compare_collections(record, {"type": "trusted-release/release/v1"},
                            now=REPORT_TIME)


def test_compare_report_is_deterministic_and_offline_savable(store, tmp_path):
    _, _, _, _, files = store
    old = _publish(store, _members(files))
    new = _publish(store, _members(files), version="2026.11")
    r1 = compare_collections(old, new, now=REPORT_TIME)
    r2 = compare_collections(old, new, now=REPORT_TIME)
    assert r1 == r2
    assert r1["report_id"]
    path = tmp_path / "report.json"
    path.write_text(json.dumps(r1, indent=2, sort_keys=True))
    loaded = json.loads(path.read_text())
    assert loaded["report_id"] == r1["report_id"]

