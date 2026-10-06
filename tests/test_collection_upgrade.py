"""Compatible upgrade combination selection and confirmation."""

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
POLICY = ReleasePolicy("standard", 1, {"build": 1, "qa": 1})


@pytest.fixture()
def store(tmp_path):
    reg = Registry(str(tmp_path / "registry"))
    keys = IssuerKeyStore(str(tmp_path / "issuers"))
    crl = RevocationList(str(tmp_path / "crl"))
    keys.create_key("sec", scope="*", now=NOW)
    keys.create_key("build", scope="*", role="build", now=NOW)
    keys.create_key("qa", scope="*", role="qa", now=NOW)

    def make(name, content):
        path = tmp_path / name
        path.write_bytes(content)
        return str(path)

    files = {
        ("appA", "1.0"): (make("a1", b"A1"), make("a1.build", b"BA1")),
        ("appA", "2.0"): (make("a2", b"A2"), make("a2.build", b"BA2")),
        ("appB", "1.0"): (make("b1", b"B1"), make("b1.build", b"BB1")),
        ("appB", "2.0"): (make("b2", b"B2"), make("b2.build", b"BB2")),
        ("lib", "1.0"): (make("l1", b"L1"), make("l1.build", b"BL1")),
        ("lib", "1.3"): (make("l13", b"L13"), make("l13.build", b"BL13")),
        ("lib", "1.5"): (make("l15", b"L15"), make("l15.build", b"BL15")),
        ("lib", "2.1"): (make("l21", b"L21"), make("l21.build", b"BL21")),
        ("lib", "3.0"): (make("l30", b"L30"), make("l30.build", b"BL30")),
        ("plugA", "1.0"): (make("pa1", b"PA1"), make("pa1.build", b"BPA1")),
        ("plugB", "1.0"): (make("pb1", b"PB1"), make("pb1.build", b"BPB1")),
        ("app", "2.0"): (make("app2", b"APP2"), make("app2.build", b"BAPP2")),
        ("app", "2.1"): (make("app21", b"APP21"), make("app21.build", b"BAPP21")),
    }
    return tmp_path, reg, keys, crl, files


def _digest_candidate(store, product, version, requires=None, conflicts=None):
    _, reg, _, _, files = store
    artifact, build_spec = files[(product, version)]
    manifest = reg.register_artifact(
        source_path=artifact, product=product, version=version,
        build_spec_path=build_spec, now=NOW,
    )
    return {
        "product": product,
        "version": version,
        "artifact_digest": manifest["artifact_digest"],
        "build_spec_digest": manifest["build_spec_digest"],
        "requires": requires or [],
        "conflicts_with": conflicts or [],
    }


def _members(candidates, dependencies):
    by_key = {(c["product"], c["version"]): c for c in candidates}
    members = []
    for key, candidate in by_key.items():
        members.append({
            "product": key[0],
            "version": key[1],
            "artifact_digest": candidate["artifact_digest"],
            "build_spec_digest": candidate["build_spec_digest"],
            "depends_on": [
                {"product": p, "version": v} for p, v in dependencies.get(key, [])
            ],
        })
    return members


def _approve(store, candidate, issuer):
    _, reg, keys, _, _ = store
    return Publisher(reg, keys).approve_collection(
        candidate, issuer_id=issuer, now=NOW
    )


def _finalize(store, candidate, approvals):
    _, reg, keys, crl, _ = store
    return Publisher(reg, keys, crl).finalize_collection(
        candidate, approvals, now=LATER
    )


def test_two_targets_contend_for_one_shared_dependency(store):
    _, reg, keys, crl, files = store
    current_candidates = [
        _digest_candidate(store, "appA", "1.0"),
        _digest_candidate(store, "appB", "1.0"),
        _digest_candidate(store, "lib", "1.0"),
    ]
    current_members = _members(current_candidates, {
        ("appA", "1.0"): [("lib", "1.0")],
        ("appB", "1.0"): [("lib", "1.0")],
    })
    old = Publisher(reg, keys).create_collection_candidate(
        name="platform", version="2026.01", members=current_members,
        policy=POLICY, now=NOW,
    )
    _finalize(store, old, [_approve(store, old, "build"), _approve(store, old, "qa")])

    candidates = [
        _digest_candidate(store, "appA", "2.0",
                          requires=[{"product": "lib", "specifier": ">=1.0,<2.0"}]),
        _digest_candidate(store, "appB", "2.0",
                          requires=[{"product": "lib", "specifier": ">=2.0,<3.0"}]),
        _digest_candidate(store, "lib", "1.5"),
        _digest_candidate(store, "lib", "2.1"),
    ]
    plan = Publisher(reg, keys, crl).preview_collection_upgrade(
        name="platform", version="2026.02", candidates=candidates,
        targets=[("appA", "2.0"), ("appB", "2.0")],
        policy=POLICY, now=NOW, current_collection=None,
    )

    assert plan["feasible"] is False
    full = [o for o in plan["options"] if o["coverage_count"] == 2]
    assert full == []
    assert plan["maximum_coverage"]["coverage_count"] == 1
    assert plan["maximum_coverage"]["change_count"] == 2
    libs = {
        tuple(o["targets"]): [v for v in o["selected"] if v.startswith("lib:")]
        for o in plan["options"]
    }
    assert libs[("appA:2.0",)] == ["lib:1.5"]
    assert libs[("appB:2.0",)] == ["lib:2.1"]
    assert any("appA:2.0 requires lib >=1.0,<2.0" in x["reason"]
               for x in plan["unsatisfied_constraints"])
    assert any("appB:2.0 requires lib >=2.0,<3.0" in x["reason"]
               for x in plan["unsatisfied_constraints"])


def test_no_range_intersection_has_no_combination(store):
    _, reg, keys, _, _ = store
    candidates = [
        _digest_candidate(store, "appA", "2.0",
                          requires=[{"product": "lib", "specifier": ">=3.0,<4.0"}]),
        _digest_candidate(store, "lib", "1.5"),
        _digest_candidate(store, "lib", "2.1"),
    ]
    plan = Publisher(reg, keys).preview_collection_upgrade(
        name="platform", version="2026.02", candidates=candidates,
        targets=[("appA", "2.0")], policy=POLICY, now=NOW,
    )
    assert plan["feasible"] is False
    assert plan["options"] == []
    assert plan["recommended"] is None
    assert any("lib >=3.0,<4.0" in x["reason"]
               for x in plan["unsatisfied_constraints"])


def test_single_member_replacement_keeps_cycle_and_requires_new_approvals(store):
    _, reg, keys, crl, files = store
    current_candidates = [
        _digest_candidate(store, "app", "2.0"),
        _digest_candidate(store, "lib", "1.3"),
        _digest_candidate(store, "plugA", "1.0"),
        _digest_candidate(store, "plugB", "1.0"),
    ]
    current_members = _members(current_candidates, {
        ("app", "2.0"): [("lib", "1.3")],
        ("plugA", "1.0"): [("plugB", "1.0"), ("lib", "1.3")],
        ("plugB", "1.0"): [("plugA", "1.0")],
    })
    pub = Publisher(reg, keys, crl)
    old_candidate = pub.create_collection_candidate(
        name="platform", version="2026.01", members=current_members,
        policy=POLICY, now=NOW,
    )
    old_approvals = [_approve(store, old_candidate, "build"),
                     _approve(store, old_candidate, "qa")]
    old = _finalize(store, old_candidate, old_approvals)

    upgraded = _digest_candidate(
        store, "app", "2.1",
        requires=[{"product": "lib", "specifier": "==1.3"}],
    )
    preview = pub.preview_collection_upgrade(
        name="platform", version="2026.02", candidates=[upgraded],
        targets=[("app", "2.1")], policy=POLICY, now=NOW,
        current_collection=old,
    )
    option = preview["recommended"]
    assert option["technically_compatible"] is True
    assert option["approval_state"]["approvals_complete"] is False
    assert {x["role"] for x in option["approval_state"]["missing_roles"]} == {
        "build", "qa"
    }
    selected = option["candidate"]["spec"]["members"]
    edges = {
        (m["product"], d["product"])
        for m in selected for d in m["depends_on"]
    }
    assert ("plugA", "plugB") in edges
    assert ("plugB", "plugA") in edges
    assert preview["publish_ready_options"] == []

    new_approvals = [
        _approve(store, option["candidate"], "build"),
        _approve(store, option["candidate"], "qa"),
    ]
    # Approvals collected for another candidate cannot be substituted now.
    other = pub.create_collection_candidate(
        name="platform", version="2026.02",
        members=[dict(m, artifact_digest=upgraded["artifact_digest"],
                      build_spec_digest=upgraded["build_spec_digest"])
                 if m["product"] == "app" else m for m in option["members"]],
        policy=POLICY, now=NOW,
    )
    wrong = [_approve(store, other, "build"), _approve(store, other, "qa")]
    with pytest.raises(ValueError, match="insufficient valid distinct issuers"):
        pub.confirm_collection_upgrade(preview, selection_id=option["id"],
                                       approvals=wrong, now=LATER)

    record = pub.confirm_collection_upgrade(
        preview, selection_id=option["id"],
        approvals=old_approvals + new_approvals, now=LATER,
    )
    result = Verifier(keys, crl).verify_collection(
        record,
        resolve_content=lambda digest: reg.artifact_path(digest)
        if reg.has_artifact(digest) else None,
        now=LATER,
    )
    assert result.ok, result.errors
    indexed = reg.read_index()["collections"]
    assert [x["collection_release_id"] for x in indexed] == [
        old["collection_release_id"], record["collection_release_id"]
    ]


def test_unchanged_selection_stays_with_current_published_collection(store):
    _, reg, keys, crl, _ = store
    current_candidates = [
        _digest_candidate(
            store, "app", "2.0",
            requires=[{"product": "lib", "specifier": "==1.0"}],
        ),
        _digest_candidate(store, "lib", "1.0"),
    ]
    members = _members(current_candidates, {
        ("app", "2.0"): [("lib", "1.0")],
    })
    pub = Publisher(reg, keys, crl)
    candidate = pub.create_collection_candidate(
        name="platform", version="2026.01", members=members,
        policy=POLICY, now=NOW,
    )
    old = _finalize(store, candidate, [
        _approve(store, candidate, "build"),
        _approve(store, candidate, "qa"),
    ])
    preview = pub.preview_collection_upgrade(
        name="platform", version="2026.01", candidates=current_candidates,
        targets=[("app", "2.0")], policy=POLICY, now=NOW,
        current_collection=old,
    )
    option = preview["recommended"]
    assert option["already_published"] is True
    assert preview["publish_ready_options"] == []
    with pytest.raises(ValueError, match="already published"):
        pub.confirm_collection_upgrade(
            preview, selection_id=option["id"],
            approvals=old["approvals"], now=LATER,
        )
    assert len(reg.read_index()["collections"]) == 1
