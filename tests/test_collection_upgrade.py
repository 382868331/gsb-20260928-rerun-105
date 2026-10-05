from trusted_release import IssuerKeyStore, Publisher, Registry, RevocationList
from trusted_release.encoding import file_digest
from trusted_release.policy import ReleasePolicy
from trusted_release.upgrade import plan_collection_upgrade

NOW = "2026-01-01T00:00:00Z"
CONFIRM = "2026-02-01T00:00:00Z"
POLICY = ReleasePolicy("standard", 1, {"build": 1, "qa": 1})


def _artifact(tmp_path, name, content, requires=None, conflicts=None):
    artifact = tmp_path / f"{name}.tar"
    build = tmp_path / f"{name}.build"
    artifact.write_bytes(content)
    build.write_text(f"build {name}", encoding="utf-8")
    result = {
        "artifact_digest": file_digest(str(artifact)),
        "build_spec_digest": file_digest(str(build)),
        "artifact_path": str(artifact),
        "build_spec_path": str(build),
        "requires": requires or {},
    }
    if conflicts:
        result["conflicts"] = conflicts
    return result


def _catalog(tmp_path):
    products = {
        ("app", "1.0"): _artifact(tmp_path, "app-1.0", b"app 1", {"lib": ">=1,<2"}),
        ("app", "2.0"): _artifact(
            tmp_path, "app-2.0", b"app 2", {"lib": ">=2,<3"},
            conflicts=[{"product": "plugin", "version": "1.0"}],
        ),
        ("plugin", "1.0"): _artifact(
            tmp_path, "plugin-1.0", b"plugin 1",
            {"lib": ">=1,<2", "bridge": "1.0"},
        ),
        ("lib", "1.0"): _artifact(tmp_path, "lib-1.0", b"lib 1"),
        ("lib", "1.3"): _artifact(tmp_path, "lib-1.3", b"lib 1.3"),
        ("lib", "2.0"): _artifact(tmp_path, "lib-2.0", b"lib 2"),
        ("bridge", "1.0"): _artifact(
            tmp_path, "bridge-1.0", b"bridge 1", {"plugin": "1.0"}
        ),
    }
    catalog = []
    for (product, version), body in products.items():
        catalog.append({"product": product, "version": version, **body})
    return catalog


def _store(tmp_path):
    keys = IssuerKeyStore(str(tmp_path / "keys"))
    reg = Registry(str(tmp_path / "registry"))
    crl = RevocationList(str(tmp_path / "crl"))
    keys.create_key("sec", scope="*", now=NOW)
    keys.create_key("build", scope="*", role="build", now=NOW)
    keys.create_key("qa", scope="*", role="qa", now=NOW)
    return reg, keys, crl


def _approve(reg, keys, candidate):
    publisher = Publisher(reg, keys)
    return [
        publisher.approve_collection(candidate, issuer_id="build", now=NOW),
        publisher.approve_collection(candidate, issuer_id="qa", now=NOW),
    ]


def test_shared_dependency_and_cycle_are_one_global_constraint(tmp_path):
    catalog = _catalog(tmp_path)
    plan = plan_collection_upgrade(
        name="platform", version="2026.10", artifacts=catalog,
        targets=["app:1.0", "plugin:1.0"], policy=POLICY, now=NOW,
    )

    assert plan["recommendation"]["maximum_target_coverage"] == 2
    option = plan["options"][0]
    assert option["technically_compatible"] is True
    assert option["approvals_complete"] is False
    selected = {(m["product"], m["version"]) for m in option["members"]}
    assert ("lib", "1.3") in selected
    assert ("lib", "2.0") not in selected
    assert any(d["product"] == "lib" for d in option["shared_dependencies"])
    cycle_products = {
        item.split(":", 1)[0] for item in option["cycles"][0]
    }
    assert cycle_products == {"bridge", "plugin"}
    assert option["missing_approval_roles"] == {"build": 1, "qa": 1}


def test_unsatisfiable_shared_range_and_mutex_falls_back_to_single_targets(tmp_path):
    catalog = _catalog(tmp_path)
    plan = plan_collection_upgrade(
        name="platform", version="2026.10", artifacts=catalog,
        targets=["app:2.0", "plugin:1.0"], policy=POLICY, now=NOW,
    )

    assert plan["options"]
    assert plan["recommendation"]["maximum_target_coverage"] == 1
    infeasible = plan["infeasible"][0]
    assert infeasible["targets"] == ["app:2.0", "plugin:1.0"]
    assert any("lib" in reason for reason in infeasible["reasons"])
    assert any("conflicts" in reason for reason in infeasible["reasons"])
    app_option = next(o for o in plan["options"] if o["covered_targets"] == ["app:2.0"])
    plugin_option = next(o for o in plan["options"] if o["covered_targets"] == ["plugin:1.0"])
    assert any(m["product"] == "lib" and m["version"] == "2.0"
               for m in app_option["members"])
    assert any(m["product"] == "lib" and m["version"] == "1.3"
               for m in plugin_option["members"])


def test_confirmation_rechecks_candidate_binding_and_current_approvals(tmp_path):
    reg, keys, crl = _store(tmp_path)
    catalog = _catalog(tmp_path)
    plan = plan_collection_upgrade(
        name="platform", version="2026.10", artifacts=catalog,
        targets=["app:2.0", "plugin:1.0"], policy=POLICY, now=NOW,
    )
    plugin_option = next(
        o for o in plan["options"] if o["covered_targets"] == ["plugin:1.0"]
    )
    app_option = next(
        o for o in plan["options"] if o["covered_targets"] == ["app:2.0"]
    )
    plugin_approvals = _approve(reg, keys, plugin_option["candidate"])
    publisher = Publisher(reg, keys, crl)
    preview = publisher.preview_collection_upgrade(
        name="platform", version="2026.10", artifacts=catalog,
        targets=["app:2.0", "plugin:1.0"], policy=POLICY, now=NOW,
        available_approvals=plugin_approvals,
    )
    preview_app = next(
        o for o in preview["options"]
        if o["covered_targets"] == ["app:2.0"]
    )
    preview_plugin = next(
        o for o in preview["options"]
        if o["covered_targets"] == ["plugin:1.0"]
    )
    assert preview_app["technically_compatible"] is True
    assert preview_app["approvals_complete"] is False
    assert preview_plugin["approvals_complete"] is True
    assert preview_app["invalid_approvals"]

    try:
        publisher.confirm_collection_upgrade(
            plan, plugin_approvals, now=CONFIRM, option_id=app_option["option_id"]
        )
    except ValueError as exc:
        assert "role build" in str(exc)
    else:
        raise AssertionError("approvals from another candidate were accepted")

    app_approvals = _approve(reg, keys, app_option["candidate"])
    record = publisher.confirm_collection_upgrade(
        plan, app_approvals, now=CONFIRM, option_id=app_option["option_id"]
    )
    assert record["candidate_digest"] == app_option["candidate"]["candidate_digest"]

    before = len(reg.read_index()["collections"])
    again = publisher.confirm_collection_upgrade(
        plan, app_approvals, now="2026-03-01T00:00:00Z",
        option_id=app_option["option_id"],
    )
    assert again == record
    assert len(reg.read_index()["collections"]) == before
