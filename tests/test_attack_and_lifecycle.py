"""Additional adversarial and lifecycle checks for trusted release."""

import json

import pytest

from trusted_release import (
    IssuerKeyStore,
    Publisher,
    Registry,
    RevocationList,
    TrustPolicy,
    Verifier,
)

NOW = "2026-01-01T00:00:00Z"
LATER = "2026-06-01T00:00:00Z"
FUTURE = "2028-01-01T00:00:00Z"


@pytest.fixture()
def env(tmp_path):
    registry = Registry(str(tmp_path / "registry"))
    keys = IssuerKeyStore(str(tmp_path / "issuers"))
    crl = RevocationList(str(tmp_path / "crl"))
    artifact = tmp_path / "widget-1.0.tar.gz"
    spec = tmp_path / "BUILD.md"
    artifact.write_bytes(b"widget binary contents v1")
    spec.write_bytes(b"# build instructions\nmake\n")
    keys.create_key("build-team", scope="product:widget", now=NOW)
    return tmp_path, registry, keys, crl, artifact, spec


def _publish(env, **overrides):
    _, registry, keys, _, artifact, spec = env
    params = dict(
        artifact_path=str(artifact),
        build_spec_path=str(spec),
        product="widget",
        version="1.0",
        issuer_id="build-team",
        now=NOW,
        validity_days=365,
    )
    params.update(overrides)
    return Publisher(registry, keys).publish(**params)


def test_attestation_fields_all_protected_by_signature(env):
    *_, keys, crl, _, _ = env
    record = _publish(env)
    for field in ("issuer_id", "scope", "expires_at", "release_id"):
        forged = json.loads(json.dumps(record))
        value = forged["attestation"][field]
        forged["attestation"][field] = value + "x" if isinstance(value, str) else 99
        result = Verifier(keys, crl).verify_release(
            forged,
            artifact_path=str(env[4]),
            build_spec_path=str(env[5]),
            now=NOW,
        )
        assert not result.ok
        # Every tampered signed field must be caught (sig, scope or trust).
        assert result.errors


def test_signature_from_other_release_rejected(env):
    tmp, registry, keys, crl, artifact, spec = env
    r1 = _publish(env)
    other_artifact = tmp / "w2.bin"
    other_artifact.write_bytes(b"different widget payload")
    r2 = Publisher(registry, keys).publish(
        artifact_path=str(other_artifact),
        build_spec_path=str(spec),
        product="widget",
        version="2.0",
        issuer_id="build-team",
        now=NOW,
    )
    forged = json.loads(json.dumps(r1))
    forged["signature"] = r2["signature"]
    result = Verifier(keys, crl).verify_release(
        forged,
        artifact_path=str(artifact),
        build_spec_path=str(spec),
        now=NOW,
    )
    assert not result.ok


def test_unknown_issuer_key_is_not_trusted(env):
    *_, keys, crl, artifact, spec = env
    record = _publish(env)
    store2 = IssuerKeyStore(str(env[0] / "other-issuers"))
    store2.create_key("build-team", scope="product:widget", now=NOW)
    result = Verifier(store2, crl).verify_release(
        record,
        artifact_path=str(artifact),
        build_spec_path=str(spec),
        now=NOW,
    )
    assert not result.ok
    assert any(
        ("not found in current trust store" in e)
        or ("signature verification failed" in e)
        for e in result.errors
    )


def test_publish_without_key_fails_without_index(env):
    tmp, registry, _, _, artifact, spec = env
    with pytest.raises(Exception):
        Publisher(registry, IssuerKeyStore(str(tmp / "nokey"))).publish(
            artifact_path=str(artifact),
            build_spec_path=str(spec),
            product="widget",
            version="9.9",
            issuer_id="nobody",
            now=NOW,
        )
    assert registry.read_index()["releases"] == []


def test_missing_files_abort_before_index(env):
    tmp, registry, _, _, artifact, spec = env
    keys = IssuerKeyStore(str(tmp / "issuers2"))
    keys.create_key("build-team", scope="product:widget", now=NOW)
    with pytest.raises(FileNotFoundError):
        Publisher(registry, keys).publish(
            artifact_path=str(tmp / "missing.bin"),
            build_spec_path=str(spec),
            product="widget",
            version="1.0",
            issuer_id="build-team",
            now=NOW,
        )
    assert registry.read_index()["releases"] == []


def test_glob_scope_key_covers_all_products(env, tmp_path):
    tmp, registry, keys, crl, artifact, spec = env
    keys.create_key("security-office", scope="*", now=NOW)
    record = Publisher(registry, keys).publish(
        artifact_path=str(artifact),
        build_spec_path=str(spec),
        product="gadget",
        version="1.0",
        issuer_id="security-office",
        now=NOW,
    )
    result = Verifier(keys, crl).verify_release(
        record,
        artifact_path=str(artifact),
        build_spec_path=str(spec),
        now=NOW,
        expected_product="gadget",
    )
    assert result.ok, result.errors


def test_key_validity_window_expires(env):
    tmp, registry, keys, crl, artifact, spec = env
    keys.create_key(
        "short-lived", scope="product:widget", now=NOW, valid_to=LATER
    )
    record = Publisher(registry, keys).publish(
        artifact_path=str(artifact),
        build_spec_path=str(spec),
        product="widget",
        version="3.0",
        issuer_id="short-lived",
        now=NOW,
    )
    assert Verifier(keys, crl).verify_release(
        record,
        artifact_path=str(artifact),
        build_spec_path=str(spec),
        now=NOW,
    ).ok
    result = Verifier(keys, crl).verify_release(
        record,
        artifact_path=str(artifact),
        build_spec_path=str(spec),
        now=LATER,
    )
    assert not result.ok
    assert any("window" in e for e in result.errors)


def test_tampered_crl_fails_closed(env):
    *_, keys, crl, artifact, spec = env
    keys.create_key("security-office", scope="*", now=NOW)
    record = _publish(env)
    seed = keys.load_secret("security-office", 1)
    crl.issue(
        revoked={},
        reason="ok",
        now=NOW,
        issuer_id="security-office",
        key_version=1,
        secret_seed=seed,
    )
    snapshot_path = crl.read_version(1) and crl._snapshot_path(1)
    data = json.loads(open(snapshot_path, encoding="utf-8").read())
    data["body"]["revoked"] = {"build-team": [1]}
    open(snapshot_path, "w", encoding="utf-8").write(json.dumps(data))
    result = Verifier(keys, crl).verify_release(
        record,
        artifact_path=str(artifact),
        build_spec_path=str(spec),
        now=NOW,
    )
    assert not result.ok
    assert any("revocation list failed" in e for e in result.errors)


def test_history_remains_listed_after_rotation_and_revocation(env):
    _, registry, keys, crl, artifact, spec = env
    record = _publish(env)
    keys.create_key("security-office", scope="*", now=NOW)
    keys.set_status("build-team", 1, "revoked")
    seed = keys.load_secret("security-office", 1)
    crl.issue(
        revoked={"build-team": [1]},
        reason="compromise",
        now=LATER,
        issuer_id="security-office",
        key_version=1,
        secret_seed=seed,
    )
    assert record["release_id"] in registry.list_release_ids()
    assert (
        registry.read_index()["releases"][0]["release_id"]
        == record["release_id"]
    )
    stored = registry.read_release(record["release_id"])
    assert stored["signature"] == record["signature"]
