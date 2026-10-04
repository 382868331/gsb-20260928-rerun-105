"""Command line interface for the trusted release system.

All operations work offline and only use the Python standard library.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys

from .attestation import RevocationList, verify_signature
from .issuer import IssuerKeyStore
from .publisher import Publisher, utc_now
from .registry import Registry
from .verifier import TrustPolicy, Verifier, load_bundle
from .policy import ReleasePolicy


def _store_paths(home: str):
    return (
        os.path.join(home, "registry"),
        os.path.join(home, "issuers"),
        os.path.join(home, "crl"),
    )


def cmd_init(args) -> int:
    reg_dir, key_dir, crl_dir = _store_paths(args.home)
    Registry(reg_dir)
    IssuerKeyStore(key_dir)
    RevocationList(crl_dir)
    print(f"initialized trusted release store at {args.home}")
    return 0


def cmd_key_create(args) -> int:
    keystore = IssuerKeyStore(os.path.join(args.home, "issuers"))
    rec = keystore.create_key(
        issuer_id=args.issuer,
        scope=args.scope,
        now=args.now or utc_now(),
        valid_to=args.valid_to or "",
        role=args.role,
    )
    print(
        f"issuer={rec.issuer_id} key_version={rec.key_version} "
        f"status={rec.status} scope={rec.scope}"
    )
    return 0


def cmd_key_list(args) -> int:
    keystore = IssuerKeyStore(os.path.join(args.home, "issuers"))
    for r in keystore.list_keys(args.issuer):
        print(json.dumps(r.to_dict(), sort_keys=True))
    return 0


def cmd_publish(args) -> int:
    reg = Registry(os.path.join(args.home, "registry"))
    keys = IssuerKeyStore(os.path.join(args.home, "issuers"))
    pub = Publisher(reg, keys)
    record = pub.publish(
        artifact_path=args.artifact,
        build_spec_path=args.build_spec,
        product=args.product,
        version=args.version,
        issuer_id=args.issuer,
        now=args.now or utc_now(),
        validity_days=args.validity_days,
    )
    print(f"published release_id={record['release_id']}")
    if args.bundle:
        with open(args.bundle, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2, ensure_ascii=False, sort_keys=True)
        print(f"offline bundle written to {args.bundle}")
    return 0


def cmd_candidate(args) -> int:
    reg = Registry(os.path.join(args.home, "registry"))
    keys = IssuerKeyStore(os.path.join(args.home, "issuers"))
    requirements = {}
    for item in args.require:
        role, count = item.split("=", 1)
        requirements[role] = int(count)
    candidate = Publisher(reg, keys).create_candidate(
        artifact_path=args.artifact,
        build_spec_path=args.build_spec,
        product=args.product,
        version=args.version,
        policy=ReleasePolicy(args.policy_id, args.policy_version, requirements),
        now=args.now or utc_now(),
    )
    with open(args.bundle, "w", encoding="utf-8") as f:
        json.dump(candidate, f, indent=2, ensure_ascii=False, sort_keys=True)
    print(f"candidate_id={candidate['candidate_id']} bundle={args.bundle}")
    return 0


def cmd_approve(args) -> int:
    keys = IssuerKeyStore(os.path.join(args.home, "issuers"))
    with open(args.candidate, "r", encoding="utf-8") as f:
        candidate = json.load(f)
    approval = Publisher(Registry(os.path.join(args.home, "registry")), keys).approve_candidate(
        candidate, issuer_id=args.issuer, now=args.now or utc_now(),
        validity_days=args.validity_days,
    )
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(approval, f, indent=2, ensure_ascii=False, sort_keys=True)
    print(f"approval_id={approval['approval_id']} output={args.output}")
    return 0


def cmd_finalize(args) -> int:
    reg = Registry(os.path.join(args.home, "registry"))
    keys = IssuerKeyStore(os.path.join(args.home, "issuers"))
    crl = RevocationList(os.path.join(args.home, "crl"))
    with open(args.candidate, "r", encoding="utf-8") as f:
        candidate = json.load(f)
    approvals = [load_bundle(path) for path in args.approvals]
    record = Publisher(reg, keys, crl).publish_candidate(
        candidate, approvals, now=args.now or utc_now())
    with open(args.bundle, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, ensure_ascii=False, sort_keys=True)
    print(f"published release_id={record['release_id']} bundle={args.bundle}")
    return 0


def _parse_set_members(args) -> list[dict]:
    deps: dict[str, list[str]] = {}
    for item in args.dep or []:
        product, dep = item.split(":", 1)
        deps.setdefault(product, []).append(dep)
    members = []
    for spec in args.member:
        product, version, artifact, build_spec = spec.split(":", 3)
        members.append(
            {
                "product": product,
                "version": version,
                "artifact_path": artifact,
                "build_spec_path": build_spec,
                "depends_on": sorted(deps.get(product, [])),
            }
        )
    return members


def cmd_set_candidate(args) -> int:
    reg = Registry(os.path.join(args.home, "registry"))
    keys = IssuerKeyStore(os.path.join(args.home, "issuers"))
    requirements = {}
    for item in args.require:
        role, count = item.split("=", 1)
        requirements[role] = int(count)
    candidate = Publisher(reg, keys).create_set_candidate(
        name=args.name,
        set_version=args.set_version,
        members=_parse_set_members(args),
        policy=ReleasePolicy(args.policy_id, args.policy_version, requirements),
        now=args.now or utc_now(),
    )
    with open(args.bundle, "w", encoding="utf-8") as f:
        json.dump(candidate, f, indent=2, ensure_ascii=False, sort_keys=True)
    print(f"set_id={candidate['set_id']} bundle={args.bundle}")
    for cycle in candidate["dependency_cycles"]:
        print(f"dependency cycle: {' -> '.join(cycle)}")
    return 0


def cmd_set_approve(args) -> int:
    keys = IssuerKeyStore(os.path.join(args.home, "issuers"))
    with open(args.candidate, "r", encoding="utf-8") as f:
        candidate = json.load(f)
    approval = Publisher(Registry(os.path.join(args.home, "registry")), keys).approve_set_candidate(
        candidate, issuer_id=args.issuer, now=args.now or utc_now(),
        validity_days=args.validity_days,
    )
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(approval, f, indent=2, ensure_ascii=False, sort_keys=True)
    print(f"approval_id={approval['approval_id']} output={args.output}")
    return 0


def cmd_set_finalize(args) -> int:
    reg = Registry(os.path.join(args.home, "registry"))
    keys = IssuerKeyStore(os.path.join(args.home, "issuers"))
    crl = RevocationList(os.path.join(args.home, "crl"))
    with open(args.candidate, "r", encoding="utf-8") as f:
        candidate = json.load(f)
    approvals = [load_bundle(path) for path in args.approvals]
    try:
        record = Publisher(reg, keys, crl).publish_set_candidate(
            candidate, approvals, now=args.now or utc_now())
    except ValueError as exc:
        print(f"set finalize failed: {exc}", file=sys.stderr)
        return 1
    with open(args.bundle, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, ensure_ascii=False, sort_keys=True)
    print(f"published set_id={record['set_id']} bundle={args.bundle}")
    return 0


def cmd_set_verify(args) -> int:
    keys = IssuerKeyStore(os.path.join(args.home, "issuers"))
    crl = RevocationList(os.path.join(args.home, "crl"))
    reg = Registry(os.path.join(args.home, "registry"))
    verifier = Verifier(keys, crl, TrustPolicy(trust_rotated=args.trust_rotated))
    if args.bundle:
        record = load_bundle(args.bundle)
    else:
        record = reg.read_set(args.set_id)
    member_files = {}
    for spec in args.member or []:
        parts = spec.split(":")
        product = parts[0]
        artifact = parts[1] if len(parts) > 1 else ""
        build_spec = parts[2] if len(parts) > 2 else ""
        member_files[product] = (artifact, build_spec or None)
    if not args.member:
        for m in record.get("members", []):
            stored = reg.artifact_path(m["artifact_digest"])
            if os.path.exists(stored):
                member_files[m["product"]] = (
                    stored, reg.artifact_path(m["build_spec_digest"]))
    result = verifier.verify_set_release(
        record,
        member_files=member_files,
        now=args.now or utc_now(),
        as_of="release" if args.as_of_release else "current",
    )
    if args.json:
        print(
            json.dumps(
                {"ok": result.ok, "set_id": result.release_id,
                 "errors": result.errors, "checks": result.checks},
                indent=2,
                sort_keys=True,
            )
        )
    else:
        status = "TRUSTED" if result.ok else "UNTRUSTED"
        print(f"{status} set={result.release_id}")
        for e in result.errors:
            print(f"  - {e}")
    return 0 if result.ok else 3


def cmd_list(args) -> int:
    reg = Registry(os.path.join(args.home, "registry"))
    idx = reg.read_index()
    for entry in idx["releases"]:
        print(json.dumps(entry, sort_keys=True))
    print(f"total={len(idx['releases'])}", file=sys.stderr)
    return 0


def cmd_revoke(args) -> int:
    keys = IssuerKeyStore(os.path.join(args.home, "issuers"))
    crl = RevocationList(os.path.join(args.home, "crl"))
    kv = keys.latest_version(args.crl_issuer)
    if kv is None:
        raise SystemExit("CRL issuer has no key")
    seed = keys.load_secret(args.crl_issuer, kv)
    revoked = {args.issuer: args.key_versions}
    snapshot = crl.issue(
        revoked=revoked,
        reason=args.reason,
        now=args.now or utc_now(),
        issuer_id=args.crl_issuer,
        key_version=kv,
        secret_seed=seed,
    )
    # Also mark revoked key status in the keystore history.
    for ver in args.key_versions:
        keys.set_status(args.issuer, ver, "revoked", args.now or utc_now())
    print(f"CRL v{snapshot['body']['crl_version']} issued")
    return 0


def cmd_crl_list(args) -> int:
    crl = RevocationList(os.path.join(args.home, "crl"))
    for v in crl.list_versions():
        snap = crl.read_version(v)
        print(json.dumps(snap["body"], sort_keys=True))
    return 0


def cmd_verify(args) -> int:
    keys = IssuerKeyStore(os.path.join(args.home, "issuers"))
    crl = RevocationList(os.path.join(args.home, "crl"))
    reg = Registry(os.path.join(args.home, "registry"))
    verifier = Verifier(keys, crl, TrustPolicy(trust_rotated=args.trust_rotated))

    if args.bundle:
        record = load_bundle(args.bundle)
    else:
        record = reg.read_release(args.release_id)

    spec_path = args.build_spec or None
    if spec_path is None:
        digest = record["build_spec_digest"]
        stored = reg.artifact_path(digest)
        if os.path.exists(stored):
            spec_path = stored
    result = verifier.verify_release(
        record,
        artifact_path=args.artifact,
        build_spec_path=spec_path,
        now=args.now or utc_now(),
        expected_product=args.product,
        as_of="release" if args.as_of_release else "current",
    )
    if args.json:
        print(
            json.dumps(
                {"ok": result.ok, "release_id": result.release_id,
                 "errors": result.errors, "checks": result.checks},
                indent=2,
                sort_keys=True,
            )
        )
    else:
        status = "TRUSTED" if result.ok else "UNTRUSTED"
        print(f"{status} release={result.release_id}")
        for e in result.errors:
            print(f"  - {e}")
    return 0 if result.ok else 3


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="trusted-release")
    p.add_argument("--home", default=".release-store", help="store home dir")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("key-create")
    s.add_argument("--issuer", required=True)
    s.add_argument("--scope", required=True)
    s.add_argument("--valid-to", default="")
    s.add_argument("--role", default="")
    s.add_argument("--now", default="")
    s.set_defaults(func=cmd_key_create)

    s = sub.add_parser("key-list")
    s.add_argument("--issuer")
    s.set_defaults(func=cmd_key_list)

    s = sub.add_parser("publish")
    s.add_argument("--artifact", required=True)
    s.add_argument("--build-spec", required=True)
    s.add_argument("--product", required=True)
    s.add_argument("--version", required=True)
    s.add_argument("--issuer", required=True)
    s.add_argument("--validity-days", type=int, default=365)
    s.add_argument("--bundle", default="")
    s.add_argument("--now", default="")
    s.set_defaults(func=cmd_publish)

    s = sub.add_parser("candidate")
    s.add_argument("--artifact", required=True)
    s.add_argument("--build-spec", required=True)
    s.add_argument("--product", required=True)
    s.add_argument("--version", required=True)
    s.add_argument("--policy-id", required=True)
    s.add_argument("--policy-version", type=int, required=True)
    s.add_argument("--require", action="append", required=True)
    s.add_argument("--bundle", required=True)
    s.add_argument("--now", default="")
    s.set_defaults(func=cmd_candidate)

    s = sub.add_parser("approve")
    s.add_argument("--candidate", required=True)
    s.add_argument("--issuer", required=True)
    s.add_argument("--output", required=True)
    s.add_argument("--validity-days", type=int, default=365)
    s.add_argument("--now", default="")
    s.set_defaults(func=cmd_approve)

    s = sub.add_parser("finalize")
    s.add_argument("--candidate", required=True)
    s.add_argument("--approvals", nargs="+", required=True)
    s.add_argument("--bundle", required=True)
    s.add_argument("--now", default="")
    s.set_defaults(func=cmd_finalize)

    s = sub.add_parser("list")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("set-candidate")
    s.add_argument("--name", required=True)
    s.add_argument("--set-version", required=True)
    s.add_argument("--member", action="append", required=True,
                   help="product:version:artifact_path:build_spec_path")
    s.add_argument("--dep", action="append", default=[],
                   help="product:dependency_product (repeatable)")
    s.add_argument("--policy-id", required=True)
    s.add_argument("--policy-version", type=int, required=True)
    s.add_argument("--require", action="append", required=True)
    s.add_argument("--bundle", required=True)
    s.add_argument("--now", default="")
    s.set_defaults(func=cmd_set_candidate)

    s = sub.add_parser("set-approve")
    s.add_argument("--candidate", required=True)
    s.add_argument("--issuer", required=True)
    s.add_argument("--output", required=True)
    s.add_argument("--validity-days", type=int, default=365)
    s.add_argument("--now", default="")
    s.set_defaults(func=cmd_set_approve)

    s = sub.add_parser("set-finalize")
    s.add_argument("--candidate", required=True)
    s.add_argument("--approvals", nargs="*", default=[])
    s.add_argument("--bundle", required=True)
    s.add_argument("--now", default="")
    s.set_defaults(func=cmd_set_finalize)

    s = sub.add_parser("set-verify")
    s.add_argument("--set-id", default="")
    s.add_argument("--bundle", default="")
    s.add_argument("--member", action="append", default=[],
                   help="product:artifact_path[:build_spec_path]")
    s.add_argument("--trust-rotated", action="store_true")
    s.add_argument("--as-of-release", action="store_true")
    s.add_argument("--now", default="")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_set_verify)

    s = sub.add_parser("revoke")
    s.add_argument("--crl-issuer", required=True)
    s.add_argument("--issuer", required=True)
    s.add_argument("--key-versions", type=int, nargs="+", required=True)
    s.add_argument("--reason", default="")
    s.add_argument("--now", default="")
    s.set_defaults(func=cmd_revoke)

    s = sub.add_parser("crl-list")
    s.set_defaults(func=cmd_crl_list)

    s = sub.add_parser("verify")
    s.add_argument("--artifact", required=True)
    s.add_argument("--build-spec", default="")
    s.add_argument("--release-id", default="")
    s.add_argument("--bundle", default="")
    s.add_argument("--product", default=None)
    s.add_argument("--trust-rotated", action="store_true")
    s.add_argument("--as-of-release", action="store_true")
    s.add_argument("--now", default="")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_verify)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
