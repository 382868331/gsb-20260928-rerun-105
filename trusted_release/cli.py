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
        keys.set_status(args.issuer, ver, "revoked")
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

    spec_path = args.build_spec
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

    s = sub.add_parser("list")
    s.set_defaults(func=cmd_list)

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
    s.add_argument("--now", default="")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_verify)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
