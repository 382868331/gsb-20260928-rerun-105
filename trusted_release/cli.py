"""Offline command line interface (Python standard library only).

Subcommands:

* ``init``        - create registry/issuer/CRL directories
* ``key-create``  - create or rotate an issuer key (with scope/window)
* ``key-list``    - inspect key history (rotation visible)
* ``publish``     - register artifact + build spec, sign, index atomically
* ``list``        - list the trusted release catalog
* ``revoke``      - issue a new signed CRL snapshot and mark keys revoked
* ``crl-list``    - inspect historical CRL snapshots
* ``verify``      - offline verify content + signer + scope, exit 3 if fail
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .attestation import RevocationList
from .issuer import IssuerKeyStore
from .publisher import Publisher, utc_now
from .registry import Registry
from .verifier import TrustPolicy, Verifier, load_bundle


def _keystore(home: str) -> IssuerKeyStore:
    return IssuerKeyStore(os.path.join(home, "issuers"))


def _registry(home: str) -> Registry:
    return Registry(os.path.join(home, "registry"))


def _crl(home: str) -> RevocationList:
    return RevocationList(os.path.join(home, "crl"))


def cmd_init(args) -> int:
    _registry(args.home)
    _keystore(args.home)
    _crl(args.home)
    print(f"initialized trusted release store at {args.home}")
    return 0


def cmd_key_create(args) -> int:
    record = _keystore(args.home).create_key(
        issuer_id=args.issuer,
        scope=args.scope,
        now=args.now or utc_now(),
        valid_to=args.valid_to or "",
    )
    print(
        f"issuer={record.issuer_id} key_version={record.key_version} "
        f"status={record.status} scope={record.scope}"
    )
    return 0


def cmd_key_list(args) -> int:
    for record in _keystore(args.home).list_keys(args.issuer):
        print(json.dumps(record.to_dict(), sort_keys=True))
    return 0


def cmd_publish(args) -> int:
    record = Publisher(_registry(args.home), _keystore(args.home)).publish(
        artifact_path=args.artifact,
        build_spec_path=args.build_spec,
        product=args.product,
        version=args.version,
        issuer_id=args.issuer,
        now=args.now or None,
        validity_days=args.validity_days,
    )
    print(f"published release_id={record['release_id']}")
    if args.bundle:
        with open(args.bundle, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2, sort_keys=True, ensure_ascii=False)
        print(f"offline bundle written to {args.bundle}")
    return 0


def cmd_list(args) -> int:
    index = _registry(args.home).read_index()
    for entry in index["releases"]:
        print(json.dumps(entry, sort_keys=True))
    print(f"total={len(index['releases'])}", file=sys.stderr)
    return 0


def cmd_revoke(args) -> int:
    keys = _keystore(args.home)
    crl = _crl(args.home)
    key_version = keys.latest_version(args.crl_issuer)
    if key_version is None:
        raise SystemExit(f"CRL issuer {args.crl_issuer!r} has no key")
    seed = keys.load_secret(args.crl_issuer, key_version)
    snapshot = crl.issue(
        revoked={args.issuer: args.key_versions},
        reason=args.reason,
        now=args.now or utc_now(),
        issuer_id=args.crl_issuer,
        key_version=key_version,
        secret_seed=seed,
    )
    for version in args.key_versions:
        keys.set_status(args.issuer, version, "revoked")
    print(f"CRL v{snapshot['body']['crl_version']} issued")
    return 0


def cmd_crl_list(args) -> int:
    crl = _crl(args.home)
    for version in crl.list_versions():
        print(json.dumps(crl.read_version(version)["body"], sort_keys=True))
    return 0


def cmd_verify(args) -> int:
    home = args.home
    keys = _keystore(home)
    crl = _crl(home)
    registry = _registry(home)
    verifier = Verifier(
        keys, crl, TrustPolicy(trust_rotated=args.trust_rotated)
    )

    if args.bundle:
        record = load_bundle(args.bundle)
    else:
        if not args.release_id:
            raise SystemExit("verify requires --release-id or --bundle")
        record = registry.read_release(args.release_id)

    build_spec = args.build_spec
    if not build_spec:
        stored = registry.artifact_path(record["build_spec_digest"])
        if os.path.exists(stored):
            build_spec = stored

    result = verifier.verify_release(
        record,
        artifact_path=args.artifact,
        build_spec_path=build_spec or None,
        now=args.now or utc_now(),
        expected_product=args.product or None,
    )
    if args.json:
        print(
            json.dumps(
                {
                    "ok": result.ok,
                    "release_id": result.release_id,
                    "errors": result.errors,
                    "checks": result.checks,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(
            f"{'TRUSTED' if result.ok else 'UNTRUSTED'} "
            f"release={result.release_id}"
        )
        for error in result.errors:
            print(f"  - {error}")
    return 0 if result.ok else 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="trusted-release")
    parser.add_argument("--home", default=".release-store", help="store home")
    sub = parser.add_subparsers(dest="cmd", required=True)

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
    s.add_argument("--product", default="")
    s.add_argument("--trust-rotated", action="store_true")
    s.add_argument("--now", default="")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
