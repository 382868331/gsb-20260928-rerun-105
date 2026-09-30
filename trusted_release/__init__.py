"""Offline trusted software artifact release system (stdlib only).

The package provides four capabilities:

* artifact registration with content-addressed storage (``Registry``);
* build-specification binding pinned inside a signed attestation;
* issuer key management with rotation (``IssuerKeyStore``) and signed,
  versioned revocation material (``RevocationList``);
* offline verification (``Verifier``) that simultaneously proves the
  presented *content*, the *signer* and the *applicability scope* under the
  trust conditions configured *now*.

No third-party packages are required: Ed25519 is implemented from
RFC 8032 in :mod:`trusted_release.ed25519`.
"""

from .attestation import (
    RevocationList,
    build_attestation,
    sign_attestation,
    verify_signature,
)
from .issuer import IssuerKeyStore, KeyRecord
from .publisher import Publisher, utc_now
from .registry import Registry
from .verifier import TrustPolicy, VerificationResult, Verifier, load_bundle, export_bundle

__all__ = [
    "RevocationList",
    "build_attestation",
    "sign_attestation",
    "verify_signature",
    "IssuerKeyStore",
    "KeyRecord",
    "Publisher",
    "utc_now",
    "Registry",
    "TrustPolicy",
    "VerificationResult",
    "Verifier",
    "export_bundle",
    "load_bundle",
]
