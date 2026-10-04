"""Artifact registry: content-addressed storage, registration and
build-spec binding.

Layout under registry root::

    artifacts/<sha256-prefix>/<sha256>      raw artifact bytes
    manifests/<digest>.json                  artifact manifest
    releases/<release-id>.json               immutable release records
    index.json                               release index (trusted catalog)

Artifacts are content-addressed: replacing the file changes its digest,
so a signature over the old digest can never validate the new bytes.
"""

from __future__ import annotations

import json
import os

from .encoding import canonical_json, digest_bytes, file_digest

INDEX_FILE = "index.json"


class Registry:
    def __init__(self, root: str):
        self.root = root
        self.art_dir = os.path.join(root, "artifacts")
        self.man_dir = os.path.join(root, "manifests")
        self.rel_dir = os.path.join(root, "releases")
        for d in (self.art_dir, self.man_dir, self.rel_dir):
            os.makedirs(d, exist_ok=True)
        self.index_path = os.path.join(root, INDEX_FILE)
        if not os.path.exists(self.index_path):
            self._write_index({"version": 1, "releases": []})

    # ---------- low level index / manifest IO (atomic) ----------
    def _write_index(self, idx: dict) -> None:
        tmp = self.index_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(idx, f, indent=2, ensure_ascii=False, sort_keys=True)
            f.write("\n")
        os.replace(tmp, self.index_path)

    def read_index(self) -> dict:
        with open(self.index_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _atomic_json(self, path: str, obj: dict) -> None:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(canonical_json(obj).decode("utf-8"))
        os.replace(tmp, path)

    # ---------- artifact storage ----------
    def _artifact_path(self, digest: str) -> str:
        algo, _, hexpart = digest.partition(":")
        return os.path.join(self.art_dir, algo, hexpart[:2], hexpart)

    def artifact_path(self, digest: str) -> str:
        return self._artifact_path(digest)

    def has_artifact(self, digest: str) -> bool:
        return os.path.exists(self._artifact_path(digest))

    def _store_bytes(self, data: bytes, expected_digest: str | None = None) -> str:
        digest = digest_bytes(data)
        if expected_digest is not None and digest != expected_digest:
            raise ValueError(
                f"content tampered: expected {expected_digest}, got {digest}"
            )
        path = self._artifact_path(digest)
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, path)
        return digest

    # ---------- registration & binding ----------
    def manifest_path(self, digest: str) -> str:
        return os.path.join(self.man_dir, digest.replace(":", "_") + ".json")

    def has_manifest(self, digest: str) -> bool:
        return os.path.exists(self.manifest_path(digest))

    def read_manifest(self, digest: str) -> dict:
        with open(self.manifest_path(digest), "r", encoding="utf-8") as f:
            return json.load(f)

    def register_artifact(
        self,
        source_path: str,
        product: str,
        version: str,
        build_spec_path: str,
        now: str,
        metadata: dict | None = None,
    ) -> dict:
        """Import an artifact and bind it to a build specification.

        Both the artifact and the build spec are hashed. The manifest pins
        both digests, so swapping either file breaks the binding.
        """
        artifact_digest = file_digest(source_path)
        with open(source_path, "rb") as f:
            data = f.read()
        self._store_bytes(data, artifact_digest)

        spec_digest = file_digest(build_spec_path)
        with open(build_spec_path, "rb") as f:
            spec_bytes = f.read()
        self._store_bytes(spec_bytes, spec_digest)

        manifest = {
            "product": product,
            "version": version,
            "artifact_digest": artifact_digest,
            "artifact_size": len(data),
            "build_spec_digest": spec_digest,
            "build_spec_size": len(spec_bytes),
            "registered_at": now,
            "metadata": metadata or {},
        }
        self._atomic_json(self.manifest_path(artifact_digest), manifest)
        return manifest

    # ---------- release index ----------
    def index_release(self, record: dict) -> None:
        """Append a fully signed release to the trusted catalog.

        Called only after signing succeeds; an interrupted/failed publish
        therefore never produces an index entry.
        """
        idx = self.read_index()
        for entry in idx["releases"]:
            if entry["release_id"] == record["release_id"]:
                raise ValueError(
                    f"release {record['release_id']} already indexed"
                )
        # Write the immutable release record FIRST. The index is updated
        # last and atomically: an interrupted publish can never leave an
        # index entry pointing at an unfinished/untrusted release.
        rel_path = os.path.join(self.rel_dir, record["release_id"] + ".json")
        if not os.path.exists(rel_path):
            self._atomic_json(rel_path, record)
        idx["releases"].append(
            {
                "release_id": record["release_id"],
                "product": record["product"],
                "version": record["version"],
                "artifact_digest": record["artifact_digest"],
                "build_spec_digest": record["build_spec_digest"],
                "issuer_id": record.get("issuer_id", ""),
                "key_version": record.get("key_version", 0),
                "issued_at": record.get("issued_at", record.get("released_at", "")),
                "expires_at": record.get("expires_at", ""),
                "policy_id": record.get("policy", {}).get("policy_id", ""),
                "policy_version": record.get("policy", {}).get("policy_version", 0),
                "approval_count": len(record.get("approvals", [])),
            }
        )
        self._write_index(idx)

    def read_release(self, release_id: str) -> dict:
        path = os.path.join(self.rel_dir, release_id + ".json")
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    # ---------- release set index ----------
    def index_set_release(self, record: dict) -> None:
        """Append a fully approved release set to the trusted catalog.

        The immutable set record is written first; the index is updated
        last, atomically, in a single write that covers every member.
        An interrupted finalize therefore can never expose half a set:
        either the whole set is in the catalog or none of it is.
        """
        idx = self.read_index()
        idx.setdefault("sets", [])
        for entry in idx["sets"]:
            if entry["set_id"] == record["set_id"]:
                raise ValueError(f"set {record['set_id']} already indexed")
        rel_path = os.path.join(self.rel_dir, record["set_id"] + ".json")
        if not os.path.exists(rel_path):
            self._atomic_json(rel_path, record)
        idx["sets"].append(
            {
                "type": "set",
                "set_id": record["set_id"],
                "name": record["name"],
                "set_version": record["set_version"],
                "set_digest": record["set_digest"],
                "members": [
                    {
                        "product": m["product"],
                        "version": m["version"],
                        "artifact_digest": m["artifact_digest"],
                        "build_spec_digest": m["build_spec_digest"],
                        "depends_on": list(m.get("depends_on", [])),
                    }
                    for m in record["members"]
                ],
                "released_at": record.get("released_at", ""),
                "policy_id": record.get("policy", {}).get("policy_id", ""),
                "policy_version": record.get("policy", {}).get("policy_version", 0),
                "approval_count": len(record.get("approvals", [])),
            }
        )
        self._write_index(idx)

    def read_set(self, set_id: str) -> dict:
        path = os.path.join(self.rel_dir, set_id + ".json")
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def list_release_ids(self) -> list[str]:
        return sorted(
            f[:-5] for f in os.listdir(self.rel_dir) if f.endswith(".json")
        )
