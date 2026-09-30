"""Content-addressed artifact registry, build-spec binding, release index.

Layout::

    artifacts/sha256/<xx>/<full-hex>   immutable content bytes
    manifests/sha256_<hex>.json        artifact + build-spec binding
    releases/<release_id>.json         immutable signed release records
    index.json                         trusted catalog

Artifacts are content-addressed, so replacing a file changes its digest
and a signature over the previous digest cannot validate the new bytes.
"""

from __future__ import annotations

import json
import os

from .encoding import canonical_json, digest_bytes, file_digest

INDEX_FILE = "index.json"


class Registry:
    def __init__(self, root: str):
        self.root = root
        self.artifacts_dir = os.path.join(root, "artifacts")
        self.manifests_dir = os.path.join(root, "manifests")
        self.releases_dir = os.path.join(root, "releases")
        for directory in (
            self.artifacts_dir,
            self.manifests_dir,
            self.releases_dir,
        ):
            os.makedirs(directory, exist_ok=True)
        self.index_path = os.path.join(root, INDEX_FILE)
        if not os.path.exists(self.index_path):
            self._write_index({"version": 1, "releases": []})

    # ---------- atomic JSON helpers ----------
    def _write_index(self, index: dict) -> None:
        tmp = self.index_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(index, fh, indent=2, sort_keys=True, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, self.index_path)

    def read_index(self) -> dict:
        with open(self.index_path, "r", encoding="utf-8") as fh:
            index = json.load(fh)
        if "releases" not in index or not isinstance(index["releases"], list):
            raise ValueError("corrupt release index")
        return index

    def _atomic_json(self, path: str, obj: dict) -> None:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2, sort_keys=True, ensure_ascii=False)
        os.replace(tmp, path)

    # ---------- content-addressed storage ----------
    def artifact_path(self, digest: str) -> str:
        algo, _, hexpart = digest.partition(":")
        return os.path.join(self.artifacts_dir, algo, hexpart[:2], hexpart)

    def has_artifact(self, digest: str) -> bool:
        return os.path.exists(self.artifact_path(digest))

    def _store_bytes(self, data: bytes, expected_digest: str) -> str:
        digest = digest_bytes(data)
        if digest != expected_digest:
            raise ValueError(
                f"content tampered during storage: expected {expected_digest}, "
                f"got {digest}"
            )
        path = self.artifact_path(digest)
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "wb") as fh:
                fh.write(data)
            os.replace(tmp, path)
        return digest

    # ---------- registration & build-spec binding ----------
    def manifest_path(self, artifact_digest: str) -> str:
        return os.path.join(
            self.manifests_dir, artifact_digest.replace(":", "_") + ".json"
        )

    def has_manifest(self, artifact_digest: str) -> bool:
        return os.path.exists(self.manifest_path(artifact_digest))

    def read_manifest(self, artifact_digest: str) -> dict:
        with open(self.manifest_path(artifact_digest), "r", encoding="utf-8") as fh:
            return json.load(fh)

    def register_artifact(
        self,
        source_path: str,
        product: str,
        version: str,
        build_spec_path: str,
        now: str,
        metadata: dict | None = None,
    ) -> dict:
        """Import artifact + build spec and pin both digests in a manifest."""
        with open(source_path, "rb") as fh:
            artifact_bytes = fh.read()
        artifact_digest = digest_bytes(artifact_bytes)
        self._store_bytes(artifact_bytes, file_digest(source_path))

        with open(build_spec_path, "rb") as fh:
            spec_bytes = fh.read()
        build_spec_digest = digest_bytes(spec_bytes)
        self._store_bytes(spec_bytes, file_digest(build_spec_path))

        manifest = {
            "type": "trusted-release/manifest/v1",
            "product": product,
            "version": version,
            "artifact_digest": artifact_digest,
            "artifact_size": len(artifact_bytes),
            "build_spec_digest": build_spec_digest,
            "build_spec_size": len(spec_bytes),
            "registered_at": now,
            "metadata": metadata or {},
        }
        self._atomic_json(self.manifest_path(artifact_digest), manifest)
        return manifest

    # ---------- release catalog ----------
    def index_release(self, record: dict) -> None:
        """Append an already-signed record to the trusted catalog.

        The immutable release file is written first; ``index.json`` is
        updated last and atomically. Therefore an interrupted/failed publish
        can never leave an index entry that points at an unfinished release.
        """
        index = self.read_index()
        if any(
            entry["release_id"] == record["release_id"]
            for entry in index["releases"]
        ):
            raise ValueError(f"release {record['release_id']} already indexed")

        release_path = os.path.join(
            self.releases_dir, record["release_id"] + ".json"
        )
        if not os.path.exists(release_path):
            self._atomic_json(release_path, record)

        index["releases"].append(
            {
                "release_id": record["release_id"],
                "product": record["product"],
                "version": record["version"],
                "artifact_digest": record["artifact_digest"],
                "build_spec_digest": record["build_spec_digest"],
                "issuer_id": record["issuer_id"],
                "key_version": record["key_version"],
                "issued_at": record["issued_at"],
                "expires_at": record["expires_at"],
            }
        )
        self._write_index(index)

    def read_release(self, release_id: str) -> dict:
        path = os.path.join(self.releases_dir, release_id + ".json")
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def list_release_ids(self) -> list[str]:
        return sorted(
            name[:-5]
            for name in os.listdir(self.releases_dir)
            if name.endswith(".json")
        )
