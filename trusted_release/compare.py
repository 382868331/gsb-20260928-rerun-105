"""Release collection version comparison reports.

An approver picks two published collections (old and new) and gets a
self-contained, offline-savable report covering:

* artifact content changes (added / removed / replaced members, build
  spec changes),
* dependency graph changes (added / removed edges, shared dependencies,
  cycles before and after),
* required approval role changes (policy id/version and per-role quorum
  diffs),
* a per-item explanation of which approvals collected for the old
  collection no longer apply to the new one and why, and which approvals
  still need to be collected to satisfy the new policy.

The report only *reads* both release records. It never inherits or
replays old approvals onto the new collection and never rewrites either
published record; each report links back to the two collections through
their immutable summaries (release id, spec/candidate/policy digests).
"""

from __future__ import annotations

from . import collection as coll
from .encoding import canonical_hash
from .policy import ReleasePolicy

REPORT_TYPE = "trusted-release/collection-compare/v1"


def _member_key(member: dict) -> tuple[str, str]:
    return (str(member.get("product")), str(member.get("version")))


def _edge(src: tuple[str, str], dep: dict) -> tuple[str, str, str, str]:
    return (src[0], src[1], str(dep.get("product")), str(dep.get("version")))


def _edge_label(edge: tuple[str, str, str, str]) -> str:
    return f"{edge[0]}:{edge[1]} -> {edge[2]}:{edge[3]}"


def summarize_collection(record: dict) -> dict:
    """A compact, immutable pointer to a published collection."""
    candidate = record.get("candidate", {})
    spec = record.get("spec", candidate.get("spec", {}))
    members = spec.get("members", [])
    return {
        "collection_release_id": record.get("collection_release_id"),
        "record_id": record.get("record_id"),
        "name": record.get("name", spec.get("name")),
        "version": record.get("version", spec.get("version")),
        "spec_digest": record.get("spec_digest"),
        "candidate_digest": record.get("candidate_digest"),
        "policy_digest": record.get("policy_digest"),
        "released_at": record.get("released_at"),
        "member_count": len(members),
        "approval_count": len(record.get("approvals", [])),
    }


def _diff_content(old_members: list[dict], new_members: list[dict]) -> dict:
    old_by_key = {_member_key(m): m for m in old_members}
    new_by_key = {_member_key(m): m for m in new_members}
    added, removed, replaced, unchanged = [], [], [], []
    for key in sorted(new_by_key):
        new_m = new_by_key[key]
        old_m = old_by_key.get(key)
        if old_m is None:
            added.append({"product": key[0], "version": key[1],
                          "artifact_digest": new_m.get("artifact_digest")})
            continue
        art_changed = old_m.get("artifact_digest") != new_m.get("artifact_digest")
        spec_changed = (old_m.get("build_spec_digest")
                        != new_m.get("build_spec_digest"))
        if art_changed or spec_changed:
            replaced.append({
                "product": key[0],
                "version": key[1],
                "old_artifact_digest": old_m.get("artifact_digest"),
                "new_artifact_digest": new_m.get("artifact_digest"),
                "artifact_changed": art_changed,
                "build_spec_changed": spec_changed,
            })
        else:
            unchanged.append({"product": key[0], "version": key[1]})
    for key in sorted(old_by_key):
        if key not in new_by_key:
            removed.append({"product": key[0], "version": key[1],
                            "artifact_digest": old_by_key[key].get("artifact_digest")})
    return {"added": added, "removed": removed,
            "replaced": replaced, "unchanged": unchanged}


def _diff_dependencies(old_members: list[dict], new_members: list[dict]) -> dict:
    def edges_of(members):
        edges = set()
        for m in members:
            src = _member_key(m)
            for dep in m.get("depends_on", []):
                edges.add(_edge(src, dep))
        return edges

    def shared_of(members):
        counts: dict[tuple[str, str], list[str]] = {}
        for m in members:
            src = _member_key(m)
            for dep in m.get("depends_on", []):
                tgt = (str(dep.get("product")), str(dep.get("version")))
                counts.setdefault(tgt, []).append(f"{src[0]}:{src[1]}")
        return [
            {"product": t[0], "version": t[1], "depended_by": sorted(srcs)}
            for t, srcs in sorted(counts.items()) if len(srcs) > 1
        ]

    old_edges, new_edges = edges_of(old_members), edges_of(new_members)
    return {
        "added_edges": [_edge_label(e) for e in sorted(new_edges - old_edges)],
        "removed_edges": [_edge_label(e) for e in sorted(old_edges - new_edges)],
        "shared_dependencies_old": shared_of(old_members),
        "shared_dependencies_new": shared_of(new_members),
    }


def _diff_policy(old_policy: dict, new_policy: dict) -> dict:
    old_req = old_policy.get("requirements", {})
    new_req = new_policy.get("requirements", {})
    added = {r: new_req[r] for r in sorted(new_req) if r not in old_req}
    removed = {r: old_req[r] for r in sorted(old_req) if r not in new_req}
    changed = {
        r: {"old": old_req[r], "new": new_req[r]}
        for r in sorted(new_req)
        if r in old_req and old_req[r] != new_req[r]
    }
    unchanged = {
        r: new_req[r] for r in sorted(new_req)
        if r in old_req and old_req[r] == new_req[r]
    }
    return {
        "policy_id": {"old": old_policy.get("policy_id"),
                      "new": new_policy.get("policy_id")},
        "policy_version": {"old": old_policy.get("policy_version"),
                           "new": new_policy.get("policy_version")},
        "requirements_added": added,
        "requirements_removed": removed,
        "requirements_changed": changed,
        "requirements_unchanged": unchanged,
    }


def _analyze_approvals(old_record: dict, new_record: dict,
                       content_changes: dict, policy_changes: dict) -> dict:
    new_candidate_digest = new_record.get("candidate_digest")
    new_policy_digest = new_record.get("policy_digest")
    stale = []
    for entry in old_record.get("approvals", []):
        approval = entry.get("approval", entry)
        reasons = []
        if approval.get("candidate_digest") != new_candidate_digest:
            reasons.append(
                "approval binds the old candidate_digest; the new collection "
                "has a different candidate, so this approval cannot apply"
            )
        if approval.get("policy_digest") != new_policy_digest:
            reasons.append(
                "approval binds the old policy_digest; required roles or "
                "policy version changed"
            )
        if not reasons:
            reasons.append("approval does not match the new collection")
        stale.append({
            "approval_id": entry.get("approval_id"),
            "issuer_id": approval.get("issuer_id"),
            "key_version": approval.get("key_version"),
            "role": approval.get("role"),
            "reason": "; ".join(reasons),
        })

    replaced = {(c["product"], c["version"]) for c in content_changes["replaced"]}
    added = {(c["product"], c["version"]) for c in content_changes["added"]}
    removed = {(c["product"], c["version"]) for c in content_changes["removed"]}

    new_policy = ReleasePolicy.from_dict(new_record.get("policy", {}))
    old_approvers_by_role: dict[str, list[str]] = {}
    for entry in old_record.get("approvals", []):
        approval = entry.get("approval", entry)
        role = approval.get("role", "")
        issuer = approval.get("issuer_id")
        if issuer and issuer not in old_approvers_by_role.setdefault(role, []):
            old_approvers_by_role[role].append(issuer)

    to_collect = []
    for role, count in sorted(new_policy.requirements.items()):
        to_collect.append({
            "role": role,
            "required": count,
            "previous_approvers": sorted(old_approvers_by_role.get(role, [])),
            "note": (
                "old approvals for this role cannot be reused; "
                f"{count} fresh approval(s) binding the new candidate_digest "
                "must be collected"
            ),
        })

    explanations = []
    if replaced:
        names = ", ".join(f"{p}:{v}" for p, v in sorted(replaced))
        explanations.append(
            f"replaced member content ({names}) changes spec_digest and "
            "candidate_digest; every old approval stops applying"
        )
    if added:
        names = ", ".join(f"{p}:{v}" for p, v in sorted(added))
        explanations.append(f"new members added: {names}")
    if removed:
        names = ", ".join(f"{p}:{v}" for p, v in sorted(removed))
        explanations.append(f"members removed: {names}")
    if policy_changes["requirements_added"] or policy_changes["requirements_changed"]:
        explanations.append(
            "required approval roles changed; approvals collected under the "
            "old policy version do not count toward the new quorum"
        )
    if not (replaced or added or removed):
        explanations.append(
            "member content is identical, but approvals still bind the exact "
            "candidate_digest and are never inherited automatically"
        )

    return {
        "stale_approvals": stale,
        "approvals_to_collect": to_collect,
        "explanations": explanations,
    }


def compare_collections(old_record: dict, new_record: dict, *, now: str) -> dict:
    """Build a comparison report between two published collections.

    Purely read-only: both records are left untouched and no approval is
    carried over to the new collection.
    """
    for rec, label in ((old_record, "old"), (new_record, "new")):
        if rec.get("type") != coll.RELEASE_TYPE:
            raise ValueError(
                f"{label} record is not a collection release: "
                f"{rec.get('type')!r}"
            )
    old_spec = old_record.get("spec", old_record.get("candidate", {}).get("spec", {}))
    new_spec = new_record.get("spec", new_record.get("candidate", {}).get("spec", {}))
    old_members = old_spec.get("members", [])
    new_members = new_spec.get("members", [])

    content_changes = _diff_content(old_members, new_members)
    dependency_changes = _diff_dependencies(old_members, new_members)
    dependency_changes["cycles_old"] = coll.find_cycles(old_spec)
    dependency_changes["cycles_new"] = coll.find_cycles(new_spec)
    policy_changes = _diff_policy(
        old_record.get("policy", {}), new_record.get("policy", {}))
    approval_analysis = _analyze_approvals(
        old_record, new_record, content_changes, policy_changes)

    report = {
        "type": REPORT_TYPE,
        "generated_at": now,
        "old": summarize_collection(old_record),
        "new": summarize_collection(new_record),
        "content_changes": content_changes,
        "dependency_changes": dependency_changes,
        "policy_changes": policy_changes,
        "approval_analysis": approval_analysis,
        "notes": [
            "this report is read-only: it neither inherits approvals nor "
            "rewrites either published collection",
            "approvals bind candidate_digest; any content, dependency, or "
            "policy change requires fresh approvals for the new collection",
        ],
    }
    report["report_id"] = canonical_hash(
        {k: report[k] for k in report if k != "report_id"})
    return report

