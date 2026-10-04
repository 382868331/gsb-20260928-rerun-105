"""Read-only version comparison reports for release collections."""

from __future__ import annotations

from .collection import find_cycles
from .encoding import canonical_hash

REPORT_TYPE = "trusted-release/collection-comparison/v1"
RELEASE_TYPE = "trusted-release/collection/v1"


def _key(member):
    return f"{member['product']}:{member['version']}"


def _edges(spec):
    return {
        (_key(m), f"{dep['product']}:{dep['version']}")
        for m in spec.get("members", [])
        for dep in m.get("depends_on", [])
    }


def _members(spec):
    return {_key(m): m for m in spec.get("members", [])}


def _summary(bundle):
    released = bundle.get("type") == RELEASE_TYPE
    candidate = bundle.get("candidate", bundle)
    spec = bundle.get("spec", candidate.get("spec", {}))
    policy = bundle.get("policy", candidate.get("policy", {}))
    approvals = bundle.get("approvals", []) if released else []
    roles = {}
    for env in approvals:
        approval = env.get("approval", {})
        roles.setdefault(approval.get("role", ""), set()).add(approval.get("issuer_id", ""))
    return {
        "kind": "released_collection" if released else "collection_candidate",
        "collection_release_id": bundle.get("collection_release_id", candidate.get("collection_release_id", "")),
        "candidate_id": candidate.get("candidate_id", ""),
        "candidate_digest": candidate.get("candidate_digest", ""),
        "name": bundle.get("name", candidate.get("name", "")),
        "version": bundle.get("version", candidate.get("version", "")),
        "spec_digest": bundle.get("spec_digest", candidate.get("spec_digest", "")),
        "policy_id": policy.get("policy_id", ""),
        "policy_version": policy.get("policy_version", 0),
        "policy_digest": bundle.get("policy_digest", candidate.get("policy_digest", "")),
        "requirements": dict(policy.get("requirements", {})),
        "member_count": len(spec.get("members", [])),
        "dependency_edge_count": len(_edges(spec)),
        "dependency_cycles": find_cycles(spec),
        "released_at": bundle.get("released_at", ""),
        "included_approval_count": len(approvals),
        "included_approval_roles": {role: len(issuers) for role, issuers in sorted(roles.items())},
    }


def _content(old_spec, new_spec):
    old, new = _members(old_spec), _members(new_spec)
    added, removed, replaced, unchanged = [], [], [], []
    for k in sorted(set(new) - set(old)):
        added.append({"member": k, "change": "added", "new_artifact_digest": new[k]["artifact_digest"], "new_build_spec_digest": new[k]["build_spec_digest"], "explanation": f"member {k} is added"})
    for k in sorted(set(old) - set(new)):
        removed.append({"member": k, "change": "removed", "old_artifact_digest": old[k]["artifact_digest"], "old_build_spec_digest": old[k]["build_spec_digest"], "explanation": f"member {k} is removed"})
    for k in sorted(set(old) & set(new)):
        fields = ("artifact_digest", "build_spec_digest")
        changed = [x for x in fields if old[k][x] != new[k][x]]
        item = {"member": k, "changed_fields": changed, "old_artifact_digest": old[k]["artifact_digest"], "new_artifact_digest": new[k]["artifact_digest"], "old_build_spec_digest": old[k]["build_spec_digest"], "new_build_spec_digest": new[k]["build_spec_digest"]}
        item["explanation"] = f"member {k} replaces {', '.join(changed)}" if changed else f"member {k} content and build spec are unchanged"
        (replaced if changed else unchanged).append(item)
    return {"added": added, "removed": removed, "replaced": replaced, "unchanged": unchanged}


def _dependencies(old_spec, new_spec):
    old, new = _edges(old_spec), _edges(new_spec)
    fmt = lambda edges: [{"from": a, "to": b} for a, b in sorted(edges)]
    incoming = {}
    for source, target in new:
        incoming.setdefault(target, []).append(source)
    return {
        "added": fmt(new - old),
        "removed": fmt(old - new),
        "unchanged": fmt(old & new),
        "shared_dependencies": [{"member": target, "depended_on_by": sorted(sources), "dependent_count": len(sources)} for target, sources in sorted(incoming.items()) if len(sources) > 1],
        "old_cycles": find_cycles(old_spec),
        "new_cycles": find_cycles(new_spec),
    }


def _policies(old, new):
    roles = sorted(set(old["requirements"]) | set(new["requirements"]))
    changes = []
    for role in roles:
        a, b = int(old["requirements"].get(role, 0)), int(new["requirements"].get(role, 0))
        state = "unchanged" if a == b else "role_added" if a == 0 else "role_removed" if b == 0 else "requirement_increased" if b > a else "requirement_decreased"
        changes.append({"role": role, "old_required_count": a, "new_required_count": b, "change": state})
    return {"old_policy_digest": old["policy_digest"], "new_policy_digest": new["policy_digest"], "policy_changed": old["policy_digest"] != new["policy_digest"], "role_changes": changes}


def _assess_old_approvals(old_bundle, old, new):
    result = []
    for env in sorted(old_bundle.get("approvals", []), key=lambda x: x.get("approval_id", "")):
        approval = env.get("approval", {})
        reasons = ["bound to old candidate_digest, not new candidate_digest", "bound to old collection_release_id and spec_digest"]
        if old["policy_digest"] != new["policy_digest"]:
            reasons.append("bound to old policy digest")
        result.append({"approval_id": env.get("approval_id", ""), "issuer_id": approval.get("issuer_id", ""), "role": approval.get("role", ""), "key_version": approval.get("key_version", 0), "applicable_to_new_collection": False, "carryover_count": 0, "reasons": reasons, "explanation": "audit evidence for the old collection only; obtain a fresh approval on the new candidate"})
    return result


def _gaps(new):
    included = new["included_approval_roles"]
    return [{
        "role": role,
        "required_distinct_issuers": required,
        "included_in_new_bundle_distinct_issuers": int(included.get(role, 0)),
        "usable_old_approvals": 0,
        "missing_new_approvals": max(0, required - int(included.get(role, 0))),
        "explanation": "zero old approvals are inherited; missing approvals must be signed on the new candidate",
    } for role, required in sorted(new["requirements"].items())]


def build_collection_comparison(old_bundle, new_bundle):
    """Build a deterministic self-contained offline comparison report."""
    old, new = _summary(old_bundle), _summary(new_bundle)
    if not old["candidate_digest"] or not new["candidate_digest"]:
        raise ValueError("both inputs must be collection candidates or releases")
    if old["candidate_digest"] == new["candidate_digest"]:
        raise ValueError("cannot compare a collection with itself")
    old_spec = old_bundle.get("spec", old_bundle.get("candidate", {}).get("spec", {}))
    new_spec = new_bundle.get("spec", new_bundle.get("candidate", {}).get("spec", {}))
    report = {
        "type": REPORT_TYPE,
        "old_collection": old,
        "new_collection": new,
        "content_changes": _content(old_spec, new_spec),
        "dependency_changes": _dependencies(old_spec, new_spec),
        "policy_changes": _policies(old, new),
        "old_approval_assessment": _assess_old_approvals(old_bundle, old, new),
        "required_new_approvals": _gaps(new),
        "inheritance": {"approvals_automatically_inherited": False, "published_collections_modified": False, "explanation": "The report is read-only; collect new approvals explicitly against the new candidate."},
    }
    report["report_digest"] = canonical_hash(report)
    return report
