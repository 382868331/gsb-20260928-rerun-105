"""Plan technically compatible and approval-ready collection upgrades."""

from __future__ import annotations

from itertools import combinations

from . import collection as coll
from .encoding import canonical_hash
from .policy import ReleasePolicy

PLAN_TYPE = "trusted-release/collection-upgrade-plan/v1"
OPTION_TYPE = "trusted-release/collection-upgrade-option/v1"


def _version_tuple(value: str) -> tuple:
    parts = []
    for item in str(value).split("."):
        try:
            parts.append((0, int(item)))
        except ValueError:
            parts.append((1, item))
    return tuple(parts)


def version_satisfies(version: str, spec: str | None) -> bool:
    if spec in (None, "", "*"):
        return True
    current = _version_tuple(version)
    for clause in str(spec).split(","):
        clause = clause.strip()
        if not clause:
            continue
        for op in (">=", "<=", "==", "!=", ">", "<", "="):
            if clause.startswith(op):
                wanted = clause[len(op):].strip()
                break
        else:
            op, wanted = "=", clause
        target = _version_tuple(wanted)
        if op == "=" and current != target:
            return False
        if op == "==" and current != target:
            return False
        if op == "!=" and current == target:
            return False
        if op == ">=" and current < target:
            return False
        if op == "<=" and current > target:
            return False
        if op == ">" and current <= target:
            return False
        if op == "<" and current >= target:
            return False
    return True


def _catalog(artifacts):
    if not isinstance(artifacts, list):
        return artifacts
    result = {}
    for artifact in artifacts:
        result.setdefault(str(artifact["product"]), {})[
            str(artifact["version"])
        ] = artifact
    return result


def _requirements(artifact: dict) -> dict[str, str]:
    raw = artifact.get("requires", artifact.get("dependency_ranges", {})) or {}
    return {str(product): str(spec) for product, spec in raw.items()}


def _intersect(left: str | None, right: str) -> str:
    return right if not left else f"{left}, {right}"


def _conflicts(artifact: dict) -> list[tuple[str, str]]:
    result = []
    for item in artifact.get("conflicts", []) or []:
        if isinstance(item, dict):
            result.append((str(item["product"]), str(item.get("version", "*"))))
        else:
            product, _, spec = str(item).partition(" ")
            result.append((product, spec or "*"))
    return result


def _solve(catalog, roots):
    solutions = set()
    failures = []

    def expand(partial, ranges):
        for product, exact in roots.items():
            if product in partial and partial[product] != exact:
                failures.append(
                    f"target {product}:{exact} conflicts with {product}:{partial[product]}"
                )
                return
            partial[product] = exact

        versions = dict(partial)
        conflict_found = False
        for product, version in partial.items():
            artifact = catalog.get(product, {}).get(version)
            if artifact is None:
                failures.append(f"candidate not found: {product}:{version}")
                return
            for conflict_product, conflict_spec in _conflicts(artifact):
                actual = versions.get(conflict_product)
                if actual and version_satisfies(actual, conflict_spec):
                    conflict_found = True
                    failures.append(
                        f"{product}:{version} conflicts with {conflict_product}:{actual}"
                    )
        # Every selected artifact contributes a range to the one global slot
        # for that dependency product. This is what makes cycles common
        # constraints instead of two independently picked versions.
        next_ranges = dict(ranges)
        for product, version in partial.items():
            artifact = catalog[product][version]
            for dep_product, dep_spec in _requirements(artifact).items():
                previous = next_ranges.get(dep_product)
                combined = _intersect(previous, dep_spec)
                if dep_product in partial and not version_satisfies(
                    partial[dep_product], combined
                ):
                    failures.append(
                        f"shared {dep_product}:{partial[dep_product]} does not satisfy {combined}"
                    )
                    return
                next_ranges[dep_product] = combined
                matches = [
                    candidate_version
                    for candidate_version in catalog.get(dep_product, {})
                    if version_satisfies(candidate_version, combined)
                ]
                if not matches:
                    failures.append(
                        f"no candidate for {dep_product} satisfies {combined}"
                    )

        if conflict_found:
            return

        required_products = set(next_ranges)
        unchosen = sorted(p for p in required_products if p not in partial)
        if not unchosen:
            selected = {}
            for product, version in partial.items():
                if not version_satisfies(version, next_ranges.get(product)):
                    failures.append(
                        f"{product}:{version} does not satisfy {next_ranges.get(product)}"
                    )
                    return
                selected[(product, version)] = catalog[product][version]
            reasons = []
            for (product, version), artifact in selected.items():
                for conflict_product, conflict_spec in _conflicts(artifact):
                    actual = versions.get(conflict_product)
                    if actual and version_satisfies(actual, conflict_spec):
                        reasons.append(
                            f"{product}:{version} conflicts with {conflict_product}:{actual}"
                        )
            if reasons:
                failures.extend(sorted(set(reasons)))
            else:
                solutions.add(frozenset(selected))
            return

        product = unchosen[0]
        spec = next_ranges[product]
        matches = [
            version for version in sorted(catalog.get(product, {}))
            if version_satisfies(version, spec)
        ]
        if not matches:
            failures.append(f"no candidate for {product} satisfies {spec}")
            return
        for version in sorted(matches, key=_version_tuple, reverse=True):
            expand(dict(partial) | {product: version}, next_ranges)

    expand({}, {})
    unique_failures = []
    for reason in failures:
        if reason not in unique_failures:
            unique_failures.append(reason)
    if not solutions:
        return frozenset(), unique_failures
    return frozenset(solutions), []


def _selection_members(selection, catalog):
    versions = {product: version for product, version in selection}
    members = []
    for product, version in sorted(selection):
        artifact = catalog[product][version]
        members.append({
            "product": product,
            "version": version,
            "artifact_digest": artifact["artifact_digest"],
            "build_spec_digest": artifact["build_spec_digest"],
            "depends_on": [
                {"product": dep, "version": versions[dep]}
                for dep in sorted(_requirements(artifact)) if dep in versions
            ],
        })
    return members


def _changes(selection, current_versions):
    return sorted(
        f"{product}:{current_versions.get(product, '<absent>')}->{version}"
        for product, version in selection
        if current_versions.get(product) != version
    )


def _content_sources(selection, catalog):
    sources = {}
    for product, version in sorted(selection):
        artifact = catalog[product][version]
        if "artifact_path" in artifact and "build_spec_path" in artifact:
            sources[f"{product}:{version}"] = {
                "artifact_path": artifact["artifact_path"],
                "build_spec_path": artifact["build_spec_path"],
            }
    return sources


def _shared_dependencies(spec):
    counts = {}
    for member in spec.get("members", []):
        source = f"{member['product']}:{member['version']}"
        for dep in member.get("depends_on", []):
            counts.setdefault((dep["product"], dep["version"]), []).append(source)
    return [
        {"product": product, "version": version, "depended_by": sorted(sources)}
        for (product, version), sources in sorted(counts.items())
        if len(set(sources)) > 1
    ]


def plan_collection_upgrade(*, name, version, artifacts, targets, policy, now,
                            current=None, approvals_by_candidate=None,
                            available_approvals=None):
    policy_obj = policy if isinstance(policy, ReleasePolicy) else ReleasePolicy.from_dict(policy)
    catalog = _catalog(artifacts)
    target_pairs = []
    for item in targets:
        if isinstance(item, dict):
            target_pairs.append((str(item["product"]), str(item["version"])))
        else:
            product, _, item_version = str(item).partition(":")
            target_pairs.append((product, item_version))
    current_spec = (
        (current or {}).get("spec")
        if isinstance(current, dict) and isinstance(current.get("spec"), dict)
        else current
    )
    current_members = (current_spec or {}).get("members", [])
    current_versions = {
        str(member["product"]): str(member["version"])
        for member in current_members
    }
    approvals_by_candidate = approvals_by_candidate or {}
    available_approvals = available_approvals or []
    options_by_id = {}
    infeasible = []

    for size in range(len(target_pairs), 0, -1):
        for subset in combinations(target_pairs, size):
            roots = dict(subset)
            solution_sets, reasons = _solve(catalog, roots)
            if not solution_sets:
                if size == len(target_pairs):
                    infeasible.append({
                        "targets": [f"{p}:{v}" for p, v in subset],
                        "reasons": reasons,
                    })
                continue
            by_change = sorted(
                solution_sets,
                key=lambda solution: len(_changes(solution, current_versions)),
            )
            minimum_change = len(_changes(by_change[0], current_versions))
            solution = max(
                (item for item in by_change
                 if len(_changes(item, current_versions)) == minimum_change),
                key=lambda item: tuple(
                    _version_tuple(version) for _, version in sorted(item)
                ),
            )
            solutions_to_consider = [solution]
            for solution in solutions_to_consider:
                members = _selection_members(solution, catalog)
                spec = coll.build_spec(name=name, version=version, members=members)
                nonce = canonical_hash({
                    "purpose": "collection-upgrade-option",
                    "spec": spec,
                    "policy": policy_obj.to_dict(),
                }).split(":", 1)[1][:32]
                candidate = coll.build_candidate(spec=spec, policy=policy_obj,
                                                 now=now, nonce=nonce)
                selected_versions = dict(solution)
                covered = sorted(f"{p}:{v}" for p, v in subset)
                changed = _changes(solution, current_versions)
                issuers = {role: set() for role in policy_obj.requirements}
                envelopes = list(approvals_by_candidate.get(
                    candidate["candidate_digest"], []
                ))
                envelopes.extend(
                    envelope for envelope in available_approvals
                    if envelope not in envelopes
                )
                for envelope in envelopes:
                    approval = envelope.get("approval", envelope)
                    role = approval.get("role")
                    if role in issuers and approval.get("candidate_digest") == candidate["candidate_digest"]:
                        issuers[role].add(approval.get("issuer_id"))
                missing = {
                    role: count for role, count in policy_obj.requirements.items()
                    if len(issuers.get(role, set())) < count
                }
                option = {
                    "type": OPTION_TYPE,
                    "option_id": candidate["candidate_id"],
                    "candidate": candidate,
                    "members": members,
                    "content_sources": _content_sources(solution, catalog),
                    "covered_targets": covered,
                    "changed_members": changed,
                    "change_count": len(changed),
                    "target_coverage": len(subset),
                    "technically_compatible": True,
                    "approvals_complete": not missing,
                    "approval_counts": {r: len(issuers.get(r, set())) for r in policy_obj.requirements},
                    "missing_approval_roles": missing,
                    "shared_dependencies": _shared_dependencies(spec),
                    "cycles": coll.find_cycles(spec),
                }
                previous = options_by_id.get(option["option_id"])
                if (
                    previous is None
                    or len(covered) > len(previous["covered_targets"])
                    or (
                        len(covered) == len(previous["covered_targets"])
                        and len(changed) < previous["change_count"]
                    )
                ):
                    options_by_id[option["option_id"]] = option

    ranked = sorted(options_by_id.values(), key=lambda o: (
        -o["target_coverage"], o["change_count"],
        tuple(o["changed_members"]), o["option_id"],
    ))
    for index, option in enumerate(ranked):
        option["rank"] = index
    max_coverage = max((o["target_coverage"] for o in ranked), default=0)
    minimum_changes = min((o["change_count"] for o in ranked), default=None)
    plan = {
        "type": PLAN_TYPE,
        "generated_at": now,
        "name": name,
        "version": version,
        "targets": [f"{p}:{v}" for p, v in target_pairs],
        "options": ranked,
        "recommendation": {
            "maximum_target_coverage": max_coverage,
            "minimum_changes": minimum_changes,
            "maximum_coverage_option_id": next((o["option_id"] for o in ranked if o["target_coverage"] == max_coverage), None),
            "minimum_change_option_id": next((o["option_id"] for o in ranked if o["change_count"] == minimum_changes), None),
        },
        "infeasible": infeasible,
        "notes": [
            "technical compatibility means dependency ranges and mutex conditions are satisfied",
            "approval completeness is separate and is rechecked at confirmation",
            "already published collections are never rewritten",
        ],
    }
    plan["plan_id"] = canonical_hash({k: v for k, v in plan.items() if k != "plan_id"})
    return plan
