"""Compatible upgrade planning for release collections.

The planner treats a release as one global constraint problem: one product
has exactly one selected version, every dependency range must have a common
concrete selected version, and mutual-exclusion rules are checked against the
complete selection. Cycles therefore impose mutual constraints instead of
depending on which member a graph traversal visits first.
"""

from __future__ import annotations

from itertools import combinations, product as cartesian_product
from .encoding import canonical_hash

PLAN_TYPE = "trusted-release/collection-upgrade-plan/v1"


def _version_key(version: str) -> tuple:
    parts = []
    for part in str(version).split("."):
        try:
            parts.append((0, int(part)))
        except ValueError:
            parts.append((1, part))
    return tuple(parts)


def _compare_versions(left: str, right: str) -> int:
    a, b = _version_key(left), _version_key(right)
    if a < b:
        return -1
    if a > b:
        return 1
    return 0


def version_satisfies(version: str, specifier: str) -> bool:
    """Match comma-separated simple ranges such as >=1.0,<2.0."""
    text = str(specifier).strip()
    if not text or text == "*":
        return True
    for clause in text.split(","):
        clause = clause.strip()
        for op in (">=", "<=", "==", "!=", "~=", ">", "<", "="):
            if clause.startswith(op):
                wanted = clause[len(op):].strip()
                break
        else:
            wanted = clause
            op = "=="
        cmp = _compare_versions(version, wanted)
        if op == "=":
            ok = cmp == 0
        elif op == "==":
            ok = cmp == 0
        elif op == "!=":
            ok = cmp != 0
        elif op == ">":
            ok = cmp > 0
        elif op == ">=":
            ok = cmp >= 0
        elif op == "<":
            ok = cmp < 0
        elif op == "<=":
            ok = cmp <= 0
        elif op == "~=":
            left_parts = str(version).split(".")
            wanted_parts = wanted.split(".")
            ok = (
                cmp >= 0
                and left_parts[:-1] == wanted_parts[:-1]
                and bool(wanted_parts[:-1])
            )
        else:
            ok = False
        if not ok:
            return False
    return True


def _candidate_key(candidate: dict) -> tuple[str, str]:
    return str(candidate["product"]), str(candidate["version"])


def _constraint(constraint: dict) -> tuple[str, str]:
    return str(constraint["product"]), str(
        constraint.get("specifier", constraint.get("version_range", "*"))
    )


def _requirements(candidate: dict) -> list[dict]:
    for field in ("requires", "depends_on_ranges", "constraints"):
        if field in candidate:
            return candidate[field]
    ranges = []
    for raw in candidate.get("depends_on", []):
        if "specifier" in raw or "version_range" in raw:
            ranges.append(raw)
    return ranges


def _conflicts(candidate: dict) -> list[dict]:
    for field in ("conflicts_with", "mutually_exclusive_with", "conflicts"):
        if field in candidate:
            return candidate[field]
    return []


def _selection_is_valid(selected: dict[tuple[str, str], dict]) -> list[str]:
    by_product = {key[0]: candidate for key, candidate in selected.items()}
    errors = []
    for key, candidate in sorted(selected.items()):
        source = f"{key[0]}:{key[1]}"
        for raw in _requirements(candidate):
            dep_product, spec = _constraint(raw)
            dependency = by_product.get(dep_product)
            if dependency is None:
                errors.append(f"{source} requires {dep_product} {spec}, but no version is selected")
            elif not version_satisfies(dependency["version"], spec):
                errors.append(
                    f"{source} requires {dep_product} {spec}; selected "
                    f"{dependency['version']} is outside that range"
                )
        for raw in _conflicts(candidate):
            other_product, spec = _constraint(raw)
            other = by_product.get(other_product)
            if other is not None and version_satisfies(other["version"], spec):
                errors.append(
                    f"{source} conflicts with {other_product}:{other['version']} "
                    f"matching {spec}"
                )
    return errors


def _member_from_candidate(candidate: dict, selected: dict[tuple[str, str], dict]) -> dict:
    member = {
        "product": candidate["product"],
        "version": candidate["version"],
        "artifact_digest": candidate["artifact_digest"],
        "build_spec_digest": candidate["build_spec_digest"],
        "depends_on": [],
    }
    for raw in _requirements(candidate):
        dep_product = str(raw["product"])
        dep = next((c for (product, _), c in selected.items() if product == dep_product), None)
        if dep is not None:
            member["depends_on"].append({"product": dep_product, "version": dep["version"]})
    return member


def plan_compatible_upgrade(
    *,
    candidates: list[dict],
    targets: list[str | tuple[str, str] | dict],
    current_members: list[dict] | None = None,
) -> dict:
    """Return globally feasible upgrade combinations and objective rankings."""
    options_by_product: dict[str, list[dict]] = {}
    candidate_by_key: dict[tuple[str, str], dict] = {}
    for candidate in candidates:
        key = _candidate_key(candidate)
        if key in candidate_by_key:
            raise ValueError(f"duplicate candidate {key[0]}:{key[1]}")
        candidate_by_key[key] = candidate
        options_by_product.setdefault(key[0], []).append(candidate)
    for versions in options_by_product.values():
        versions.sort(key=lambda c: _version_key(c["version"]))

    target_keys: set[tuple[str, str]] = set()
    for target in targets:
        if isinstance(target, str):
            if target not in options_by_product:
                raise ValueError(f"target product {target} has no candidates")
            target_keys.update(_candidate_key(c) for c in options_by_product[target])
        elif isinstance(target, tuple):
            target_keys.add((str(target[0]), str(target[1])))
        else:
            target_keys.add((str(target["product"]), str(target["version"])))
    missing = sorted(key for key in target_keys if key not in candidate_by_key)
    if missing:
        raise ValueError("unknown target candidates: " + ", ".join(f"{p}:{v}" for p, v in missing))

    current = {}
    for m in current_members or []:
        key = (str(m["product"]), str(m["version"]))
        current[key] = {
            "product": key[0],
            "version": key[1],
            "artifact_digest": m.get("artifact_digest"),
            "build_spec_digest": m.get("build_spec_digest"),
            "requires": [
                {"product": str(d["product"]), "specifier": f"=={d['version']}"}
                for d in m.get("depends_on", [])
            ],
        }
    feasible = []
    failures: list[str] = []

    def solve(desired: set[tuple[str, str]]) -> None:
        selected = dict(current)
        for key in desired:
            for old_key in [old for old in selected if old[0] == key[0]]:
                selected.pop(old_key)
            selected[key] = candidate_by_key[key]
        required_products = {key[0] for key in selected}
        changed = True
        while changed:
            changed = False
            for candidate in list(selected.values()):
                for raw in _requirements(candidate):
                    product = str(raw["product"])
                    if product not in required_products:
                        required_products.add(product)
                        changed = True
        choice_products = sorted(required_products)
        product_options = []
        missing_dependency = False
        for p in choice_products:
            if p in options_by_product:
                product_options.append(options_by_product[p])
            elif any(product == p for product, _ in current):
                product_options.append([c for (product, _), c in current.items() if product == p])
            else:
                failures.append(f"required product {p} has no selectable candidate")
                missing_dependency = True
        if missing_dependency:
            return
        for values in cartesian_product(*product_options):
            trial = dict(current)
            for product, candidate in zip(choice_products, values):
                for old_key in [old for old in trial if old[0] == product]:
                    trial.pop(old_key)
                trial[(product, candidate["version"])] = candidate
            errors = _selection_is_valid(trial)
            if errors:
                failures.extend(errors)
                continue
            current_products = {p for p, _ in current}
            selected_products = {p for p, _ in trial}
            added = sorted(selected_products - current_products)
            removed = sorted(current_products - selected_products)
            desired_products = {p for p, _ in desired}
            non_target_deviations = [
                key for key in trial
                if key[0] not in desired_products
                and (
                    key[0] not in current_products
                    or (key[0], next(
                        version for product, version in current if product == key[0]
                    )) != key
                )
            ]
            changed_keys = sorted(
                key for key in trial
                if key in current and key not in desired
                and (
                    current[key].get("artifact_digest") != trial[key].get("artifact_digest")
                    or current[key].get("build_spec_digest") != trial[key].get("build_spec_digest")
                ))
            target_selected = desired.issubset(trial)
            members = [
                _member_from_candidate(candidate, trial)
                for _, candidate in sorted(trial.items())
            ]
            signature = canonical_hash(members)
            feasible.append({
                "id": signature.split(":", 1)[1][:24],
                "targets": [f"{p}:{v}" for p, v in sorted(desired)],
                "target_coverage": [
                    f"{p}:{v}" for p, v in sorted(desired & set(trial))
                ],
                "coverage_count": len(desired & set(trial)),
                "selected": [f"{p}:{v}" for p, v in sorted(trial)],
                "members": members,
                "technically_compatible": target_selected,
                "added_members": added,
                "removed_members": removed,
                "changed_content": [f"{p}:{v}" for p, v in changed_keys],
                "change_count": (
                    len(desired)
                    + len(non_target_deviations)
                    + len(removed)
                    + len(changed_keys)
                ),
                "conflicts": [],
            })

    # Try the complete request first, then progressively smaller target sets
    # so maximum target coverage can still be reported when one target is stuck.
    sizes = range(len(target_keys), 0, -1)
    for size in sizes:
        for desired_set in combinations(sorted(target_keys), size):
            solve(set(desired_set))

    unique = {option["id"]: option for option in feasible}
    for option in unique.values():
        option["minimum_changes"] = option["change_count"]
    options = sorted(
        unique.values(),
        key=lambda o: (-o["coverage_count"], o["change_count"], o["selected"]),
    )
    for index, option in enumerate(options):
        option["rank"] = index
    full = [o for o in options if o["coverage_count"] == len(target_keys)]
    reason_counts: dict[str, int] = {}
    for reason in failures:
        reason_counts[reason] = reason_counts.get(reason, 0) + 1
    return {
        "type": PLAN_TYPE,
        "feasible": bool(full),
        "targets": [f"{p}:{v}" for p, v in sorted(target_keys)],
        "options": options,
        "recommended": options[0] if options else None,
        "maximum_coverage": options[0] if options else None,
        "minimum_changes_option": min(
            options,
            key=lambda o: (o["change_count"], -o["coverage_count"], o["selected"]),
            default=None,
        ),
        "unsatisfied_constraints": [
            {"reason": reason, "occurrences": count}
            for reason, count in sorted(reason_counts.items())
        ],
    }


plan_collection_upgrade = plan_compatible_upgrade
plan_upgrade = plan_compatible_upgrade
