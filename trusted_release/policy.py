"""Release quorum policies and approval policy binding."""

from __future__ import annotations

from dataclasses import dataclass, field

from .encoding import canonical_hash, canonical_json

POLICY_TYPE = "trusted-release/release-policy/v1"
CANDIDATE_TYPE = "trusted-release/release-candidate/v1"
APPROVAL_TYPE = "trusted-release/approval/v1"
RELEASE_TYPE_V2 = "trusted-release/release/v2"

SET_CANDIDATE_TYPE = "trusted-release/set-candidate/v1"
SET_APPROVAL_TYPE = "trusted-release/set-approval/v1"
SET_RELEASE_TYPE = "trusted-release/release-set/v1"


@dataclass(frozen=True)
class ReleasePolicy:
    policy_id: str
    policy_version: int
    requirements: dict[str, int] = field(default_factory=dict)

    @staticmethod
    def from_dict(data: dict) -> "ReleasePolicy":
        if data.get("type") not in (None, POLICY_TYPE):
            raise ValueError("unsupported policy type")
        requirements = {
            str(role): int(count)
            for role, count in data["requirements"].items()
            if int(count) > 0
        }
        if not requirements:
            raise ValueError("release policy must require at least one approval")
        if any(count <= 0 for count in requirements.values()):
            raise ValueError("role requirement must be positive")
        return ReleasePolicy(
            policy_id=str(data["policy_id"]),
            policy_version=int(data["policy_version"]),
            requirements=dict(sorted(requirements.items())),
        )

    def to_dict(self) -> dict:
        return {
            "type": POLICY_TYPE,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "requirements": dict(self.requirements),
        }

    @property
    def digest(self) -> str:
        return canonical_hash(self.to_dict())


def validate_policy_bundle(record_policy: dict) -> ReleasePolicy:
    policy = ReleasePolicy.from_dict(record_policy)
    if canonical_json(policy.to_dict()) != canonical_json(record_policy):
        raise ValueError("policy canonicalization mismatch")
    return policy
