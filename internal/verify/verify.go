package verify

import (
	"fmt"
	"time"

	"trustedrelease/internal/attest"
	"trustedrelease/internal/issuer"
	"trustedrelease/internal/store"
)

type Result struct {
	ArtifactDigest string
	BuildDigest    string
	Envelope       *attest.Envelope
	Issuer         *issuer.Issuer
}

type Options struct {
	Now time.Time
}

// Verify 在使用/发布前执行完整核对：
//  1. 重新计算实际制品与构建说明摘要；
//  2. 登记记录必须把两者关联起来；
//  3. 证明必须存在且签名可由已登记签发者公钥验证；
//  4. 证明中的摘要必须等于当前实际摘要（改名不受影响，内容替换立即失败）；
//  5. 证明未过期、未撤销。
func Verify(s *store.Store, artifactPath, buildPath string, opts Options) (*Result, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	artifactDigest, _, err := store.DigestFile(artifactPath)
	if err != nil {
		return nil, fmt.Errorf("read artifact: %w", err)
	}
	buildDigest, _, err := store.DigestFile(buildPath)
	if err != nil {
		return nil, fmt.Errorf("read build instructions: %w", err)
	}

	manifest, err := store.ReadJSON[store.Manifest](s.Path(store.ManifestPath(artifactDigest)))
	if err != nil {
		return nil, fmt.Errorf("artifact is not registered: %w", err)
	}
	if manifest.BuildDigest != buildDigest {
		return nil, fmt.Errorf("build instructions mismatch: registered %s, current %s", manifest.BuildDigest, buildDigest)
	}
	if !s.HasObject(artifactDigest) {
		return nil, fmt.Errorf("%w: %s", store.ErrObjectMissing, artifactDigest)
	}

	envPath := s.Path(store.AttestationPath(artifactDigest))
	env, err := store.ReadJSON[attest.Envelope](envPath)
	if err != nil {
		return nil, fmt.Errorf("%w for artifact %s", store.ErrAttestationMissing, artifactDigest)
	}
	if env.Payload.ArtifactDigest != artifactDigest {
		return nil, fmt.Errorf("attestation is bound to another artifact")
	}
	if env.Payload.BuildDigest != buildDigest {
		return nil, fmt.Errorf("attestation is bound to other build instructions")
	}

	info, pub, err := issuer.Load(s, env.Payload.IssuerID)
	if err != nil {
		return nil, err
	}
	if err := env.Verify(pub); err != nil {
		return nil, err
	}
	issuedAt, err := time.Parse(time.RFC3339, env.Payload.IssuedAt)
	if err != nil {
		return nil, fmt.Errorf("invalid issued_at: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, env.Payload.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("invalid expires_at: %w", err)
	}
	if now.Before(issuedAt) {
		return nil, fmt.Errorf("attestation is not valid yet (issued_at=%s)", issuedAt.Format(time.RFC3339))
	}
	if !now.Before(expiresAt) {
		return nil, fmt.Errorf("attestation expired at %s", expiresAt.Format(time.RFC3339))
	}
	revoked, err := issuer.IsRevoked(s, env.Payload.Serial)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, fmt.Errorf("attestation serial %s has been revoked", env.Payload.Serial)
	}

	return &Result{ArtifactDigest: artifactDigest, BuildDigest: buildDigest, Envelope: env, Issuer: info}, nil
}
