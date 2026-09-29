package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trustedrelease/internal/attest"
	"trustedrelease/internal/store"
)

func setupArtifact(t *testing.T, ttl time.Duration) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	artifact := filepath.Join(root, "artifact.bin")
	build := filepath.Join(root, "build.json")
	must(t, os.WriteFile(artifact, []byte("complete artifact payload"), 0o600))
	must(t, os.WriteFile(build, []byte(`{"command":"make package","source":"local"}`), 0o600))
	mustRun(t, "keygen", "-root", root, "-name", "ci", "-display", "Local CI")
	mustRun(t, "register", "-root", root, "-artifact", artifact, "-build", build)
	mustRun(t, "attest", "-root", root, "-artifact", artifact, "-build", build,
		"-issuer", "ci", "-key", filepath.Join(root, "keys", "ci.key"), "-ttl", ttl.String())
	return root, artifact, build
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustRun(t *testing.T, args ...string) {
	t.Helper()
	if err := run(args[0], args[1:]); err != nil {
		t.Fatalf("%s failed: %v", strings.Join(args, " "), err)
	}
}

func runExpectError(t *testing.T, want string, args ...string) {
	t.Helper()
	err := run(args[0], args[1:])
	if err == nil {
		t.Fatalf("%s unexpectedly succeeded", strings.Join(args, " "))
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %q, want substring %q", err.Error(), want)
	}
}

func releaseExists(t *testing.T, root, version string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(root, "releases", "release-"+version+".json"))
	return err == nil
}

func TestCompleteArtifactVerifiesAndReleases(t *testing.T) {
	root, artifact, build := setupArtifact(t, time.Hour)
	mustRun(t, "verify", "-root", root, "-artifact", artifact, "-build", build)
	mustRun(t, "release", "-root", root, "-artifact", artifact, "-build", build, "-version", "v1.0.0")
	if !releaseExists(t, root, "v1.0.0") {
		t.Fatal("trusted release was not published")
	}
}

func TestRenamedArtifactStillVerifiesBecauseIdentityIsContent(t *testing.T) {
	root, artifact, build := setupArtifact(t, time.Hour)
	renamed := filepath.Join(root, "downloaded-with-different-name.bin")
	must(t, os.Rename(artifact, renamed))
	mustRun(t, "verify", "-root", root, "-artifact", renamed, "-build", build)
	mustRun(t, "release", "-root", root, "-artifact", renamed, "-build", build, "-version", "v1.0.1")
}

func TestModifiedArtifactCannotReuseOldAttestationOrRelease(t *testing.T) {
	root, artifact, build := setupArtifact(t, time.Hour)
	must(t, os.WriteFile(artifact, []byte("replaced artifact payload"), 0o600))
	runExpectError(t, "artifact is not registered", "verify", "-root", root, "-artifact", artifact, "-build", build)
	runExpectError(t, "refusing to publish untrusted version", "release", "-root", root, "-artifact", artifact, "-build", build, "-version", "v1.1.0")
	if releaseExists(t, root, "v1.1.0") {
		t.Fatal("modified artifact was released")
	}
}

func TestModifiedBuildInstructionsFail(t *testing.T) {
	root, artifact, build := setupArtifact(t, time.Hour)
	must(t, os.WriteFile(build, []byte(`{"command":"make backdoor"}`), 0o600))
	runExpectError(t, "build instructions mismatch", "verify", "-root", root, "-artifact", artifact, "-build", build)
}

func TestExpiredAttestationFails(t *testing.T) {
	root, artifact, build := setupArtifact(t, time.Nanosecond)
	time.Sleep(2 * time.Millisecond)
	runExpectError(t, "attestation expired", "verify", "-root", root, "-artifact", artifact, "-build", build)
	runExpectError(t, "refusing to publish untrusted version", "release", "-root", root, "-artifact", artifact, "-build", build, "-version", "v2.0.0")
}

func TestRevokedAttestationFails(t *testing.T) {
	root, artifact, build := setupArtifact(t, time.Hour)
	mustRun(t, "revoke", "-root", root, "-artifact", artifact, "-reason", "security incident")
	runExpectError(t, "has been revoked", "verify", "-root", root, "-artifact", artifact, "-build", build)
	runExpectError(t, "refusing to publish untrusted version", "release", "-root", root, "-artifact", artifact, "-build", build, "-version", "v3.0.0")
}

func TestAttestationFileRemovedFails(t *testing.T) {
	root, artifact, build := setupArtifact(t, time.Hour)
	digest, _, err := store.DigestFile(artifact)
	must(t, err)
	must(t, os.Remove(filepath.Join(root, store.AttestationPath(digest))))
	runExpectError(t, "attestation missing", "verify", "-root", root, "-artifact", artifact, "-build", build)
}

func TestSignatureDoesNotVerifyAfterClaimsTampering(t *testing.T) {
	root, artifact, build := setupArtifact(t, time.Hour)
	digest, _, err := store.DigestFile(artifact)
	must(t, err)
	path := filepath.Join(root, store.AttestationPath(digest))
	env, err := store.ReadJSON[attest.Envelope](path)
	must(t, err)
	env.Signature[0] ^= 1
	must(t, (&store.Store{Root: root}).WriteJSON(store.AttestationPath(digest), env))
	runExpectError(t, "signature does not match claims", "verify", "-root", root, "-artifact", artifact, "-build", build)
}
