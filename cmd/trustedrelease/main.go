package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"trustedrelease/internal/attest"
	"trustedrelease/internal/issuer"
	"trustedrelease/internal/keys"
	"trustedrelease/internal/store"
	"trustedrelease/internal/verify"
)

type release struct {
	Version        string    `json:"version"`
	ArtifactDigest string    `json:"artifact_digest"`
	BuildDigest    string    `json:"build_digest"`
	IssuerID       string    `json:"issuer_id"`
	Serial         string    `json:"attestation_serial"`
	ReleasedAt     time.Time `json:"released_at"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: trustedrelease <keygen|register|attest|verify|revoke|release> [flags]")
}

func run(cmd string, args []string) error {
	now := time.Now()
	switch cmd {
	case "keygen":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		root := fs.String("root", ".trusted", "local trusted store directory")
		name := fs.String("name", "", "issuer id")
		display := fs.String("display", "", "human-readable issuer name")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if *name == "" {
			return fmt.Errorf("-name is required")
		}
		s, err := store.Open(*root)
		if err != nil {
			return err
		}
		pub, priv, err := keys.Generate()
		if err != nil {
			return err
		}
		if _, err := issuer.Create(s, *name, nonEmpty(*display, *name), pub, now); err != nil {
			return err
		}
		keyPath := s.Path("keys", *name+".key")
		if err := keys.WritePrivatePEM(keyPath, priv); err != nil {
			return err
		}
		fmt.Printf("registered issuer %s\nwrote temporary test key %s\n", *name, keyPath)
		return nil

	case "register":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		root := fs.String("root", ".trusted", "local trusted store directory")
		artifact := fs.String("artifact", "", "artifact file")
		build := fs.String("build", "", "build instructions file")
		if err := fs.Parse(args); err != nil {
			return err
		}
		s, err := store.Open(*root)
		if err != nil {
			return err
		}
		return registerArtifact(s, *artifact, *build, now)

	case "attest":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		root := fs.String("root", ".trusted", "local trusted store directory")
		artifact := fs.String("artifact", "", "artifact file")
		build := fs.String("build", "", "build instructions file")
		issuerID := fs.String("issuer", "", "registered issuer id")
		keyPath := fs.String("key", "", "issuer Ed25519 private key PEM")
		ttl := fs.Duration("ttl", 24*time.Hour, "attestation lifetime")
		if err := fs.Parse(args); err != nil {
			return err
		}
		s, err := store.Open(*root)
		if err != nil {
			return err
		}
		return attestArtifact(s, *artifact, *build, *issuerID, *keyPath, *ttl, now)

	case "verify":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		root := fs.String("root", ".trusted", "local trusted store directory")
		artifact := fs.String("artifact", "", "artifact file")
		build := fs.String("build", "", "build instructions file")
		if err := fs.Parse(args); err != nil {
			return err
		}
		s, err := store.Open(*root)
		if err != nil {
			return err
		}
		res, err := verify.Verify(s, *artifact, *build, verify.Options{Now: now})
		if err != nil {
			return err
		}
		fmt.Printf("VERIFIED trusted artifact\n  artifact: %s\n  build:    %s\n  issuer:   %s\n  serial:   %s\n", res.ArtifactDigest, res.BuildDigest, res.Issuer.ID, res.Envelope.Payload.Serial)
		return nil

	case "revoke":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		root := fs.String("root", ".trusted", "local trusted store directory")
		artifact := fs.String("artifact", "", "artifact file")
		reason := fs.String("reason", "revoked", "revocation reason")
		if err := fs.Parse(args); err != nil {
			return err
		}
		s, err := store.Open(*root)
		if err != nil {
			return err
		}
		digest, _, err := store.DigestFile(*artifact)
		if err != nil {
			return err
		}
		env, err := store.ReadJSON[attest.Envelope](s.Path(store.AttestationPath(digest)))
		if err != nil {
			return fmt.Errorf("attestation missing: %w", err)
		}
		if err := issuer.Revoke(s, env, *reason, now); err != nil {
			return err
		}
		fmt.Printf("revoked attestation %s\n", env.Payload.Serial)
		return nil

	case "release":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		root := fs.String("root", ".trusted", "local trusted store directory")
		artifact := fs.String("artifact", "", "artifact file")
		build := fs.String("build", "", "build instructions file")
		version := fs.String("version", "", "version to publish")
		if err := fs.Parse(args); err != nil {
			return err
		}
		s, err := store.Open(*root)
		if err != nil {
			return err
		}
		res, err := verify.Verify(s, *artifact, *build, verify.Options{Now: now})
		if err != nil {
			return fmt.Errorf("refusing to publish untrusted version: %w", err)
		}
		if err := validateVersion(*version); err != nil {
			return err
		}
		rel := release{Version: *version, ArtifactDigest: res.ArtifactDigest, BuildDigest: res.BuildDigest, IssuerID: res.Issuer.ID, Serial: res.Envelope.Payload.Serial, ReleasedAt: now.UTC()}
		relPath := filepath.Join("releases", "release-"+sanitizeVersion(*version)+".json")
		if _, err := os.Stat(s.Path(relPath)); err == nil {
			return fmt.Errorf("version %s already exists", *version)
		}
		if err := s.WriteJSON(relPath, rel); err != nil {
			return err
		}
		fmt.Printf("published trusted version %s (%s)\n", *version, res.ArtifactDigest)
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func registerArtifact(s *store.Store, artifactPath, buildPath string, now time.Time) error {
	if artifactPath == "" || buildPath == "" {
		return fmt.Errorf("-artifact and -build are required")
	}
	artifactData, err := os.ReadFile(artifactPath)
	if err != nil {
		return err
	}
	buildData, err := os.ReadFile(buildPath)
	if err != nil {
		return err
	}
	artifactDigest, err := s.PutObject(artifactData)
	if err != nil {
		return err
	}
	buildDigest, err := s.PutObject(buildData)
	if err != nil {
		return err
	}
	m := store.Manifest{
		ArtifactDigest:  artifactDigest,
		OriginalName:    filepath.Base(artifactPath),
		BuildDigest:     buildDigest,
		BuildSourcePath: buildPath,
		RegisteredAt:    now.UTC().Format(time.RFC3339),
	}
	if err := s.WriteJSON(store.ManifestPath(artifactDigest), m); err != nil {
		return err
	}
	fmt.Printf("registered %s\n  artifact: %s\n  build:    %s\n", filepath.Base(artifactPath), artifactDigest, buildDigest)
	return nil
}

func attestArtifact(s *store.Store, artifactPath, buildPath, issuerID, keyPath string, ttl time.Duration, now time.Time) error {
	if artifactPath == "" || buildPath == "" || issuerID == "" || keyPath == "" {
		return fmt.Errorf("-artifact, -build, -issuer and -key are required")
	}
	if ttl <= 0 {
		return fmt.Errorf("-ttl must be positive")
	}
	artifactDigest, _, err := store.DigestFile(artifactPath)
	if err != nil {
		return err
	}
	buildDigest, _, err := store.DigestFile(buildPath)
	if err != nil {
		return err
	}
	manifest, err := store.ReadJSON[store.Manifest](s.Path(store.ManifestPath(artifactDigest)))
	if err != nil {
		return fmt.Errorf("artifact must be registered before attestation: %w", err)
	}
	if manifest.BuildDigest != buildDigest {
		return fmt.Errorf("build instructions differ from the registered declaration")
	}
	info, pub, err := issuer.Load(s, issuerID)
	if err != nil {
		return err
	}
	key, err := keys.ReadPrivatePEM(keyPath)
	if err != nil {
		return err
	}
	if !bytes.Equal([]byte(key.Public().(ed25519.PublicKey)), []byte(pub)) {
		return fmt.Errorf("private key does not match registered public key for issuer %s", info.ID)
	}
	serialBytes := make([]byte, 16)
	if _, err := rand.Read(serialBytes); err != nil {
		return err
	}
	claims := attest.Claims{
		Version:        1,
		Serial:         hex.EncodeToString(serialBytes),
		IssuerID:       issuerID,
		ArtifactDigest: artifactDigest,
		BuildDigest:    buildDigest,
		IssuedAt:       now.UTC().Format(time.RFC3339),
		ExpiresAt:      now.Add(ttl).UTC().Format(time.RFC3339),
	}
	env, err := attest.Sign(claims, key)
	if err != nil {
		return err
	}
	if err := s.WriteJSON(store.AttestationPath(artifactDigest), env); err != nil {
		return err
	}
	fmt.Printf("signed attestation %s for %s\n", claims.Serial, artifactDigest)
	return nil
}

func nonEmpty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

var versionRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)

func validateVersion(v string) error {
	if !versionRE.MatchString(v) {
		return fmt.Errorf("invalid version %q", v)
	}
	return nil
}

func sanitizeVersion(v string) string {
	return v
}
