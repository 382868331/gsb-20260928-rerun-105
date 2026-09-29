package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Store 是本地可信仓库的根目录。制品内容、构建说明、签发者关系分目录保存，
// 后续接入更多构建来源时只需新增登记来源，不影响内容寻址与验证逻辑。
type Store struct{ Root string }

func Open(root string) (*Store, error) {
	if root == "" {
		root = ".trusted"
	}
	for _, dir := range []string{"objects", "manifests", "attestations", "issuers", "revocations", "releases", "keys"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			return nil, err
		}
	}
	return &Store{Root: root}, nil
}

func (s *Store) Path(parts ...string) string {
	return filepath.Join(append([]string{s.Root}, parts...)...)
}

// DigestBytes 返回内容的 SHA-256 摘要。制品身份只取决于实际字节，
// 与文件名无关，因此改名不等于换内容。
func DigestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func DigestFile(path string) (string, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	return DigestBytes(data), data, nil
}

// PutObject 以内容摘要为键保存内容。内容一旦不同就落到不同对象，
// 旧证明无法沿用到替换后的内容。
func (s *Store) PutObject(data []byte) (string, error) {
	digest := DigestBytes(data)
	rel, err := ObjectRel(digest)
	if err != nil {
		return "", err
	}
	full := s.Path("objects", rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(full, data, 0o644); err != nil {
		return "", err
	}
	return digest, nil
}

func (s *Store) HasObject(digest string) bool {
	rel, err := ObjectRel(digest)
	if err != nil {
		return false
	}
	_, err = os.Stat(s.Path("objects", rel))
	return err == nil
}

func ObjectRel(digest string) (string, error) {
	hexPart, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || len(hexPart) != sha256.Size*2 {
		return "", fmt.Errorf("invalid digest %q", digest)
	}
	return filepath.Join(hexPart[:2], hexPart[2:]), nil
}

type Manifest struct {
	ArtifactDigest  string `json:"artifact_digest"`
	OriginalName    string `json:"original_name"`
	BuildDigest     string `json:"build_digest"`
	BuildSourcePath string `json:"build_source_path"`
	RegisteredAt    string `json:"registered_at"`
}

func (s *Store) WriteJSON(rel string, v any) error {
	full := s.Path(rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := full + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, full)
}

func ReadJSON[T any](path string) (*T, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func ManifestPath(digest string) string {
	return filepath.Join("manifests", "register-"+strings.TrimPrefix(digest, "sha256:")+".json")
}

func AttestationPath(digest string) string {
	return filepath.Join("attestations", "att-"+strings.TrimPrefix(digest, "sha256:")+".json")
}

func (s *Store) CopyFile(path string) (io.WriteCloser, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	return os.Create(path)
}

// Sentinel errors give callers explicit, testable failure reasons.
var (
	ErrAttestationMissing = errors.New("attestation missing")
	ErrObjectMissing      = errors.New("content object missing")
)
