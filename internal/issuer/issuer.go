package issuer

import (
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"regexp"
	"time"

	"trustedrelease/internal/attest"
	"trustedrelease/internal/keys"
	"trustedrelease/internal/store"
)

type Issuer struct {
	ID           string    `json:"id"`
	DisplayName  string    `json:"display_name"`
	PublicKeyPEM string    `json:"public_key_pem"`
	CreatedAt    time.Time `json:"created_at"`
}

type Revocation struct {
	Serial    string    `json:"serial"`
	Reason    string    `json:"reason"`
	RevokedAt time.Time `json:"revoked_at"`
}

var idRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func ValidateID(id string) error {
	if !idRE.MatchString(id) {
		return fmt.Errorf("invalid issuer id %q: use lowercase letters, digits, dot, underscore or hyphen", id)
	}
	return nil
}

func Path(id string) string {
	return filepath.Join("issuers", "issuer-"+id+".json")
}

func Create(s *store.Store, id, displayName string, pub ed25519.PublicKey, now time.Time) (*Issuer, error) {
	if err := ValidateID(id); err != nil {
		return nil, err
	}
	full := s.Path(Path(id))
	if _, err := store.ReadJSON[Issuer](full); err == nil {
		return nil, fmt.Errorf("issuer %q already exists", id)
	}
	pemBytes, err := keys.MarshalPublic(pub)
	if err != nil {
		return nil, err
	}
	info := &Issuer{ID: id, DisplayName: displayName, PublicKeyPEM: string(pemBytes), CreatedAt: now.UTC()}
	return info, s.WriteJSON(Path(id), info)
}

func Load(s *store.Store, id string) (*Issuer, ed25519.PublicKey, error) {
	info, err := store.ReadJSON[Issuer](s.Path(Path(id)))
	if err != nil {
		return nil, nil, fmt.Errorf("issuer %q is not registered: %w", id, err)
	}
	pub, err := keys.ParsePublicPEM([]byte(info.PublicKeyPEM))
	if err != nil {
		return nil, nil, err
	}
	return info, pub, nil
}

func RevocationPath(serial string) string {
	return filepath.Join("revocations", "revoked-"+serial+".json")
}

func Revoke(s *store.Store, env *attest.Envelope, reason string, now time.Time) error {
	rec := Revocation{Serial: env.Payload.Serial, Reason: reason, RevokedAt: now.UTC()}
	return s.WriteJSON(RevocationPath(env.Payload.Serial), rec)
}

func IsRevoked(s *store.Store, serial string) (bool, error) {
	_, err := store.ReadJSON[Revocation](s.Path(RevocationPath(serial)))
	if err == nil {
		return true, nil
	}
	return false, nil
}
