package attest

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
)

// Claims 是被签名的声明。制品摘要与构建说明摘要都进入签名负载，
// 因此签名同时绑定实际内容与构建声明，任何一项被替换都会失效。
type Claims struct {
	Version        int    `json:"version"`
	Serial         string `json:"serial"`
	IssuerID       string `json:"issuer_id"`
	ArtifactDigest string `json:"artifact_digest"`
	BuildDigest    string `json:"build_digest"`
	IssuedAt       string `json:"issued_at"`
	ExpiresAt      string `json:"expires_at"`
}

type Envelope struct {
	Payload   Claims `json:"payload"`
	Signature []byte `json:"signature"`
}

// canonicalJSON 按字段名排序生成稳定字节串，作为签名输入。
func canonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, err
	}
	var sorted any
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	if err := dec.Decode(&sorted); err != nil {
		return nil, err
	}
	return json.Marshal(sorted)
}

func Sign(claims Claims, key ed25519.PrivateKey) (*Envelope, error) {
	body, err := canonicalJSON(claims)
	if err != nil {
		return nil, err
	}
	return &Envelope{Payload: claims, Signature: ed25519.Sign(key, body)}, nil
}

func (e *Envelope) Verify(key ed25519.PublicKey) error {
	body, err := canonicalJSON(e.Payload)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, body, e.Signature) {
		return fmt.Errorf("signature does not match claims")
	}
	return nil
}
