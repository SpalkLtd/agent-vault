package github

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func testRSAKeyPEM(t *testing.T, pkcs8 bool) ([]byte, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	var block *pem.Block
	if pkcs8 {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("marshal pkcs8: %v", err)
		}
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	} else {
		block = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	}
	return pem.EncodeToMemory(block), &key.PublicKey
}

func decodeSeg(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("b64 decode %q: %v", s, err)
	}
	return b
}

func TestSignJWT_PKCS1(t *testing.T) { assertSignJWT(t, false) }
func TestSignJWT_PKCS8(t *testing.T) { assertSignJWT(t, true) }

func assertSignJWT(t *testing.T, pkcs8 bool) {
	t.Helper()
	pemKey, pub := testRSAKeyPEM(t, pkcs8)
	now := time.Unix(1_700_000_000, 0)

	tok, err := signJWT(pemKey, "123456", now)
	if err != nil {
		t.Fatalf("signJWT: %v", err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT segments, got %d", len(parts))
	}

	// Signature verifies against the public key over header.payload.
	signingInput := parts[0] + "." + parts[1]
	sum := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], decodeSeg(t, parts[2])); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}

	// Header: RS256 / JWT.
	var hdr struct{ Alg, Typ string }
	if err := json.Unmarshal(decodeSeg(t, parts[0]), &hdr); err != nil {
		t.Fatalf("header: %v", err)
	}
	if hdr.Alg != "RS256" || hdr.Typ != "JWT" {
		t.Fatalf("bad header: %+v", hdr)
	}

	// Claims: iss set, iat backdated, exp within 10 minutes of iat.
	var claims struct {
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(decodeSeg(t, parts[1]), &claims); err != nil {
		t.Fatalf("claims: %v", err)
	}
	if claims.Iss != "123456" {
		t.Fatalf("iss = %q, want 123456", claims.Iss)
	}
	if claims.Iat > now.Unix() {
		t.Fatalf("iat %d should be <= now %d (clock-skew backdate)", claims.Iat, now.Unix())
	}
	if span := claims.Exp - claims.Iat; span <= 0 || span > 600 {
		t.Fatalf("exp-iat = %ds, must be in (0, 600]", span)
	}
}

func TestSignJWT_BadPEM(t *testing.T) {
	if _, err := signJWT([]byte("not a pem"), "1", time.Unix(1_700_000_000, 0)); err == nil {
		t.Fatalf("expected error on invalid PEM")
	}
}
