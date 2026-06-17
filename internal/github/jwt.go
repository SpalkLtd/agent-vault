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
	"fmt"
	"time"
)

// jwtClockSkew backdates iat to tolerate clock drift between us and GitHub.
const jwtClockSkew = 60 * time.Second

// jwtTTL is how long the app JWT is valid. GitHub caps this at 10 minutes; we
// use 9 to stay safely under the limit even with the skew backdate.
const jwtTTL = 9 * time.Minute

// signJWT builds and RS256-signs a GitHub App JWT for authenticating as the app
// (the "Bearer" used to mint installation tokens). issuer is the app id (numeric
// app id or client id). now is injectable for tests.
func signJWT(pemKey []byte, issuer string, now time.Time) (string, error) {
	key, err := parseRSAPrivateKey(pemKey)
	if err != nil {
		return "", err
	}

	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"iat": now.Add(-jwtClockSkew).Unix(),
		"exp": now.Add(jwtTTL).Unix(),
		"iss": issuer,
	}

	hb, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal jwt header: %w", err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal jwt claims: %w", err)
	}

	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(hb) + "." + enc.EncodeToString(cb)

	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return signingInput + "." + enc.EncodeToString(sig), nil
}

// ValidatePrivateKey reports whether pem is a usable RSA private key, so the
// connect handler can reject a bad key with a 400 before storing anything.
func ValidatePrivateKey(pemKey []byte) error {
	_, err := parseRSAPrivateKey(pemKey)
	return err
}

// parseRSAPrivateKey parses a PEM-encoded RSA private key in either PKCS#1
// ("RSA PRIVATE KEY") or PKCS#8 ("PRIVATE KEY") form — GitHub App keys are
// PKCS#1, but operators may convert to PKCS#8.
func parseRSAPrivateKey(pemKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemKey)
	if block == nil {
		return nil, fmt.Errorf("invalid private key: no PEM block found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA (%T)", parsed)
	}
	return key, nil
}
