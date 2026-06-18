package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := testKey(t)
	plaintext := []byte("super secret value")

	ct, nonce, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := Decrypt(ct, nonce, key)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Fatalf("expected %q, got %q", plaintext, got)
	}
}

func TestAADDomainSeparation(t *testing.T) {
	key := testKey(t)
	plaintext := []byte("CA root private key bytes")
	domainA := []byte("agent-vault/ca-root-key/v1")

	ct, nonce, err := Encrypt(plaintext, key, domainA)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Same domain opens.
	if got, err := Decrypt(ct, nonce, key, domainA); err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("same-domain decrypt failed: got=%q err=%v", got, err)
	}
	// A different domain must NOT open (cross-slot relocation defense).
	if _, err := Decrypt(ct, nonce, key, []byte("agent-vault/credential/v1")); err == nil {
		t.Fatal("cross-domain decrypt succeeded; AAD domain separation is broken")
	}
	// The nil-AAD (legacy/credential reveal) path must NOT open it either.
	if _, err := Decrypt(ct, nonce, key); err == nil {
		t.Fatal("nil-AAD decrypt of a domain-bound blob succeeded; confused-deputy defense broken")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := testKey(t)
	key2 := testKey(t)

	ct, nonce, err := Encrypt([]byte("data"), key1)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Decrypt(ct, nonce, key2)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	key := testKey(t)

	ct, nonce, err := Encrypt([]byte("data"), key)
	if err != nil {
		t.Fatal(err)
	}

	// Flip a byte in ciphertext.
	ct[0] ^= 0xff

	_, err = Decrypt(ct, nonce, key)
	if err == nil {
		t.Fatal("expected error decrypting tampered ciphertext")
	}
}

func TestNonceUniqueness(t *testing.T) {
	key := testKey(t)
	plaintext := []byte("same data")

	_, nonce1, _ := Encrypt(plaintext, key)
	_, nonce2, _ := Encrypt(plaintext, key)

	if bytes.Equal(nonce1, nonce2) {
		t.Fatal("nonces should differ between encryptions")
	}
}

func TestEncryptInvalidKeySize(t *testing.T) {
	_, _, err := Encrypt([]byte("data"), []byte("short"))
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}
