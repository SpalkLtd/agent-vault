package ca

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Infisical/agent-vault/internal/crypto"
)

// readCAKeyBlob returns the raw ciphertext+nonce stored in the CA key file.
func readCAKeyBlob(t *testing.T, dir string) (ciphertext, nonce []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, rootKeyFile))
	if err != nil {
		t.Fatalf("reading key file: %v", err)
	}
	var enc encryptedKeyFile
	if err := json.Unmarshal(raw, &enc); err != nil {
		t.Fatalf("unmarshal key file: %v", err)
	}
	ct, err := base64.StdEncoding.DecodeString(enc.Ciphertext)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	n, err := base64.StdEncoding.DecodeString(enc.Nonce)
	if err != nil {
		t.Fatalf("decode nonce: %v", err)
	}
	return ct, n
}

// TestCAKeyNotDecryptableViaNilAADPath is the regression for the confirmed
// MEDIUM finding: the CA root key was sealed with the same DEK and the same
// nil-AAD as credentials, so an A4+member attacker could copy the ca.key.enc
// blob into a credentials row and recover it verbatim through
// GET /credentials?reveal=true (which decrypts with no AAD). Binding the CA
// key to its own AAD domain makes that blob undecryptable on the credential
// reveal path.
func TestCAKeyNotDecryptableViaNilAADPath(t *testing.T) {
	dir := t.TempDir()
	newTestCA(t, Options{Dir: dir})

	ct, nonce := readCAKeyBlob(t, dir)

	// Simulate the credential-reveal path: decrypt with the DEK and no AAD.
	if _, err := crypto.Decrypt(ct, nonce, testMasterKey()); err == nil {
		t.Fatal("SECURITY: CA key blob is decryptable via the nil-AAD credential path " +
			"(can be exfiltrated by relocating it into a credentials row)")
	}
}

// TestCALoadsLegacyNilAADKey ensures backward compatibility: a CA key written
// by an older build (sealed with nil AAD) must still load, so upgrading does
// not brick an existing deployment's CA.
func TestCALoadsLegacyNilAADKey(t *testing.T) {
	dir := t.TempDir()
	// Create a CA, then rewrite its key file as a legacy nil-AAD blob.
	newTestCA(t, Options{Dir: dir})
	ct, nonce := readCAKeyBlob(t, dir)
	plain, err := crypto.Decrypt(ct, nonce, testMasterKey(), caKeyAAD)
	if err != nil {
		t.Fatalf("expected freshly-generated key to use the CA AAD domain: %v", err)
	}
	legacyCT, legacyNonce, err := crypto.Encrypt(plain, testMasterKey()) // nil AAD = legacy
	if err != nil {
		t.Fatalf("re-encrypt legacy: %v", err)
	}
	blob, _ := json.Marshal(encryptedKeyFile{
		Nonce:      base64.StdEncoding.EncodeToString(legacyNonce),
		Ciphertext: base64.StdEncoding.EncodeToString(legacyCT),
	})
	if err := os.WriteFile(filepath.Join(dir, rootKeyFile), blob, 0600); err != nil {
		t.Fatalf("write legacy key: %v", err)
	}

	// Reload: must succeed via the legacy fallback.
	if _, err := New(testMasterKey(), Options{Dir: dir}); err != nil {
		t.Fatalf("CA failed to load a legacy nil-AAD key (broke backward compat): %v", err)
	}

	// And after loading, the on-disk key should have been migrated to the AAD
	// domain so it is no longer reveal-able.
	ct2, nonce2 := readCAKeyBlob(t, dir)
	if _, err := crypto.Decrypt(ct2, nonce2, testMasterKey()); err == nil {
		t.Error("expected legacy CA key to be re-encrypted with the AAD domain on load")
	}
}
