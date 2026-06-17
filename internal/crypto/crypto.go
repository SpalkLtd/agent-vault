package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Encrypt encrypts plaintext using AES-256-GCM with the given 32-byte key.
// It returns the ciphertext and a randomly generated nonce.
//
// An optional associated-data (AAD) value provides domain separation: a
// ciphertext sealed with a given AAD can only be opened by passing the same
// AAD to Decrypt. Bind blobs of different purpose (e.g. the CA root key vs a
// credential) to distinct AAD domains so a blob from one slot cannot be
// decrypted in another (defends against at-rest blob-relocation/confused-
// deputy attacks). Callers that pass no AAD get the legacy nil-AAD behavior.
func Encrypt(plaintext, key []byte, aad ...[]byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("creating GCM: %w", err)
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generating nonce: %w", err)
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, firstAAD(aad))
	return ciphertext, nonce, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM with the given 32-byte key and
// nonce. If an AAD value is supplied it must match the one used at Encrypt time
// or Open fails (see Encrypt for the domain-separation rationale).
func Decrypt(ciphertext, nonce, key []byte, aad ...[]byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, firstAAD(aad))
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	return plaintext, nil
}

// firstAAD returns the single optional AAD value, or nil. More than one is a
// programming error.
func firstAAD(aad [][]byte) []byte {
	if len(aad) == 0 {
		return nil
	}
	return aad[0]
}
