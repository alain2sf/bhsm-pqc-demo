// Package sym implements symmetric cryptography primitives:
// - HKDF-SHA256 (RFC 5869) key derivation from KEM shared secrets
// - AES-256-GCM (NIST SP 800-38D) Authenticated Encryption with Associated Data (AEAD)
package sym

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

// Default HKDF Domain Separation Parameters matching the prototype scripts
const (
	DefaultSalt = "bhsm-demo-hkdf-salt-v1"
	DefaultInfo = "bhsm-demo aes-256-gcm v1"
)

// DeriveAES256Key derives a 32-byte (256-bit) AES key from a KEM shared secret using HKDF-SHA256.
func DeriveAES256Key(secret []byte, salt []byte, info []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("input secret material cannot be empty")
	}

	if len(salt) == 0 {
		salt = []byte(DefaultSalt)
	}
	if len(info) == 0 {
		info = []byte(DefaultInfo)
	}

	// Standard library crypto/hkdf uses hkdf.Key(hash, secret, salt, info, keyLength)
	key, err := hkdf.Key(sha256.New, secret, salt, string(info), 32)
	if err != nil {
		return nil, fmt.Errorf("HKDF key extraction failed: %w", err)
	}

	return key, nil
}

// DeriveKeyHKDFRaw derives an arbitrary length key for testing RFC vectors.
func DeriveKeyHKDFRaw(secret, salt, info []byte, length int) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, salt, string(info), length)
}

// EncryptAESGCM performs AES-256-GCM authenticated encryption.
// Output format: [12-byte random nonce] + [ciphertext] + [16-byte GCM authentication tag]
func EncryptAESGCM(key []byte, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid AES-256 key length: expected 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AES block cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GCM mode: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptAESGCM verifies the authentication tag and decrypts the payload.
func DecryptAESGCM(key []byte, encryptedData []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid AES-256 key length: expected 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AES block cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize GCM mode: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: must be at least %d bytes", nonceSize)
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM authentication failed (tampered data or wrong key): %w", err)
	}

	return plaintext, nil
}
