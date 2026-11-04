// Package sym implements symmetric cryptography primitives:
// - HKDF-SHA256 (RFC 5869) key derivation from KEM shared secrets
// - AES-256-GCM (NIST SP 800-38D) Authenticated Encryption with Associated Data (AEAD)
package sym

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// Default HKDF Domain Separation Parameters matching the prototype scripts
const (
	DefaultSalt = "bhsm-demo-hkdf-salt-v1"
	DefaultInfo = "bhsm-demo aes-256-gcm v1"
)

// SharedSecretSize is the ML-KEM (FIPS 203) shared secret length for all parameter sets.
const SharedSecretSize = 32

// Encrypted payload layout (format v1):
//
//	[5-byte header "BHSM"||0x01] [12-byte random nonce] [ciphertext] [16-byte GCM tag]
//
// The GCM additional authenticated data is header || SHA-256(KEM ciphertext), so
// the header cannot be altered and the payload only decrypts alongside the
// ML-KEM ciphertext whose shared secret produced the key.
const (
	FormatVersion byte = 0x01
	NonceSize          = 12
	TagSize            = 16
)

// Header is the magic prefix and format version written at the start of every payload.
var Header = []byte{'B', 'H', 'S', 'M', FormatVersion}

// DeriveAES256Key derives a 32-byte (256-bit) AES key from a KEM shared secret using HKDF-SHA256.
// The secret must be exactly SharedSecretSize bytes, which guards against deriving a key
// from the wrong file (e.g. a plaintext passed as -secret).
func DeriveAES256Key(secret []byte, salt []byte, info []byte) ([]byte, error) {
	if len(secret) != SharedSecretSize {
		return nil, fmt.Errorf("shared secret must be %d bytes, got %d", SharedSecretSize, len(secret))
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

func newGCM(key []byte) (cipher.AEAD, error) {
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
	return gcm, nil
}

// associatedData binds the payload header and the KEM ciphertext into the GCM tag.
func associatedData(kemCiphertext []byte) ([]byte, error) {
	if len(kemCiphertext) == 0 {
		return nil, errors.New("KEM ciphertext is required to bind the payload")
	}
	digest := sha256.Sum256(kemCiphertext)
	aad := make([]byte, 0, len(Header)+len(digest))
	aad = append(aad, Header...)
	return append(aad, digest[:]...), nil
}

// EncryptAESGCM performs AES-256-GCM authenticated encryption, bound to the
// ML-KEM ciphertext that established the key. See the format description above.
func EncryptAESGCM(key, plaintext, kemCiphertext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	aad, err := associatedData(kemCiphertext)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(Header)+NonceSize, len(Header)+NonceSize+len(plaintext)+TagSize)
	copy(out, Header)
	nonce := out[len(Header):]
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}

	return gcm.Seal(out, nonce, plaintext, aad), nil
}

// DecryptAESGCM checks the header, verifies the authentication tag (covering the
// header and the KEM ciphertext), and decrypts the payload.
func DecryptAESGCM(key, encryptedData, kemCiphertext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}

	aad, err := associatedData(kemCiphertext)
	if err != nil {
		return nil, err
	}

	minLen := len(Header) + NonceSize + TagSize
	if len(encryptedData) < minLen {
		return nil, fmt.Errorf("encrypted payload too short: must be at least %d bytes, got %d", minLen, len(encryptedData))
	}
	if !bytes.Equal(encryptedData[:len(Header)], Header) {
		return nil, fmt.Errorf("unsupported payload format: expected header %q v%d", Header[:4], FormatVersion)
	}

	body := encryptedData[len(Header):]
	nonce, ciphertext := body[:NonceSize], body[NonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("AES-GCM authentication failed (tampered data, wrong key, or wrong KEM ciphertext): %w", err)
	}

	return plaintext, nil
}
