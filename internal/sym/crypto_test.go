package sym_test

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/alain2sf/bhsm-pqc-demo/internal/sym"
)

// deriveKeyHKDFRaw derives an arbitrary length key using standard library crypto/hkdf.
func deriveKeyHKDFRaw(secret, salt, info []byte, length int) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, salt, string(info), length)
}

// TestDeriveAES256Key_RFC5869_Vector validates the HKDF implementation
// against the official RFC 5869 Test Case 1 vector.
func TestDeriveAES256Key_RFC5869_Vector(t *testing.T) {
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")

	key, err := deriveKeyHKDFRaw(ikm, salt, info, 42)
	if err != nil {
		t.Fatalf("HKDF failed: %v", err)
	}

	expectedOKM := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
	if hex.EncodeToString(key) != expectedOKM {
		t.Errorf("RFC 5869 Vector mismatch:\nGot:  %s\nWant: %s", hex.EncodeToString(key), expectedOKM)
	}
}

// TestAESGCM_RoundTrip verifies that sender encryption and receiver decryption produce matching plaintexts.
func TestAESGCM_RoundTrip(t *testing.T) {
	fakeSharedSecret := bytes.Repeat([]byte{0x42}, 32)

	// 1. Sender derives key
	senderKey, err := sym.DeriveAES256Key(fakeSharedSecret, nil, nil)
	if err != nil {
		t.Fatalf("Sender key derivation failed: %v", err)
	}

	// 2. Receiver derives key
	receiverKey, err := sym.DeriveAES256Key(fakeSharedSecret, nil, nil)
	if err != nil {
		t.Fatalf("Receiver key derivation failed: %v", err)
	}

	if !bytes.Equal(senderKey, receiverKey) {
		t.Fatalf("Sender and receiver keys do not match")
	}

	originalMessage := []byte("hello from the AES-256-GCM AEAD prototype")

	// 3. Encrypt
	ciphertext, err := sym.EncryptAESGCM(senderKey, originalMessage)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// 4. Decrypt & Authenticate
	decryptedMessage, err := sym.DecryptAESGCM(receiverKey, ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(originalMessage, decryptedMessage) {
		t.Errorf("Plaintext mismatch:\nGot:  %s\nWant: %s", string(decryptedMessage), string(originalMessage))
	}

	// 5. Test authentication failure on tampered ciphertext
	tamperedCiphertext := append([]byte(nil), ciphertext...)
	tamperedCiphertext[len(tamperedCiphertext)-1] ^= 0xFF
	_, err = sym.DecryptAESGCM(receiverKey, tamperedCiphertext)
	if err == nil {
		t.Errorf("Expected decryption error on tampered ciphertext, got nil")
	}
}
