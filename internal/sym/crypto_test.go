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
	kemCiphertext := bytes.Repeat([]byte{0x17}, 1088)
	ciphertext, err := sym.EncryptAESGCM(senderKey, originalMessage, kemCiphertext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// 4. Decrypt & Authenticate
	decryptedMessage, err := sym.DecryptAESGCM(receiverKey, ciphertext, kemCiphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(originalMessage, decryptedMessage) {
		t.Errorf("Plaintext mismatch:\nGot:  %s\nWant: %s", string(decryptedMessage), string(originalMessage))
	}

	// 5. Test authentication failure on tampered ciphertext
	tamperedCiphertext := append([]byte(nil), ciphertext...)
	tamperedCiphertext[len(tamperedCiphertext)-1] ^= 0xFF
	_, err = sym.DecryptAESGCM(receiverKey, tamperedCiphertext, kemCiphertext)
	if err == nil {
		t.Errorf("Expected decryption error on tampered ciphertext, got nil")
	}
}

// TestDeriveAES256Key_RejectsWrongSecretLength ensures only 32-byte ML-KEM
// shared secrets are accepted as HKDF input.
func TestDeriveAES256Key_RejectsWrongSecretLength(t *testing.T) {
	for _, n := range []int{0, 1, 31, 33, 64} {
		if _, err := sym.DeriveAES256Key(make([]byte, n), nil, nil); err == nil {
			t.Errorf("expected error for %d-byte secret, got nil", n)
		}
	}
}

// TestDeriveAES256Key_KnownAnswer pins the production key derivation (default
// salt and info) to a value computed independently with Python's hmac module.
func TestDeriveAES256Key_KnownAnswer(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	key, err := sym.DeriveAES256Key(secret, nil, nil)
	if err != nil {
		t.Fatalf("DeriveAES256Key failed: %v", err)
	}

	const want = "2d30752e84feb6965d1567c65ea2f2f1a24fc1899da88ac04f3aac14120d5299"
	if got := hex.EncodeToString(key); got != want {
		t.Errorf("known-answer mismatch:\nGot:  %s\nWant: %s", got, want)
	}
}

// TestAESGCM_FormatAndBinding checks the versioned header and that the payload
// is bound to its KEM ciphertext and cannot have its header altered.
func TestAESGCM_FormatAndBinding(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	kemCT := bytes.Repeat([]byte{0xAA}, 1088)
	msg := []byte("bound payload")

	enc, err := sym.EncryptAESGCM(key, msg, kemCT)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if !bytes.HasPrefix(enc, sym.Header) {
		t.Fatalf("payload does not start with header %x", sym.Header)
	}
	if want := len(sym.Header) + sym.NonceSize + len(msg) + sym.TagSize; len(enc) != want {
		t.Errorf("payload length = %d, want %d", len(enc), want)
	}

	otherCT := append([]byte(nil), kemCT...)
	otherCT[0] ^= 0x01
	if _, err := sym.DecryptAESGCM(key, enc, otherCT); err == nil {
		t.Errorf("expected failure with a different KEM ciphertext")
	}

	badHeader := append([]byte(nil), enc...)
	badHeader[len(sym.Header)-1] = 0x02
	if _, err := sym.DecryptAESGCM(key, badHeader, kemCT); err == nil {
		t.Errorf("expected failure with an unknown format version")
	}

	if _, err := sym.DecryptAESGCM(key, enc[:len(sym.Header)+sym.NonceSize], kemCT); err == nil {
		t.Errorf("expected failure on truncated payload")
	}

	if _, err := sym.EncryptAESGCM(key, msg, nil); err == nil {
		t.Errorf("expected encrypt to require a KEM ciphertext")
	}
}
