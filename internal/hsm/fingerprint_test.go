package hsm_test

import (
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/alain2sf/bhsm-pqc-demo/internal/hsm"
)

// TestPublicKeyFingerprint checks the fingerprint is the SHA-256 of the exported
// SPKI DER, i.e. what `openssl pkey -pubin -outform DER | openssl dgst -sha256` prints.
func TestPublicKeyFingerprint(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	raw := dk.EncapsulationKey().Bytes()

	pemBytes, _, err := hsm.EncodeRawPublicKeyToPEM(raw)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	sum := sha256.Sum256(block.Bytes)
	want := "SHA256:" + hex.EncodeToString(sum[:])

	got, err := hsm.PublicKeyFingerprint(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("fingerprint = %s, want %s", got, want)
	}

	if _, err := hsm.PublicKeyFingerprint(make([]byte, 100)); err == nil {
		t.Error("expected error for invalid key length")
	}
}

func TestParseFingerprint(t *testing.T) {
	hexFP := strings.Repeat("ab", 32)
	var colons []string
	for i := 0; i < 32; i++ {
		colons = append(colons, "AB")
	}

	for _, in := range []string{
		hexFP,
		"SHA256:" + hexFP,
		"sha256:" + strings.ToUpper(hexFP),
		strings.Join(colons, ":"),
		"  SHA256:" + hexFP + "\n",
	} {
		d, err := hsm.ParseFingerprint(in)
		if err != nil {
			t.Errorf("ParseFingerprint(%q) error: %v", in, err)
			continue
		}
		if hex.EncodeToString(d) != hexFP {
			t.Errorf("ParseFingerprint(%q) = %x", in, d)
		}
	}

	for _, in := range []string{
		"",
		"SHA256:",
		hexFP[:62],
		hexFP + "ab",
		strings.Repeat("zz", 32),
		"MD5:" + hexFP,
	} {
		if _, err := hsm.ParseFingerprint(in); err == nil {
			t.Errorf("ParseFingerprint(%q) expected error", in)
		}
	}
}

func TestCheckPublicKeyFingerprint(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	raw := dk.EncapsulationKey().Bytes()
	fp, err := hsm.PublicKeyFingerprint(raw)
	if err != nil {
		t.Fatal(err)
	}

	if got, err := hsm.CheckPublicKeyFingerprint(raw, strings.ToUpper(strings.TrimPrefix(fp, "SHA256:"))); err != nil || got != fp {
		t.Errorf("matching fingerprint rejected: got=%s err=%v", got, err)
	}

	other, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hsm.CheckPublicKeyFingerprint(other.EncapsulationKey().Bytes(), fp); err == nil ||
		!strings.Contains(err.Error(), "mismatch") {
		t.Errorf("expected mismatch error for a different key, got %v", err)
	}

	if _, err := hsm.CheckPublicKeyFingerprint(raw, "not-a-fingerprint"); err == nil {
		t.Error("expected error for malformed expected fingerprint")
	}
}
