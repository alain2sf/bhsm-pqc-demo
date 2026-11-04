package main

import (
	"crypto/mlkem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alain2sf/bhsm-pqc-demo/internal/hsm"
)

// TestRun_EncapFingerprintPinning checks that -e -in refuses a PEM key whose
// fingerprint differs from -fingerprint (or HSM_PUBKEY_FINGERPRINT), and writes
// no ciphertext or secret in that case.
func TestRun_EncapFingerprintPinning(t *testing.T) {
	t.Setenv("PKCS11_LIB_PATH", "")
	t.Setenv("HSM_PUBKEY_FILE", "")
	t.Setenv("HSM_PUBKEY_FINGERPRINT", "")
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }

	writeKey := func(name string) string {
		dk, err := mlkem.GenerateKey768()
		if err != nil {
			t.Fatal(err)
		}
		raw := dk.EncapsulationKey().Bytes()
		pemBytes, _, err := hsm.EncodeRawPublicKeyToPEM(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p(name), pemBytes, 0o644); err != nil {
			t.Fatal(err)
		}
		fp, err := hsm.PublicKeyFingerprint(raw)
		if err != nil {
			t.Fatal(err)
		}
		return fp
	}
	trusted := writeKey("trusted.pem")
	writeKey("swapped.pem")

	encap := func(pemFile, tag string, extra ...string) error {
		args := append([]string{"-e", "-in", p(pemFile), "-cipher", p(tag + ".ct"), "-secret", p(tag + ".ss")}, extra...)
		return run(args)
	}
	assertNoOutput := func(tag string) {
		t.Helper()
		for _, f := range []string{tag + ".ct", tag + ".ss"} {
			if _, err := os.Stat(p(f)); !os.IsNotExist(err) {
				t.Errorf("%s should not exist after a rejected encapsulation (stat err: %v)", f, err)
			}
		}
	}

	if err := encap("trusted.pem", "ok", "-fingerprint", trusted); err != nil {
		t.Errorf("matching fingerprint rejected: %v", err)
	}

	err := encap("swapped.pem", "bad", "-fingerprint", trusted)
	if err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("expected fingerprint mismatch, got %v", err)
	}
	assertNoOutput("bad")

	t.Setenv("HSM_PUBKEY_FINGERPRINT", trusted)
	if err := encap("swapped.pem", "env"); err == nil {
		t.Error("expected HSM_PUBKEY_FINGERPRINT mismatch to fail")
	}
	assertNoOutput("env")

	if err := encap("trusted.pem", "malformed", "-fingerprint", "SHA256:1234"); err == nil {
		t.Error("expected malformed -fingerprint to fail")
	}
	assertNoOutput("malformed")

	if err := run([]string{"-sym-enc", "-fingerprint", trusted}); err == nil ||
		!strings.Contains(err.Error(), "only valid with '-e'") {
		t.Errorf("expected -fingerprint to be rejected outside -e, got %v", err)
	}
}
