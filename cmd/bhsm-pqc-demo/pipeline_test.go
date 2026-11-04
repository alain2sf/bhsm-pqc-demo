package main

import (
	"bytes"
	"crypto/mlkem"
	"os"
	"path/filepath"
	"testing"

	"github.com/alain2sf/bhsm-pqc-demo/internal/hsm"
)

// TestRun_OfflinePipeline drives run() through PEM encapsulation, -sym-enc and
// -sym-dec without an HSM (the sender secret stands in for the receiver's),
// and checks the payload only decrypts with the KEM ciphertext it was bound to.
func TestRun_OfflinePipeline(t *testing.T) {
	t.Setenv("PKCS11_LIB_PATH", "")
	t.Setenv("HSM_PUBKEY_FILE", "")
	t.Setenv("HSM_PUBKEY_FINGERPRINT", "")
	dir := t.TempDir()
	p := func(name string) string { return filepath.Join(dir, name) }

	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, _, err := hsm.EncodeRawPublicKeyToPEM(dk.EncapsulationKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p("pub.pem"), pemBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	msg := []byte("offline pipeline payload")
	if err := os.WriteFile(p("msg.txt"), msg, 0o600); err != nil {
		t.Fatal(err)
	}

	steps := [][]string{
		{"-e", "-in", p("pub.pem"), "-cipher", p("ct.bin"), "-secret", p("ss.bin")},
		{"-sym-enc", "-secret", p("ss.bin"), "-cipher", p("ct.bin"), "-in", p("msg.txt"), "-out", p("msg.enc")},
		{"-sym-dec", "-secret", p("ss.bin"), "-cipher", p("ct.bin"), "-in", p("msg.enc"), "-out", p("msg.dec")},
	}
	for _, args := range steps {
		if err := run(args); err != nil {
			t.Fatalf("run(%v) failed: %v", args, err)
		}
	}

	got, err := os.ReadFile(p("msg.dec"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Errorf("decrypted %q, want %q", got, msg)
	}

	for _, f := range []string{"ss.bin", "msg.dec"} {
		info, err := os.Stat(p(f))
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %04o, want 0600", f, perm)
		}
	}

	// A different (valid-length) KEM ciphertext must break authentication.
	ct, err := os.ReadFile(p("ct.bin"))
	if err != nil {
		t.Fatal(err)
	}
	ct[0] ^= 0x01
	if err := os.WriteFile(p("ct-other.bin"), ct, 0o644); err != nil {
		t.Fatal(err)
	}
	err = run([]string{"-sym-dec", "-secret", p("ss.bin"), "-cipher", p("ct-other.bin"), "-in", p("msg.enc"), "-out", p("msg2.dec")})
	if err == nil {
		t.Errorf("expected -sym-dec to fail with a mismatched KEM ciphertext")
	}
}
