package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteSecretFile_OwnerOnlyAndNoOverwrite checks 0600 permissions and
// that existing files and symlinks are never written through.
func TestWriteSecretFile_OwnerOnlyAndNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.bin")

	if err := writeSecretFile(path, []byte("k")); err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("expected mode 0600, got %o", perm)
	}

	if err := writeSecretFile(path, []byte("k2")); err == nil {
		t.Errorf("expected error when overwriting existing file, got nil")
	}

	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := writeSecretFile(link, []byte("k")); err == nil {
		t.Errorf("expected error when writing through symlink, got nil")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("symlink target should not have been created")
	}
}

// TestCLI_RejectsRelativeLibPath ensures the PKCS#11 library is never loaded
// from a relative path (library planting in the working directory).
func TestCLI_RejectsRelativeLibPath(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "-c", "-lib", "./libBouncyHsm.Pkcs11Lib.dylib")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure for relative -lib path. Output:\n%s", output)
	}
	if !strings.Contains(string(output), "must be absolute") {
		t.Errorf("expected 'must be absolute' error, got:\n%s", output)
	}
}

// TestCLI_RequiresLibPathForHSMActions ensures there is no implicit library fallback.
func TestCLI_RequiresLibPathForHSMActions(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "-c")
	cmd.Env = append(os.Environ(), "PKCS11_LIB_PATH=")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure without a library path. Output:\n%s", output)
	}
	if !strings.Contains(string(output), "library path required") {
		t.Errorf("expected 'library path required' error, got:\n%s", output)
	}
}
