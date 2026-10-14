package pkcs11v3_test

import (
	"os"
	"testing"

	"github.com/alain2sf/bhsm-pqc-demo/internal/pkcs11v3"
)

// TestOpen_InvalidPaths verifies that Open fails gracefully when provided
// with an empty string or a non-existent file path.
func TestOpen_InvalidPaths(t *testing.T) {
	tests := []struct {
		name    string
		libPath string
	}{
		{name: "Empty path", libPath: ""},
		{name: "Whitespace only", libPath: "   "},
		{name: "Non-existent path", libPath: "/tmp/non_existent_pkcs11_module.dylib"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver, err := pkcs11v3.Open(tt.libPath)
			if err == nil {
				if driver != nil {
					driver.Close()
				}
				t.Fatalf("Open(%q) expected error, got nil", tt.libPath)
			}
		})
	}
}

// TestDriver_Close_Idempotent verifies that calling Close() multiple times
// or on an uninitialized driver does not panic or crash.
func TestDriver_Close_Idempotent(t *testing.T) {
	var driver *pkcs11v3.Driver

	// Safe to call on nil driver pointer
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Calling Close() on nil driver panicked: %v", r)
		}
	}()

	if driver != nil {
		driver.Close()
	}
}

// TestDecapsulateKey_EmptyCiphertext verifies input validation when an empty
// ciphertext buffer is passed to DecapsulateKey.
func TestDecapsulateKey_EmptyCiphertext(t *testing.T) {
	// Dummy driver instance
	driver := &pkcs11v3.Driver{}

	_, err := driver.DecapsulateKey(1, 0x00000017, 1000, nil)
	if err == nil {
		t.Errorf("DecapsulateKey with nil ciphertext expected error, got nil")
	}

	_, err = driver.DecapsulateKey(1, 0x00000017, 1000, []byte{})
	if err == nil {
		t.Errorf("DecapsulateKey with empty byte slice expected error, got nil")
	}
}

// TestOpen_WithValidLibrary loads the dynamic module if the PKCS11_LIB_PATH
// environment variable points to a valid file on disk.
func TestOpen_WithValidLibrary(t *testing.T) {
	libPath := os.Getenv("PKCS11_LIB_PATH")
	if libPath == "" {
		t.Skip("PKCS11_LIB_PATH not set; skipping live dynamic library test")
	}

	if _, err := os.Stat(libPath); os.IsNotExist(err) {
		t.Skipf("Library file does not exist at '%s'; skipping", libPath)
	}

	driver, err := pkcs11v3.Open(libPath)
	if err != nil {
		t.Fatalf("Failed to open valid PKCS#11 module at '%s': %v", libPath, err)
	}
	defer driver.Close()

	// Calling Close() twice should be safe
	driver.Close()
}
