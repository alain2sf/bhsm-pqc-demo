package hsm_test

import (
	"bytes"
	"crypto/mlkem"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/alain2sf/bhsm-pqc-demo/internal/hsm"
)

// ============================================================================
// 1. Algorithm Parsing Unit Tests
// ============================================================================

// TestParseMLKEMAlgorithm verifies that algorithm strings map to the expected PKCS#11 constants.
func TestParseMLKEMAlgorithm(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedSet uint
		expectError bool
	}{
		{name: "ML-KEM-512 standard", input: "ML-KEM-512", expectedSet: hsm.CKP_ML_KEM_512, expectError: false},
		{name: "ML-KEM-768 standard", input: "ML-KEM-768", expectedSet: hsm.CKP_ML_KEM_768, expectError: false},
		{name: "ML-KEM-1024 standard", input: "ML-KEM-1024", expectedSet: hsm.CKP_ML_KEM_1024, expectError: false},
		{name: "Lowercase input", input: "ml-kem-768", expectedSet: hsm.CKP_ML_KEM_768, expectError: false},
		{name: "Whitespace padded", input: "  ML-KEM-768  ", expectedSet: hsm.CKP_ML_KEM_768, expectError: false},
		{name: "Invalid algorithm", input: "RSA-4096", expectedSet: 0, expectError: true},
		{name: "Empty input", input: "", expectedSet: 0, expectError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hsm.ParseMLKEMAlgorithm(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("ParseMLKEMAlgorithm(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseMLKEMAlgorithm(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.expectedSet {
				t.Errorf("ParseMLKEMAlgorithm(%q) = %d, expected %d", tt.input, got, tt.expectedSet)
			}
		})
	}
}

// ============================================================================
// 2. ASN.1 & PEM Public Key Formatting Tests (-p scenario)
// ============================================================================

// TestEncodeRawPublicKeyToPEM tests PEM serialization and X.509 SubjectPublicKeyInfo wrapping.
func TestEncodeRawPublicKeyToPEM(t *testing.T) {
	tests := []struct {
		name        string
		keySize     int
		expectedOID asn1.ObjectIdentifier
		expectedAlg string
		expectError bool
	}{
		{
			name:        "ML-KEM-512 (800 bytes)",
			keySize:     800,
			expectedOID: hsm.OIDMLKEM512,
			expectedAlg: "ML-KEM-512",
			expectError: false,
		},
		{
			name:        "ML-KEM-768 (1184 bytes)",
			keySize:     1184,
			expectedOID: hsm.OIDMLKEM768,
			expectedAlg: "ML-KEM-768",
			expectError: false,
		},
		{
			name:        "ML-KEM-1024 (1568 bytes)",
			keySize:     1568,
			expectedOID: hsm.OIDMLKEM1024,
			expectedAlg: "ML-KEM-1024",
			expectError: false,
		},
		{
			name:        "Invalid key size (64 bytes)",
			keySize:     64,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeKey := bytes.Repeat([]byte{0x5A}, tt.keySize)
			pemData, algName, err := hsm.EncodeRawPublicKeyToPEM(fakeKey)

			if tt.expectError {
				if err == nil {
					t.Errorf("EncodeRawPublicKeyToPEM with size %d expected error, got nil", tt.keySize)
				}
				return
			}

			if err != nil {
				t.Fatalf("EncodeRawPublicKeyToPEM unexpected error: %v", err)
			}

			if algName != tt.expectedAlg {
				t.Errorf("Expected algorithm name %s, got %s", tt.expectedAlg, algName)
			}

			// Validate PEM block structure
			block, rest := pem.Decode(pemData)
			if block == nil || len(rest) > 0 {
				t.Fatalf("Failed to decode valid PEM block from generated output")
			}

			if block.Type != "PUBLIC KEY" {
				t.Errorf("Expected PEM block header 'PUBLIC KEY', got '%s'", block.Type)
			}

			// Validate SubjectPublicKeyInfo ASN.1 unmarshaling
			var spki hsm.SubjectPublicKeyInfo
			_, err = asn1.Unmarshal(block.Bytes, &spki)
			if err != nil {
				t.Fatalf("Failed to unmarshal ASN.1 SubjectPublicKeyInfo: %v", err)
			}

			if !spki.Algorithm.Algorithm.Equal(tt.expectedOID) {
				t.Errorf("Expected OID %v, got %v", tt.expectedOID, spki.Algorithm.Algorithm)
			}

			if !bytes.Equal(spki.PublicKey.Bytes, fakeKey) {
				t.Errorf("SPKI PublicKey bytes do not match original raw key")
			}
		})
	}
}

// ============================================================================
// 3. Encapsulation & Decapsulation Round-Trip Tests (-e & -d workflows)
// ============================================================================

// TestEncapsulateAndDecapsulate_AllVariants verifies the cryptographic lifecycle:
// Generating key pairs, encapsulating to produce ciphertext and sender secret,
// and decapsulating to verify that the receiver recovers the identical shared secret.
func TestEncapsulateAndDecapsulate_AllVariants(t *testing.T) {
	t.Run("ML-KEM-768 Full Round-Trip", func(t *testing.T) {
		// 1. Generate key pair
		dk, err := mlkem.GenerateKey768()
		if err != nil {
			t.Fatalf("Failed to generate ML-KEM-768 test key: %v", err)
		}
		rawPub := dk.EncapsulationKey().Bytes()

		// 2. Encapsulate
		ct, senderSecret, algName, err := hsm.EncapsulateFromRawKey(rawPub)
		if err != nil {
			t.Fatalf("EncapsulateFromRawKey failed: %v", err)
		}

		if algName != "ML-KEM-768" {
			t.Errorf("Expected ML-KEM-768, got %s", algName)
		}
		if len(ct) != 1088 {
			t.Errorf("Expected 1088 bytes ciphertext, got %d", len(ct))
		}
		if len(senderSecret) != 32 {
			t.Errorf("Expected 32 bytes shared secret, got %d", len(senderSecret))
		}

		// 3. Decapsulate
		receiverSecret, err := dk.Decapsulate(ct)
		if err != nil {
			t.Fatalf("Decapsulation failed: %v", err)
		}

		// 4. Verify shared secret match
		if !bytes.Equal(senderSecret, receiverSecret) {
			t.Fatalf("Shared secret mismatch: sender (%x) != receiver (%x)", senderSecret, receiverSecret)
		}

		// 5. Test decapsulation with modified/corrupted ciphertext
		corruptedCT := append([]byte(nil), ct...)
		corruptedCT[0] ^= 0xFF
		mismatchSecret, err := dk.Decapsulate(corruptedCT)
		if err == nil && bytes.Equal(senderSecret, mismatchSecret) {
			t.Errorf("Decapsulating corrupted ciphertext should not yield original shared secret")
		}
	})

	t.Run("ML-KEM-1024 Full Round-Trip", func(t *testing.T) {
		dk, err := mlkem.GenerateKey1024()
		if err != nil {
			t.Fatalf("Failed to generate ML-KEM-1024 test key: %v", err)
		}
		rawPub := dk.EncapsulationKey().Bytes()

		ct, senderSecret, algName, err := hsm.EncapsulateFromRawKey(rawPub)
		if err != nil {
			t.Fatalf("EncapsulateFromRawKey failed: %v", err)
		}

		if algName != "ML-KEM-1024" {
			t.Errorf("Expected ML-KEM-1024, got %s", algName)
		}
		if len(ct) != 1568 {
			t.Errorf("Expected 1568 bytes ciphertext, got %d", len(ct))
		}
		if len(senderSecret) != 32 {
			t.Errorf("Expected 32 bytes shared secret, got %d", len(senderSecret))
		}

		receiverSecret, err := dk.Decapsulate(ct)
		if err != nil {
			t.Fatalf("Decapsulation failed: %v", err)
		}

		if !bytes.Equal(senderSecret, receiverSecret) {
			t.Fatalf("Shared secret mismatch: sender (%x) != receiver (%x)", senderSecret, receiverSecret)
		}
	})

	t.Run("Unsupported ML-KEM-512 Error Handling", func(t *testing.T) {
		fake512Key := bytes.Repeat([]byte{0x5A}, 800)
		_, _, _, err := hsm.EncapsulateFromRawKey(fake512Key)
		if err == nil {
			t.Errorf("EncapsulateFromRawKey with 800 bytes expected unsupported error, got nil")
		}
	})

	t.Run("Invalid Key Length Error", func(t *testing.T) {
		invalidKey := bytes.Repeat([]byte{0x00}, 100)
		_, _, _, err := hsm.EncapsulateFromRawKey(invalidKey)
		if err == nil {
			t.Errorf("EncapsulateFromRawKey with invalid key length expected error, got nil")
		}
	})
}

// TestEncapsulateFromPEM tests reading an X.509 PEM public key file and executing encapsulation.
func TestEncapsulateFromPEM(t *testing.T) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("Failed to generate test ML-KEM-768 key: %v", err)
	}

	pemBytes, _, err := hsm.EncodeRawPublicKeyToPEM(dk.EncapsulationKey().Bytes())
	if err != nil {
		t.Fatalf("Failed to encode PEM: %v", err)
	}

	tmpDir := t.TempDir()
	validPEMFile := filepath.Join(tmpDir, "mlkem768_valid.pem")
	if err := os.WriteFile(validPEMFile, pemBytes, 0644); err != nil {
		t.Fatalf("Failed to write temporary PEM file: %v", err)
	}

	// 1. Test valid PEM encapsulation
	ct, senderSecret, algName, err := hsm.EncapsulateFromPEM(validPEMFile)
	if err != nil {
		t.Fatalf("EncapsulateFromPEM failed: %v", err)
	}
	if algName != "ML-KEM-768" || len(ct) != 1088 || len(senderSecret) != 32 {
		t.Errorf("EncapsulateFromPEM returned invalid outputs: alg=%s, ctLen=%d, ssLen=%d",
			algName, len(ct), len(senderSecret))
	}

	// Verify decapsulation against the private key
	receiverSecret, err := dk.Decapsulate(ct)
	if err != nil {
		t.Fatalf("Decapsulation failed: %v", err)
	}
	if !bytes.Equal(senderSecret, receiverSecret) {
		t.Errorf("Shared secret mismatch against decapsulation key")
	}

	// 2. Test missing file error
	_, _, _, err = hsm.EncapsulateFromPEM(filepath.Join(tmpDir, "non_existent.pem"))
	if err == nil {
		t.Errorf("EncapsulateFromPEM with non-existent file should return error, got nil")
	}

	// 3. Test invalid PEM content error
	corruptPEMFile := filepath.Join(tmpDir, "corrupt.pem")
	if err := os.WriteFile(corruptPEMFile, []byte("NOT A PEM FILE"), 0644); err != nil {
		t.Fatalf("Failed to write corrupt PEM file: %v", err)
	}

	_, _, _, err = hsm.EncapsulateFromPEM(corruptPEMFile)
	if err == nil {
		t.Errorf("EncapsulateFromPEM with corrupt file should return error, got nil")
	}
}

// ============================================================================
// 4. PKCS#11 Client Initialization & Guard Tests (-c scenario)
// ============================================================================

// TestNewClientInvalidPath verifies that client initialization fails cleanly when
// given empty or nonexistent library paths.
func TestNewClientInvalidPath(t *testing.T) {
	_, err := hsm.NewClient("")
	if err == nil {
		t.Errorf("NewClient with empty path should return error, got nil")
	}

	_, err = hsm.NewClient("/path/does/not/exist/libpkcs11.dylib")
	if err == nil {
		t.Errorf("NewClient with nonexistent path should return error, got nil")
	}
}

// TestLiveClientMethods runs live HSM queries if both the library and server are configured.
func TestLiveClientMethods(t *testing.T) {
	libPath := os.Getenv("PKCS11_LIB_PATH")
	if libPath == "" {
		t.Skip("PKCS11_LIB_PATH not set; skipping live HSM client tests")
	}

	if _, err := os.Stat(libPath); os.IsNotExist(err) {
		t.Skipf("Library file does not exist at '%s'; skipping", libPath)
	}

	cfg := os.Getenv("BOUNCY_HSM_CFG_STRING")
	if cfg == "" {
		t.Skip("BOUNCY_HSM_CFG_STRING not set; skipping live HSM network tests")
	}

	client, err := hsm.NewClient(libPath)
	if err != nil {
		t.Skipf("Could not connect to live HSM server (%v); skipping live network test", err)
	}
	defer client.Close()

	// 1. Verify GetInfo
	info, err := client.GetInfo()
	if err != nil {
		t.Fatalf("GetInfo failed: %v", err)
	}
	if len(info.ManufacturerID) == 0 {
		t.Errorf("Expected manufacturer ID, got empty string")
	}

	// 2. Verify InspectTokens
	tokens, err := client.InspectTokens()
	if err != nil {
		t.Fatalf("InspectTokens failed: %v", err)
	}
	t.Logf("Discovered %d active token(s)", len(tokens))

	// 3. Verify non-existent token label lookup fails cleanly
	_, err = client.FindSlotByTokenLabel("NonExistentTokenLabel_12345")
	if err == nil {
		t.Errorf("Expected error when searching for non-existent token, got nil")
	}
}
