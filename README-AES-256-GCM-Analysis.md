To implement this symmetric encryption/decryption workflow in Go, here is an architectural analysis of the two design options, the cryptographic primitives, and a recommended implementation plan.

---

### 1. Single Binary vs. Separate Binary in the Layout

#### Option A: Unified Binary (`cmd/bhsm-pqc-demo`) (Recommended)
Add flags (e.g., `-sym-enc` and `-sym-dec`) directly into `bhsm-pqc-demo`.
* **Advantage:** Single executable for the whole pipeline ($Keygen \to Export \to Encap \to Decap \to HKDF \to AES\text{-}GCM$).
* **Workflow:** We can run `make demo` to test the entire Post-Quantum hybrid encryption pipeline in one seamless sequence.

#### Option B: Dual Binary Layout (`cmd/bhsm-sym-demo`)
Create a second `main.go` under `cmd/bhsm-sym-demo/main.go`.
* **Advantage:** Separates the HSM interaction layer from the application/transport encryption layer.
* **Layout:**
  ```text
  bhsm-pqc-demo/
  ├── cmd/
  │   ├── bhsm-pqc-demo/     # HSM PKCS#11 + ML-KEM tool
  │   │   └── main.go
  │   └── bhsm-sym-demo/     # HKDF + AES-GCM tool
  │       └── main.go
  ├── internal/
  │   ├── hsm/               # PKCS#11 operations
  │   ├── pkcs11v3/          # CGO bridge for C_DecapsulateKey
  │   └── sym/               # HKDF & AES-256-GCM crypto logic
  ```

---

### 2. Cryptographic Primitives in Go

#### A. HKDF-SHA256 Key Derivation
In the original Bash script, we use:
* **Hash:** `SHA-256`
* **Input Key Material (IKM):** 32-byte shared secret (`sender_secret.bin` / `receiver_secret.bin`)
* **Salt:** `[]byte("bhsm-demo-hkdf-salt-v1")`
* **Info / Context:** `[]byte("bhsm-demo cms-aes-256-gcm v1")`
* **Key Length:** 32 bytes (256 bits) for AES-256.

In Go (1.24+ standard library `crypto/hkdf`):
```go
import (
    "crypto/hkdf"
    "crypto/sha256"
    "io"
)

func DeriveKeyHKDF(secret []byte, salt []byte, info []byte) ([]byte, error) {
    kdf := hkdf.New(sha256.New, secret, salt, info)
    key := make([]byte, 32)
    if _, err := io.ReadFull(kdf, key); err != nil {
        return nil, err
    }
    return key, nil
}
```

---

#### B. AES-256-GCM AEAD vs. CMS `AuthEnvelopedData`

In the Bash script, OpenSSL uses `openssl cms -encrypt -aes-256-gcm`, which wraps AES-GCM into an **ASN.1 RFC 5083 / RFC 5084 `AuthEnvelopedData` structure** (with a `KEKRecipientInfo` block and a `KeyIdentifier = "01"`).

In Go, we have two options for encryption:

1. **Standard AES-256-GCM AEAD (Recommended for modern Go applications):**
   * Format: `[12-byte random nonce] + [AES-GCM ciphertext] + [16-byte Poly1305/GHASH authentication tag]`.
   * Standard in TLS 1.3, QUIC, and Go services (`crypto/cipher.NewGCM`).
   * Fast, self-contained, and no complex ASN.1 envelopes required.

2. **Full CMS `AuthEnvelopedData` ASN.1 Structure:**
   * Wraps the AES-GCM ciphertext in the exact ASN.1 DER structure output by `openssl cms`.
   * Directly interoperable with `openssl cms -decrypt`.

---

### 3. Proposed Implementation Plan

We can structure this cleanly by adding an **`internal/sym`** package:

1. **`internal/sym/crypto.go`**: HKDF-SHA256 key derivation with salt and context domain separation matching the script + AES-256-GCM authenticated encryption and decryption.
3. **`internal/sym/crypto_test.go`**: Unit tests verifying HKDF against standard test vectors and round-trip encryption/decryption.
4. **CLI Integration**: Add targets to the `Makefile` (`make sym-enc`, `make sym-dec`, `make sym-verify`) and integrate into `make demo`.

---

### Architectural Alternatives

1. **Architecture preference:** Should we prefer keeping everything in a **single unified binary** (Option A) with flags like `-sym-enc` and `-sym-dec`, or should we like a **separate binary** (`cmd/bhsm-sym-demo`, Option B)?
2. **Format preference:** Is **standard AES-256-GCM AEAD** (nonce + ciphertext + tag) suitable, or do we need strict byte-level ASN.1 DER compatibility with `openssl cms`?

---

### Architectural Choices

1. **single unified binary** (Option A) with flags like `-sym-enc` and `-sym-dec`.
2. **standard AES-256-GCM AEAD** (nonce + ciphertext + tag).