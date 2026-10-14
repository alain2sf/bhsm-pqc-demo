# Bouncy HSM Post-Quantum Cryptography Prototype (ML-KEM + AES-256-GCM)

A complete Golang prototype demonstrating Post-Quantum Cryptography (PQC) integration with **Bouncy HSM** using the OASIS **PKCS#11 v3.2** specification and symmetric **AES-256-GCM AEAD** data encryption with **HKDF-SHA256**.

This project implements the full end-to-end hybrid post-quantum key agreement and authenticated encryption lifecycle from a macOS (Apple Silicon ARM64) host communicating over a TCP RPC interface with a Bouncy HSM server hosted in a Linux guest VM.

---

## 1. Conceptual Background (For Beginners)

### What is PKCS#11 (Cryptoki)?
PKCS#11 is a standardized C API used to communicate with Hardware Security Modules (HSMs) and smart cards. It defines how applications authenticate, generate keys, and perform cryptographic operations without exposing private key material to system memory.

Key PKCS#11 concepts used in this project:
- **Slot**: A logical or physical reader interface inside the HSM.
- **Token**: The cryptographic storage device inserted into a slot (e.g., `DemoSlotToken1`).
- **Session**: An active communication channel to a token (`Read-Only` or `Read-Write`).
- **Object**: Cryptographic material stored on a token (Keys, Certificates, Data).
- **Attributes**: Metadata key-value pairs describing an object (e.g., `CKA_LABEL`, `CKA_TOKEN`, `CKA_PRIVATE`, `CKA_UNIQUE_ID`).
- **Mechanism**: The cryptographic algorithm engine (e.g., `CKM_ML_KEM_KEY_PAIR_GEN`, `CKM_ML_KEM`).

### What is ML-KEM?
**ML-KEM** (Module-Lattice-Based Key-Encapsulation Mechanism) is the NIST standard (FIPS 203) for post-quantum key exchange. It is designed to secure symmetric key agreement against both classical and quantum computing attacks.
- **ML-KEM-512**: NIST Security Category 1 (AES-128 equivalent). Public key: 800 bytes, Ciphertext: 768 bytes, Secret: 32 bytes.
- **ML-KEM-768**: NIST Security Category 3 (AES-192 equivalent, recommended standard). Public key: 1184 bytes, Ciphertext: 1088 bytes, Secret: 32 bytes.
- **ML-KEM-1024**: NIST Security Category 5 (AES-256 equivalent). Public key: 1568 bytes, Ciphertext: 1568 bytes, Secret: 32 bytes.

### Hybrid Cryptography: Key Derivation (HKDF) & AES-256-GCM AEAD
Once the 32-byte shared secret is established between sender and receiver via ML-KEM:
1. **HKDF-SHA256 (RFC 5869):** Derives a cryptographically strong 32-byte (256-bit) AES key using a domain-separation salt (`bhsm-demo-hkdf-salt-v1`) and context info (`bhsm-demo aes-256-gcm v1`).
2. **AES-256-GCM AEAD (NIST SP 800-38D):** Authenticated encryption mode that produces:
   * **12-byte random Nonce (IV)**
   * **Ciphertext**
   * **16-byte Authentication Tag (GHASH)** preventing any tampering or bit-flipping attacks.

---

## 2. Architecture Overview

```text
┌────────────────────────────────────────────────────────────────────────┐
│                          macOS Host (ARM64)                            │
│                                                                        │
│   [ Go Application: bhsm-pqc-demo ]                                    │
│   ├── cmd/bhsm-pqc-demo/main.go                                        │
│   │                                                                    │
│   ├── internal/hsm/client.go  (100% Clean Go business logic)           │
│   │     ├── (PKCS#11 v2.40 Operations: -c, -g, -p)                     │
│   │     ▼                                                              │
│   │   [ github.com/miekg/pkcs11 ]  (Standard Go CGO Wrapper)           │
│   │     │                                                              │
│   │     ├── (PKCS#11 v3.2 C_DecapsulateKey: -d)                        │
│   │     ▼                                                              │
│   ├── internal/pkcs11v3/decapsulate.go (Isolated CGO v3.2 Driver)      │
│   │     │                                                              │
│   │     ▼                                                              │
│   │   [ BouncyHsm.Pkcs11Lib.dylib ] (Native macOS Dynamic Proxy)       │
│   │                                                                    │
│   └── internal/sym/crypto.go (HKDF-SHA256 & AES-256-GCM AEAD)          │
│         ├── -sym-enc (Derives AES key from sender secret & encrypts)   │
│         └── -sym-dec (Derives AES key from receiver secret & decrypts) │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ TCP Socket RPC (Port 8181 / 8765)
┌───────────────────────────────────▼────────────────────────────────────┐
│                            Linux Guest VM                              │
│                                                                        │
│   [ Bouncy HSM Server Engine ]                                         │
│   ├── PKCS#11 Native Engine (TCP Listener)                             │
│   ├── Token & Keystore Storage                                         │
│   └── Web Management UI                                                │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Project Structure

```text
bhsm-pqc-demo/
├── cmd/
│   └── bhsm-pqc-demo/
│       ├── main.go           # Unified CLI router (-c, -g, -p, -e, -d, -sym-enc, -sym-dec)
│       └── main_test.go      # CLI flag and exit behavior unit tests
├── internal/
│   ├── hsm/
│   │   ├── client.go         # High-level PKCS#11 operations (100% clean Go)
│   │   └── client_test.go    # Unit tests for algorithm parsing, ASN.1 / PEM, and crypto
│   ├── pkcs11v3/
│   │   ├── decapsulate.go    # Isolated PKCS#11 v3.2 C_DecapsulateKey CGO driver
│   │   └── decapsulate_test.go # Driver lifecycle and input validation unit tests
│   └── sym/
│       ├── crypto.go         # HKDF-SHA256 & AES-256-GCM AEAD implementation
│       └── crypto_test.go    # RFC 5869 test vector & round-trip AEAD unit tests
├── go.mod                    # Go module dependencies
├── go.sum                    # Dependency checksums
├── Makefile                  # Build, test, and workflow automation
└── README.md                 # Project documentation
```

---

## 4. Prerequisites

1. **Go Toolchain**: Go `1.27.1` or newer installed on your macOS host:
   ```bash
   go version
   ```
2. **Bouncy HSM Server**: Running inside your Linux guest VM (listening on port `8765` for RPC and proxy through port `8181`).
See "BouncyHSM Deployment Guide (Demo Prototype) v3.1” [`BouncyHSM-Deployment-Guide.pdf`] to setup Bouncy HSM Server.
3. **macOS PKCS#11 Dynamic Library**:
See “BouncyHSM & OpenSSL Runbook (Demo Prototype) v1.0” [`BouncyHSM-OpenSSL-Integration.pdf`] chapter "1. Build Bouncy HSM PKCS#11 Interface Library" to build the PKCS11 Dynamic Library for macOS ARM64.
4. **PIN File**: Create a plain text file containing your HSM token User PIN:
   ```bash
   echo -n "123456" > ./DemoSlotToken1.pin
   ```

---

## 5. Environment Variables

| Variable | Description | Default in Makefile |
| :--- | :--- | :--- |
| `BOUNCY_HSM_CFG_STRING` | Connection string instructing the PKCS#11 library how to reach the HSM | `Server=192.168.252.2; Port=8181; LogTarget=Console; LogLevel=NONE;` |
| `PKCS11_LIB_PATH` | File system path to `BouncyHsm.Pkcs11Lib-arm64.dylib` | `/Users/<username>/opt/BouncyHsm/build_macos/BouncyHsm.Pkcs11Lib-arm64.dylib` |
| `HSM_TOKEN_LABEL` | Target token label defined in Bouncy HSM Web UI | `DemoSlotToken1` |
| `HSM_OBJECT_LABEL` | Identifier attached to the public/private key pair | `mlkem768-demo` |
| `HSM_PIN_FILE` | Path to the file storing the User PIN | `./DemoSlotToken1.pin` |
| `PUBKEY_FILE` | Path to the exported public key PEM file | `./mlkem768_pub.pem` |
| `CIPHERTEXT_FILE` | Path for KEM ciphertext file | `./ciphertext.bin` |
| `SENDER_SECRET` | Path for sender's shared secret | `./sender_secret.bin` |
| `RECEIVER_SECRET` | Path for receiver's shared secret | `./receiver_secret.bin` |
| `PLAIN_MSG_FILE` | Path for plaintext payload file | `./msg.txt` |
| `ENC_MSG_FILE` | Path for encrypted AEAD payload file | `./msg.enc` |
| `DEC_MSG_FILE` | Path for decrypted payload file | `./msg.dec` |

---

## 6. Build, Run, and Workflow Phases

### Build Binary
```bash
make deps
make build
```
This compiles the executable into `bin/bhsm-pqc-demo`.

---

### Step 1: Connection & Slot Diagnostic Check (`make conn`)

Performs a pre-flight smoke test against the remote Bouncy HSM, validates network connectivity, and prints all active slots, token labels, models, and mechanism counts.

```bash
make conn
```

---

### Step 2: Generate ML-KEM-768 Key Pair on HSM (`make keygen`)
Authenticates to the HSM token using the provided PIN file. Removes any existing keys matching `mlkem768-demo` (logging their `CKA_UNIQUE_ID`), generates a new persistent key pair, and logs the new `CKA_UNIQUE_ID` values:

```bash
make keygen
```

#### Equivalent OpenSSL Command:
```bash
openssl genpkey -provider pkcs11prov -provider default -algorithm ML-KEM-768 \
  -pkeyopt pkcs11_uri:"pkcs11:token=DemoSlotToken1;object=mlkem768-demo;pin-source=./DemoSlotToken1.pin" \
  -out "pkcs11:token=DemoSlotToken1;object=mlkem768-demo;pin-source=./DemoSlotToken1.pin"
```

---

### Step 3: Extract Public Key to PEM (`make extract-pk`)
Opens a public (unauthenticated i.e. no PIN required) session to the HSM, locates the public key object, extracts the raw 1184-byte key material, formats it into an ASN.1 `SubjectPublicKeyInfo` container (using NIST OID `2.16.840.1.101.3.4.4.2`), and saves it to a standard PEM file:

```bash
make extract-pk
```

#### Equivalent OpenSSL Command:
```bash
openssl pkey -provider pkcs11prov -provider default \
  -in "pkcs11:token=DemoSlotToken1;object=mlkem768-demo;type=public" \
  -pubin -pubout -out mlkem768_pub.pem
```

---

### Step 4: Encapsulate Shared Secret (`make encap-hsm` or `make encap-pem`)
Performs ML-KEM encapsulation (FIPS 203) using either a local PEM public key file or directly against the HSM public key, generating a **1088-byte ciphertext** `ciphertext.bin` and a **32-byte shared secret** `sender_secret.bin`:

```bash
# Querying PK dynamically from HSM and encapsulate:
make encap-hsm

# Or offline using the exported PEM file and encapsulate:
make encap-pem
```

#### Equivalent OpenSSL Command:
```bash
openssl pkeyutl -encap \
  -inkey mlkem768_pub.pem -pubin \
  -secret sender_secret.bin \
  -out ciphertext.bin
```

---

### Step 5: Decapsulate Shared Secret on HSM (`make decap`)
Authenticates to the HSM token using the PIN file, locates the private key object handle, and executes native decapsulation on the HSM server using the PKCS#11 v3.2 function **`C_DecapsulateKey`** via `internal/pkcs11v3`, recovering `receiver_secret.bin` (32 bytes):

```bash
make decap
```

#### Equivalent OpenSSL Command:
```bash
openssl pkeyutl -provider pkcs11prov -provider default -decap \
  -inkey "pkcs11:token=DemoSlotToken1;object=mlkem768-demo;type=private;pin-source=./DemoSlotToken1.pin" \
  -in ciphertext.bin \
  -secret receiver_secret.bin
```

---

### Step 6: Verify KEM Shared Secret Agreement (`make verify` & `make show-secrets`)
Compare the sender's secret and the receiver's recovered secret to verify that the end-to-end key exchange succeeded:

```bash
make verify
make show-secrets
```

---

### Step 7: Encrypt Payload with Derived AES-256-GCM Key (`make sym-enc`)
Derives the 32-byte AES key from `sender_secret.bin` using HKDF-SHA256 and encrypts `msg.txt` into `msg.enc`:
```bash
make sym-enc
```

---

### Step 8: Decrypt Payload with Recovered AES-256-GCM Key (`make sym-dec`)
Derives the 32-byte AES key from `receiver_secret.bin` using HKDF-SHA256, verifies the GCM authentication tag, and decrypts `msg.enc` into `msg.dec`:
```bash
make sym-dec
```

---

### Step 9: Verify End-to-End Plaintext Recovery (`make sym-verify`)
```bash
make sym-verify
```

---

### Run the Complete Automated Demo in 1 Command
```bash
make demo
```

---

## 7. Running Unit Tests

Run unit tests across all subpackages (`cmd`, `internal/hsm`, `internal/pkcs11v3`, and `internal/sym`).

Unit tests validate CLI flags, algorithm parsing, error branches, ASN.1 / X.509 `SubjectPublicKeyInfo` encoding, encapsulation round-trips, and the isolated PKCS#11 v3.2 driver:

```bash
make test
```

---

## 8. CLI Reference & Help Screen

```bash
./bin/bhsm-pqc-demo -h
```

```text
Usage of ./bin/bhsm-pqc-demo:

Actions (mutually exclusive - pick exactly one):
  -c                      Run connection and slot check
  -g <algorithm>          Generate key pair (e.g., -g ML-KEM-768)
  -p                      Export public key to PEM format
  -e                      Encapsulate shared secret against public key
  -d                      Decapsulate shared secret using HSM private key
  -sym-enc                Encrypt plaintext with HKDF-derived AES-256-GCM
  -sym-dec                Decrypt ciphertext with HKDF-derived AES-256-GCM

Options:
  -in <path>              Input file path
  -out <path>             Output file path for symmetric payload
  -cipher <path>          KEM ciphertext file path (default: ./ciphertext.bin)
  -secret <path>          Shared secret file path
  -salt <string>          HKDF salt
  -info <string>          HKDF domain separation context
  -o <path>               Output file path for public key (for -p)
  -lib <path>             Path to PKCS#11 dynamic library

  Environment Variables:
  BOUNCY_HSM_CFG_STRING   HSM server configuration string
  PKCS11_LIB_PATH         Fallback path to PKCS#11 library
  HSM_TOKEN_LABEL         Token label name
  HSM_OBJECT_LABEL        Object/key label
  HSM_PIN_FILE            Path to token PIN file (for -g and -d)
  HSM_PUBKEY_FILE         Fallback input public key PEM file (for -e)
  HSM_CIPHER_FILE         Fallback ciphertext file path
  HSM_SECRET_FILE         Fallback shared secret file path
```