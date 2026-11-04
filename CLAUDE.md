# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Go prototype of a hybrid post-quantum pipeline against **Bouncy HSM** over PKCS#11 v3.2:
ML-KEM keygen on the HSM → public key export to PEM → local encapsulation → HSM-side decapsulation (`C_DecapsulateKey`) → HKDF-SHA256 → AES-256-GCM. The host is macOS ARM64; the HSM server runs in a Linux VM reached over TCP (default `192.168.252.2:8181`) through the `BouncyHsm.Pkcs11Lib-arm64.dylib` client library.

## Commands

The Makefile sets a minimum Go version: `check-go-version` fails if the installed Go is older than `MIN_GO_VERSION` (`go1.27.1`, the same as `go.mod`). `deps`, `build` and `test` all depend on it. `build` runs `go mod tidy` and `go vet ./...` before compiling to `bin/bhsm-pqc-demo`.

```bash
make build                     # tidy + vet + build bin/bhsm-pqc-demo
make test                      # go test -v ./... with PKCS11_LIB_PATH and BOUNCY_HSM_CFG_STRING exported
make vulncheck                 # govulncheck ./... (tool installed separately, updated via go-global-update; needs network)
make demo                      # full end-to-end pipeline (needs live HSM)
make run ARGS="-c"             # run the binary with arbitrary flags and the HSM env vars set
make clean                     # remove artifacts, test cache, bin/
```

Run a single test (CGO is required because `internal/pkcs11v3` uses cgo):
```bash
go test -v -run TestAESGCM_RoundTrip ./internal/sym
go test -v -run TestLiveClientMethods ./internal/hsm   # live; needs env vars below
```

Override HSM settings via make variables: `HSM_HOST`, `HSM_PORT`, `LIB_PATH`, `HSM_TOKEN_LABEL`, `HSM_OBJECT_LABEL`, `HSM_PIN_FILE`, `ALGORITHM`. `LIB_PATH` defaults to a path under `/Users/alain/opt/BouncyHsm/...`.

Pipeline targets in order: `conn`, `keygen`, `extract-pk` (also runs `openssl pkey -text` on the PEM), `encap-hsm` or `encap-pem`, `decap`, `verify`, `sym-enc`, `sym-dec`, `sym-verify`. They write artifacts (`mlkem768_pub.pem`, `ciphertext.bin`, `sender_secret.bin`, `receiver_secret.bin`, `msg.txt/.enc/.dec`) to the repo root.

### Tests and the live HSM

Tests are split into offline and live ones. Live tests (`TestLiveClientMethods`, `TestOpen_WithValidLibrary`) call `t.Skip` when `PKCS11_LIB_PATH` is unset or the file is missing, when `BOUNCY_HSM_CFG_STRING` is unset, or when the server can't be reached. A plain `go test ./...` therefore passes without an HSM, but the HSM paths go untested. ML-KEM round-trip tests use Go's `crypto/mlkem` locally and need no HSM.

## Architecture

- **`cmd/bhsm-pqc-demo/main.go`**: a single flag-driven CLI with mutually exclusive actions (`-c`, `-g <alg>`, `-p`, `-e`, `-d`, `-sym-enc`, `-sym-dec`). `main` only calls `run(args) error`, and each action is a `runX` function that returns errors instead of exiting, so deferred HSM cleanup (`Logout`, `CloseSession`, `Finalize`) always runs. Keep it that way: no `log.Fatal` or `os.Exit` below `main`. Because `run` takes its arguments, tests can drive the CLI in-process (see `run_test.go`). Token, object and PIN settings come **only from environment variables** (`HSM_TOKEN_LABEL`, `HSM_OBJECT_LABEL`, `HSM_PIN_FILE`). File paths come from flags, then env fallbacks (`HSM_CIPHER_FILE`, `HSM_SECRET_FILE`, `HSM_PUBKEY_FILE`, `PLAIN_MSG_FILE`, ...), then `./` defaults. The library path is resolved from `-lib`, then `PKCS11_LIB_PATH`. It must be absolute, and there is deliberately no CWD fallback, because a relative path would allow library planting. Shared secrets, derived keys and plaintext buffers are `clear()`ed after use, and are never printed (only `make show-secrets` does that, deliberately). Keep it that way in new code. Shared secrets and decrypted plaintext are written to disk through `writeSecretFile` (`0600`, `O_EXCL`), so each output path must not already exist; the Makefile runs `rm -f` first for this reason. The Bouncy HSM dylib itself reads `BOUNCY_HSM_CFG_STRING` to find the server.
- **`internal/hsm`**: high-level PKCS#11 operations built on `github.com/miekg/pkcs11` (v2.40 API). `hsm.Client` holds **two handles to the same dylib**:
  - a `miekg/pkcs11` context for standard calls
  - a `pkcs11v3.Driver` (raw `dlopen`) for v3.2 functions that miekg lacks

  Session handles and object handles cross between them as plain `uint`s. The package defines the v3.2 PQC constants itself (`CKM_ML_KEM*`, `CKA_PARAMETER_SET`, `CKA_ENCAPSULATE`/`DECAPSULATE`, `CKA_UNIQUE_ID`). Encapsulation runs **locally** with `crypto/mlkem`, never on the HSM. The variant is chosen from the raw key length (800/1184/1568). ML-KEM-512 can be generated and exported but not encapsulated, because Go's `crypto/mlkem` doesn't support it. PEM export wraps the raw key in a hand-built `SubjectPublicKeyInfo` with the NIST OIDs `2.16.840.1.101.3.4.4.{1,2,3}`.
- **`internal/pkcs11v3`**: an isolated cgo bridge. It `dlsym`s `C_DecapsulateKey` and calls it with the derived-key template built entirely in C memory: a session-only, extractable, non-sensitive `CKK_GENERIC_SECRET` with 32-byte `CKA_VALUE_LEN`. This avoids passing Go pointers to C. The caller (`Client.decapsulateWith`, used by `Decapsulate` and the pairing check) reads `CKA_VALUE` off the returned handle and then destroys it. `Decapsulate` first rejects ciphertexts whose length matches no parameter set (`ValidateMLKEMCiphertextLength`). New v3.2 functions belong here.
- **`internal/sym`**: HKDF-SHA256 via the stdlib `crypto/hkdf` with defaults salt `bhsm-demo-hkdf-salt-v1` and info `bhsm-demo aes-256-gcm v1`. Empty `-salt`/`-info` fall back to these. AES-256-GCM output (format v1) is `"BHSM" 0x01 (5) || nonce(12) || ciphertext || tag(16)`, with AAD `header || SHA-256(KEM ciphertext)`. As a result, `EncryptAESGCM` and `DecryptAESGCM` take the KEM ciphertext, `-sym-enc` and `-sym-dec` read `-cipher`/`HSM_CIPHER_FILE`/`./ciphertext.bin`, and payloads from before v1 no longer decrypt. Bump `FormatVersion` for any layout change. HKDF requires a 32-byte secret. It is not CMS `AuthEnvelopedData`, so it does not interoperate with `openssl cms`. `README-AES-256-GCM-Analysis.md` records this design decision and the older `cms-aes-256-gcm` info string from the original bash script.

Public key fingerprints are `SHA256:` + hex SHA-256 of the **canonical** DER SPKI, rebuilt from the raw key rather than hashed from the file bytes. The HSM key and its PEM export therefore hash the same, and the value equals `openssl pkey -pubin -outform DER | openssl dgst -sha256`. `-p` prints the fingerprint. `-e` prints it too, or with `-fingerprint`/`HSM_PUBKEY_FINGERPRINT` it checks the key and aborts on mismatch before writing anything (`make encap-pem PUBKEY_FINGERPRINT=...`).

`FetchRawPublicKey`/`ExportPublicKeyPEM` take a PIN file path. When it's non-empty (the CLI passes `HSM_PIN_FILE`), they log in and run `verifyKeyPair`: same `CKA_ID` on both halves, then a local encapsulation decapsulated on the HSM must give the same secret. ML-KEM-512 can only get the `CKA_ID` check. An empty path skips the check with a warning. `make test` exports the token, object and PIN-file variables (PIN as an absolute path) for `TestLiveKeyPairVerification`, and the Makefile pins `GOTOOLCHAIN=local`.

Behavior to know about: `-g` generates the new pair first, then **deletes every other public, private and secret key object with the same label**. Key lookups (`findUniqueMLKEMKey`) filter on `CKK_ML_KEM` and refuse a label with more than one match, so a leftover or planted duplicate makes encap and decap fail rather than pick the wrong key.

## Repo notes

- `DemoSlotToken1.pin` holds the token user PIN and is gitignored. Don't commit it or print its contents. `hsm.ReadPINFile` refuses it unless its mode is owner-only (e.g. `0600`).
- The README documents an equivalent `openssl ... -provider pkcs11prov` command for each pipeline step. Use them to cross-check behavior.
