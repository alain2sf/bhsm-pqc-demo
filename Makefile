SHELL := /bin/bash
BINARY_NAME=bhsm-pqc-demo
BUILD_DIR=bin
CMD_PATH=./cmd/bhsm-pqc-demo

# Minimum Go toolchain (any newer release is accepted)
MIN_GO_VERSION=go1.27.1

export GO111MODULE=on
# Use the installed toolchain only: never download one on go.mod's request.
export GOTOOLCHAIN=local

# ============================================================================
# HSM Connection Parameters
# ============================================================================
HSM_HOST ?= 192.168.252.2
HSM_PORT ?= 8181
LIB_PATH ?= /Users/alain/opt/BouncyHsm/build_macos/BouncyHsm.Pkcs11Lib-arm64.dylib

# Token, Key Object, and PIN Configuration
HSM_TOKEN_LABEL   ?= DemoSlotToken1
HSM_OBJECT_LABEL  ?= mlkem768-demo
HSM_PIN_FILE      ?= ./DemoSlotToken1.pin
ALGORITHM         ?= ML-KEM-768

# Artifact Paths
PUBKEY_FILE       ?= ./mlkem768_pub.pem
# Expected SHA-256 fingerprint of PUBKEY_FILE (as printed by 'make extract-pk'),
# obtained over a channel you trust; 'encap-pem' refuses a key that differs.
PUBKEY_FINGERPRINT ?=
CIPHERTEXT_FILE   ?= ./ciphertext.bin
SENDER_SECRET     ?= ./sender_secret.bin
RECEIVER_SECRET   ?= ./receiver_secret.bin

# Symmetric Payload Paths
PLAIN_MSG_FILE    ?= ./msg.txt
ENC_MSG_FILE      ?= ./msg.enc
DEC_MSG_FILE      ?= ./msg.dec

# Default generic CLI arguments for 'make run'
ARGS ?= -c

# Bouncy HSM Configuration String (LogLevel: NONE, INFO, ERROR, SEVERE, FATAL)
CFG_STRING = Server=$(HSM_HOST); Port=$(HSM_PORT); LogTarget=Console; LogLevel=NONE;

# Reusable execution runner macro
EXEC_HSM = BOUNCY_HSM_CFG_STRING="$(CFG_STRING)" \
           PKCS11_LIB_PATH="$(LIB_PATH)" \
           HSM_TOKEN_LABEL="$(HSM_TOKEN_LABEL)" \
           HSM_OBJECT_LABEL="$(HSM_OBJECT_LABEL)" \
           HSM_PIN_FILE="$(HSM_PIN_FILE)" \
           ./$(BUILD_DIR)/$(BINARY_NAME)

.PHONY: all check-go-version build run test vulncheck clean clean-artifacts show-secrets \
        conn keygen extract-pk encap-hsm encap-pem decap verify \
        sym-enc sym-dec sym-verify demo

all: build

# ----------------------------------------------------------------------------
# Build and Dependency Targets
# ----------------------------------------------------------------------------

# Numeric major.minor.patch comparison: passes when the installed Go >= MIN_GO_VERSION.
# ("go1.28rc1" compares as 1.28.0 because awk reads the leading digits of "28rc1".)
check-go-version:
	@GO_VER=$$(go env GOVERSION); \
	if awk -v have="$${GO_VER#go}" -v want="$(MIN_GO_VERSION:go%=%)" 'BEGIN { \
			split(have, h, "."); split(want, w, "."); \
			for (i = 1; i <= 3; i++) { \
				if (h[i] + 0 > w[i] + 0) exit 0; \
				if (h[i] + 0 < w[i] + 0) exit 1; \
			} \
			exit 0 }'; then \
		echo "[✓] Go version requirement met: $$GO_VER (minimum $(MIN_GO_VERSION))"; \
	else \
		echo "[-] Error: Go version too old. Minimum: $(MIN_GO_VERSION), Found: $$GO_VER"; \
		exit 1; \
	fi

deps: check-go-version
	go mod tidy

build: deps
	@mkdir -p $(BUILD_DIR)
	@# Verify and compile all packages across the repository
	go vet ./...
	@# Produce the final binary
	go build -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_PATH)

# Generic run target (accepts arbitrary ARGS)
run: build
	@echo "[*] Running with BOUNCY_HSM_CFG_STRING='$(CFG_STRING)'"
	@echo "[*] Running with PKCS11_LIB_PATH='$(LIB_PATH)'"
	@$(EXEC_HSM) $(ARGS)

# Unit test suite
test: LIB_PATH := $(LIB_PATH)
test: deps
	@echo "[*] Running with PKCS11_LIB_PATH='$(LIB_PATH)'"
	@echo "[*] Running with BOUNCY_HSM_CFG_STRING='$(CFG_STRING)'"
	@BOUNCY_HSM_CFG_STRING="$(CFG_STRING)" PKCS11_LIB_PATH="$(LIB_PATH)" \
	 HSM_TOKEN_LABEL="$(HSM_TOKEN_LABEL)" HSM_OBJECT_LABEL="$(HSM_OBJECT_LABEL)" \
	 HSM_PIN_FILE="$(abspath $(HSM_PIN_FILE))" go test -v ./...

# Vulnerability scan (govulncheck is installed and updated separately, e.g. via go-global-update)
vulncheck: check-go-version
	@command -v govulncheck >/dev/null 2>&1 || { \
		echo "[-] govulncheck not found. Install: go install golang.org/x/vuln/cmd/govulncheck@latest"; exit 1; }
	govulncheck ./...

# ----------------------------------------------------------------------------
# ML-KEM Workflow Targets
# ----------------------------------------------------------------------------

# 1. Connection check and token enumeration
conn: build
	@echo -e "\n=== [1/8] Testing HSM Connection & Listing Slots ==="
	@$(EXEC_HSM) -c

# 2. Key pair generation (ML-KEM-768 on HSM)
keygen: build
	@echo -e "\n=== [2/8] Generating $(ALGORITHM) Key Pair on HSM ==="
	@$(EXEC_HSM) -g $(ALGORITHM)

# 3. Extract public key to PEM and verify with OpenSSL
extract-pk: build
	@echo -e "\n=== [3/8] Extracting Public Key to $(PUBKEY_FILE) ==="
	@rm -f $(PUBKEY_FILE)
	@$(EXEC_HSM) -p -o $(PUBKEY_FILE)
	@echo -e "\n[*] Verifying PEM Structure with OpenSSL:"
	@openssl pkey -pubin -in $(PUBKEY_FILE) -text -noout
	@echo -e "\n[*] OpenSSL SHA-256 of SPKI DER (must equal the fingerprint above):"
	@openssl pkey -pubin -in $(PUBKEY_FILE) -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1

# 4. Encapsulation via direct HSM public key lookup (No PEM needed)
encap-hsm: build
	@echo -e "\n=== [4/8] Encapsulating Shared Secret (Querying PK from HSM) ==="
	@rm -f $(CIPHERTEXT_FILE) $(SENDER_SECRET)
	@$(EXEC_HSM) -e -cipher $(CIPHERTEXT_FILE) -secret $(SENDER_SECRET)

# 4b. Alternative: Encapsulation using the exported local PEM file (Offline sender)
encap-pem: build
	@echo -e "\n=== [4b/8] Encapsulating Shared Secret (Using Local PEM: $(PUBKEY_FILE)) ==="
	@rm -f $(CIPHERTEXT_FILE) $(SENDER_SECRET)
	@HSM_CIPHER_FILE="$(CIPHERTEXT_FILE)" \
	 HSM_SECRET_FILE="$(SENDER_SECRET)" \
	 ./$(BUILD_DIR)/$(BINARY_NAME) -e -in $(PUBKEY_FILE) \
	   $(if $(PUBKEY_FINGERPRINT),-fingerprint $(PUBKEY_FINGERPRINT))

# 5. Decapsulation on HSM using the private key
decap: build
	@echo -e "\n=== [5/8] Decapsulating Shared Secret on HSM Server ==="
	@rm -f $(RECEIVER_SECRET)
	@$(EXEC_HSM) -d -cipher $(CIPHERTEXT_FILE) -secret $(RECEIVER_SECRET)

# 6. Compare sender and receiver shared secrets
verify:
	@echo -e "\n=== [6/8] Verifying KEM Shared Secret Agreement ==="
	@cmp $(SENDER_SECRET) $(RECEIVER_SECRET) && \
	 echo -e "\033[0;32m[✓] SUCCESS: Sender and Receiver shared secrets match perfectly (32 bytes)!\033[0m" || \
	 { echo -e "\033[0;31m[-] FAILURE: Shared secrets do not match!\033[0m"; exit 1; }

# ----------------------------------------------------------------------------
# Display the Shared Secret Files: Sender (encap) & Receiver (decap)
# ----------------------------------------------------------------------------

# WARNING: prints raw key material. For local demo inspection only; deliberately
# not part of 'demo', and must never run in CI or anywhere output is logged.
show-secrets:
	@echo -e "\033[0;33m[!] WARNING: printing raw shared-secret key material (demo use only; do not log or share)\033[0m"
	@echo -e "\n--- Sender Shared Secret ---"
	@pr -m -t -w 130 \
	  <(xxd -g 1 $(SENDER_SECRET)) \
	  <(xxd -p -c 64 $(SENDER_SECRET))
	@echo -e "\n--- Receiver Shared Secret (HSM Recovered) ---"
	@pr -m -t -w 130 \
	  <(xxd -g 1 $(RECEIVER_SECRET)) \
	  <(xxd -p -c 64 $(RECEIVER_SECRET))

# ----------------------------------------------------------------------------
# Symmetric AES-256-GCM Targets
# ----------------------------------------------------------------------------

# Encryption Using Sender Shared Secret (HKDF derivation)
sym-enc: build
	@echo -e "\n=== [7/8] Encrypting Payload (HKDF + AES-256-GCM Sender) ==="
	@rm -f $(ENC_MSG_FILE)
	@if [ ! -f $(PLAIN_MSG_FILE) ]; then \
		(umask 077; echo -n "hello from the AES-256-GCM AEAD prototype using ML-KEM-768 key exchange" > $(PLAIN_MSG_FILE)); \
	fi
	@./$(BUILD_DIR)/$(BINARY_NAME) -sym-enc \
	  -secret $(SENDER_SECRET) \
	  -cipher $(CIPHERTEXT_FILE) \
	  -in $(PLAIN_MSG_FILE) \
	  -out $(ENC_MSG_FILE)

# Decryption Using Receiver Shared Secret (HKDF derivation)
sym-dec: build
	@echo -e "\n=== [8/8] Decrypting Payload (HKDF + AES-256-GCM Receiver) ==="
	@rm -f $(DEC_MSG_FILE)
	@./$(BUILD_DIR)/$(BINARY_NAME) -sym-dec \
	  -secret $(RECEIVER_SECRET) \
	  -cipher $(CIPHERTEXT_FILE) \
	  -in $(ENC_MSG_FILE) \
	  -out $(DEC_MSG_FILE)

# Compare Original plaintext with decrypted ciphertext
sym-verify:
	@echo -e "\n=== Verifying Symmetric Payload Integrity ==="
	@cmp $(PLAIN_MSG_FILE) $(DEC_MSG_FILE) && \
	 echo -e "\033[0;32m[✓] SUCCESS: Original plaintext and decrypted message match perfectly!\033[0m" || \
	 { echo -e "\033[0;31m[-] FAILURE: Decrypted message does not match original!\033[0m"; exit 1; }

# ----------------------------------------------------------------------------
# Complete End-to-End Hybrid PQC Demo Workflow
# ----------------------------------------------------------------------------

demo: clean-artifacts conn keygen extract-pk encap-hsm decap verify sym-enc sym-dec sym-verify
	@echo -e "\n\033[0;32m=======================================================================\033[0m"
	@echo -e "\033[0;32m[✓] ML-KEM-768 + HKDF-SHA256 + AES-256-GCM Complete Lifecycle Passed!\033[0m"
	@echo -e "\033[0;32m=======================================================================\033[0m"

# ----------------------------------------------------------------------------
# Cleanup Targets
# ----------------------------------------------------------------------------

clean-artifacts:
	@echo "[*] Clearing demo files..."
	@rm -f $(PUBKEY_FILE) $(CIPHERTEXT_FILE) $(SENDER_SECRET) $(RECEIVER_SECRET) \
	       $(PLAIN_MSG_FILE) $(ENC_MSG_FILE) $(DEC_MSG_FILE)

clean-cache:
	@echo "[*] Clearing Go test cache..."
	go clean -testcache

clean: clean-artifacts clean-cache
	@rm -rf $(BUILD_DIR)
