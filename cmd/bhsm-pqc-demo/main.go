package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/alain2sf/bhsm-pqc-demo/internal/hsm"
	"github.com/alain2sf/bhsm-pqc-demo/internal/sym"
)

// options holds the parsed command-line flags.
type options struct {
	// Actions (mutually exclusive)
	connTest  bool
	genAlg    string
	exportPub bool
	encap     bool
	decap     bool
	symEnc    bool
	symDec    bool

	// Options
	pubOut      string // -o
	inFile      string // -in
	outFile     string // -out
	cipherFile  string // -cipher
	secretFile  string // -secret
	salt        string
	info        string
	libPath     string
	fingerprint string // -fingerprint
}

func main() {
	// All work happens in run() so that deferred HSM cleanup (Logout,
	// CloseSession, Finalize) executes on every error path before exit.
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	opts, err := parseFlags(args)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}

	libPath, err := resolveLibPath(opts)
	if err != nil {
		return err
	}

	switch {
	case opts.connTest:
		if err := runConnectionTest(libPath); err != nil {
			return fmt.Errorf("connection test failed: %w", err)
		}
		return nil
	case opts.genAlg != "":
		return runKeygen(opts, libPath)
	case opts.exportPub:
		return runExport(opts, libPath)
	case opts.encap:
		return runEncap(opts, libPath)
	case opts.decap:
		return runDecap(opts, libPath)
	case opts.symEnc:
		return runSymEnc(opts)
	default: // opts.symDec
		return runSymDec(opts)
	}
}

func parseFlags(args []string) (*options, error) {
	o := &options{}
	fs := flag.NewFlagSet("bhsm-pqc-demo", flag.ContinueOnError)

	fs.BoolVar(&o.connTest, "c", false, "Run PKCS#11 connection and diagnostic test")
	fs.StringVar(&o.genAlg, "g", "", "Generate ML-KEM key pair (e.g. -g ML-KEM-768)")
	fs.BoolVar(&o.exportPub, "p", false, "Export public key from HSM to PEM format")
	fs.BoolVar(&o.encap, "e", false, "Perform ML-KEM encapsulation")
	fs.BoolVar(&o.decap, "d", false, "Perform ML-KEM decapsulation using the HSM private key")
	fs.BoolVar(&o.symEnc, "sym-enc", false, "Encrypt plaintext using HKDF-derived AES-256-GCM key")
	fs.BoolVar(&o.symDec, "sym-dec", false, "Decrypt ciphertext using HKDF-derived AES-256-GCM key")

	fs.StringVar(&o.pubOut, "o", "", "Output file path (for -p public key)")
	fs.StringVar(&o.inFile, "in", "", "Input file path (-in <pubkey.pem> for -e, -in <msg.txt> for -sym-enc, -in <msg.enc> for -sym-dec)")
	fs.StringVar(&o.outFile, "out", "", "Output file path for symmetric payload (-sym-enc / -sym-dec)")
	fs.StringVar(&o.cipherFile, "cipher", "", "KEM ciphertext file (-e output; -d, -sym-enc, -sym-dec input; default: ./ciphertext.bin)")
	fs.StringVar(&o.secretFile, "secret", "", "Path for shared secret file (-e, -d, -sym-enc, -sym-dec)")
	fs.StringVar(&o.salt, "salt", "", "Optional HKDF salt (default: '"+sym.DefaultSalt+"')")
	fs.StringVar(&o.info, "info", "", "Optional HKDF context info (default: '"+sym.DefaultInfo+"')")
	fs.StringVar(&o.libPath, "lib", "", "Absolute path to BouncyHsm.Pkcs11Lib library (.dylib/.so)")
	fs.StringVar(&o.fingerprint, "fingerprint", "", "Expected public key SHA-256 fingerprint for -e (as printed by -p)")

	fs.Usage = func() {
		w := fs.Output()
		fmt.Fprintf(w, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(w, "\nActions (mutually exclusive - pick exactly one):\n")
		fmt.Fprintf(w, "  -c                      Run connection and slot check\n")
		fmt.Fprintf(w, "  -g <algorithm>          Generate key pair (e.g., -g ML-KEM-768)\n")
		fmt.Fprintf(w, "  -p                      Export public key to PEM format\n")
		fmt.Fprintf(w, "  -e                      Encapsulate shared secret against public key\n")
		fmt.Fprintf(w, "  -d                      Decapsulate shared secret using HSM private key\n")
		fmt.Fprintf(w, "  -sym-enc                Encrypt plaintext with HKDF-derived AES-256-GCM\n")
		fmt.Fprintf(w, "  -sym-dec                Decrypt ciphertext with HKDF-derived AES-256-GCM\n")
		fmt.Fprintf(w, "\nOptions:\n")
		fmt.Fprintf(w, "  -in <path>              Input file path\n")
		fmt.Fprintf(w, "  -out <path>             Output file path for symmetric payload\n")
		fmt.Fprintf(w, "  -cipher <path>          KEM ciphertext file (-e output; -d/-sym-enc/-sym-dec input; default: ./ciphertext.bin)\n")
		fmt.Fprintf(w, "  -secret <path>          Shared secret file path\n")
		fmt.Fprintf(w, "  -salt <string>          HKDF salt\n")
		fmt.Fprintf(w, "  -info <string>          HKDF domain separation context\n")
		fmt.Fprintf(w, "  -o <path>               Output file path for public key (for -p)\n")
		fmt.Fprintf(w, "  -lib <path>             Absolute path to PKCS#11 dynamic library (or PKCS11_LIB_PATH)\n")
		fmt.Fprintf(w, "  -fingerprint <sha256>   Expected public key fingerprint for -e (as printed by -p; or HSM_PUBKEY_FINGERPRINT)\n")
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	actions := 0
	for _, set := range []bool{o.connTest, o.genAlg != "", o.exportPub, o.encap, o.decap, o.symEnc, o.symDec} {
		if set {
			actions++
		}
	}
	switch {
	case actions == 0:
		fmt.Println("[!] No action specified.")
		fs.Usage()
		return nil, errors.New("no action specified")
	case actions > 1:
		return nil, errors.New("only one action flag can be specified at a time")
	}
	if o.fingerprint != "" && !o.encap {
		return nil, errors.New("flag '-fingerprint' is only valid with '-e'")
	}

	return o, nil
}

// resolveLibPath returns the PKCS#11 library path from -lib or PKCS11_LIB_PATH.
// There is no implicit fallback: a relative default would dlopen whatever library
// sits in the current directory, and that code would see the PIN at C_Login.
func resolveLibPath(o *options) (string, error) {
	libPath := o.libPath
	if libPath == "" {
		libPath = os.Getenv("PKCS11_LIB_PATH")
	}

	pemEncap := o.encap && (o.inFile != "" || os.Getenv("HSM_PUBKEY_FILE") != "")
	needsHSM := !o.symEnc && !o.symDec && !pemEncap

	if needsHSM && libPath == "" {
		return "", errors.New("PKCS#11 library path required: use -lib <absolute path> or set PKCS11_LIB_PATH")
	}
	if libPath != "" && !filepath.IsAbs(libPath) {
		return "", fmt.Errorf("PKCS#11 library path must be absolute, got %q", libPath)
	}
	return libPath, nil
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// writeSecretFile writes key material or recovered plaintext with owner-only
// permissions. O_EXCL refuses to overwrite an existing file (which would keep
// its old, possibly world-readable mode) or to follow a pre-planted symlink.
func writeSecretFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 G703 -- path chosen by the operator (flag or env var) of this local CLI; O_EXCL refuses existing files and symlinks
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close() // the write error is the one worth reporting
		return err
	}
	return f.Close()
}

func requireEnv(key string) (string, error) {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return "", fmt.Errorf("required environment variable '%s' is not set", key)
	}
	return val, nil
}

// requireEnvs fetches several required environment variables in order.
func requireEnvs(keys ...string) ([]string, error) {
	vals := make([]string, len(keys))
	for i, k := range keys {
		v, err := requireEnv(k)
		if err != nil {
			return nil, err
		}
		vals[i] = v
	}
	return vals, nil
}

func getEnvOrDefault(key, fallback string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	return fallback
}

// pathOr returns the flag value if set, otherwise the env var, otherwise the default.
func pathOr(flagVal, envKey, fallback string) string {
	if flagVal != "" {
		return flagVal
	}
	return getEnvOrDefault(envKey, fallback)
}

// ----------------------------------------------------------------------------
// Actions
// ----------------------------------------------------------------------------

func runKeygen(o *options, libPath string) error {
	env, err := requireEnvs("HSM_TOKEN_LABEL", "HSM_OBJECT_LABEL", "HSM_PIN_FILE")
	if err != nil {
		return err
	}
	tokenLabel, objectLabel, pinFile := env[0], env[1], env[2]

	fmt.Printf("[*] Target Token : %s\n", tokenLabel)
	fmt.Printf("[*] Object Label : %s\n", objectLabel)
	fmt.Printf("[*] PIN File     : %s\n", pinFile)

	client, err := hsm.NewClient(libPath)
	if err != nil {
		return fmt.Errorf("initialization error: %w", err)
	}
	defer client.Close()

	if err := client.GenerateMLKEMKeyPair(tokenLabel, objectLabel, pinFile, o.genAlg); err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}
	return nil
}

func runExport(o *options, libPath string) error {
	if o.pubOut == "" {
		return errors.New("missing output file: flag '-p' requires '-o <path>' (e.g. -p -o mlkem768_pub.pem)")
	}

	env, err := requireEnvs("HSM_TOKEN_LABEL", "HSM_OBJECT_LABEL")
	if err != nil {
		return err
	}
	tokenLabel, objectLabel := env[0], env[1]

	fmt.Printf("[*] Target Token : %s\n", tokenLabel)
	fmt.Printf("[*] Object Label : %s\n", objectLabel)
	fmt.Printf("[*] Output PEM   : %s\n", o.pubOut)

	client, err := hsm.NewClient(libPath)
	if err != nil {
		return fmt.Errorf("initialization error: %w", err)
	}
	defer client.Close()

	if err := client.ExportPublicKeyPEM(tokenLabel, objectLabel, os.Getenv("HSM_PIN_FILE"), o.pubOut); err != nil {
		return fmt.Errorf("public key export failed: %w", err)
	}
	return nil
}

func runEncap(o *options, libPath string) error {
	cipherPath := pathOr(o.cipherFile, "HSM_CIPHER_FILE", "./ciphertext.bin")
	secretPath := pathOr(o.secretFile, "HSM_SECRET_FILE", "./sender_secret.bin")
	pubPEM := o.inFile
	if pubPEM == "" {
		pubPEM = os.Getenv("HSM_PUBKEY_FILE")
	}

	var rawKey []byte
	if pubPEM != "" {
		fmt.Printf("[*] Reading public key from PEM file: %s\n", pubPEM)
		k, err := hsm.ReadPublicKeyPEM(pubPEM)
		if err != nil {
			return fmt.Errorf("PEM public key rejected: %w", err)
		}
		rawKey = k
	} else {
		env, err := requireEnvs("HSM_TOKEN_LABEL", "HSM_OBJECT_LABEL")
		if err != nil {
			return fmt.Errorf("%w (or supply -in <pubkey.pem>)", err)
		}
		tokenLabel, objectLabel := env[0], env[1]

		fmt.Printf("[*] Fetching public key from HSM Token '%s' (Object: '%s')...\n", tokenLabel, objectLabel)
		client, err := hsm.NewClient(libPath)
		if err != nil {
			return fmt.Errorf("initialization error: %w", err)
		}
		defer client.Close()

		k, err := client.FetchRawPublicKey(tokenLabel, objectLabel, os.Getenv("HSM_PIN_FILE"))
		if err != nil {
			return fmt.Errorf("public key retrieval failed: %w", err)
		}
		rawKey = k
	}

	// The PEM file is only as trustworthy as the channel it arrived over, so a
	// sender can pin the fingerprint that -p printed next to the HSM.
	want := o.fingerprint
	if want == "" {
		want = os.Getenv("HSM_PUBKEY_FINGERPRINT")
	}
	if want != "" {
		fp, err := hsm.CheckPublicKeyFingerprint(rawKey, want)
		if err != nil {
			return err
		}
		fmt.Printf("[+] Public key fingerprint verified: %s\n", fp)
	} else {
		fp, err := hsm.PublicKeyFingerprint(rawKey)
		if err != nil {
			return err
		}
		fmt.Printf("[*] Public key fingerprint: %s\n", fp)
		if pubPEM != "" {
			fmt.Println("[!] Warning: PEM key not pinned; compare the fingerprint above with the one from '-p', or pass -fingerprint")
		}
	}

	ciphertext, sharedSecret, algName, err := hsm.EncapsulateFromRawKey(rawKey)
	if err != nil {
		return fmt.Errorf("encapsulation failed: %w", err)
	}
	defer clear(sharedSecret)

	if err := os.WriteFile(cipherPath, ciphertext, 0644); err != nil { // #nosec G306 G703 -- KEM ciphertext is public data; path chosen by the operator (flag or env var) of this local CLI
		return fmt.Errorf("failed to write ciphertext: %w", err)
	}
	if err := writeSecretFile(secretPath, sharedSecret); err != nil {
		return fmt.Errorf("failed to write shared secret: %w", err)
	}

	fmt.Printf("[+] Encapsulation successful (%s)!\n", algName)
	fmt.Printf("    Ciphertext    : %s (%d bytes)\n", cipherPath, len(ciphertext))
	fmt.Printf("    Shared Secret : %s (%d bytes)\n", secretPath, len(sharedSecret))
	return nil
}

func runDecap(o *options, libPath string) error {
	env, err := requireEnvs("HSM_TOKEN_LABEL", "HSM_OBJECT_LABEL", "HSM_PIN_FILE")
	if err != nil {
		return err
	}
	tokenLabel, objectLabel, pinFile := env[0], env[1], env[2]

	cipherPath := pathOr(o.cipherFile, "HSM_CIPHER_FILE", "./ciphertext.bin")
	secretPath := pathOr(o.secretFile, "HSM_SECRET_FILE", "./receiver_secret.bin")

	fmt.Printf("[*] Reading ciphertext from: %s\n", cipherPath)
	ciphertext, err := os.ReadFile(cipherPath) // #nosec G304 G703 -- path chosen by the operator (flag or env var) of this local CLI
	if err != nil {
		return fmt.Errorf("failed to read ciphertext file '%s': %w", cipherPath, err)
	}

	fmt.Printf("[*] Decapsulating using HSM Token '%s' (Object: '%s', PIN file: '%s')...\n", tokenLabel, objectLabel, pinFile)
	client, err := hsm.NewClient(libPath)
	if err != nil {
		return fmt.Errorf("initialization error: %w", err)
	}
	defer client.Close()

	sharedSecret, err := client.Decapsulate(tokenLabel, objectLabel, pinFile, ciphertext)
	if err != nil {
		return fmt.Errorf("decapsulation failed: %w", err)
	}
	defer clear(sharedSecret)

	if err := writeSecretFile(secretPath, sharedSecret); err != nil {
		return fmt.Errorf("failed to write shared secret: %w", err)
	}

	fmt.Printf("[+] Decapsulation successful!\n")
	fmt.Printf("    Receiver Shared Secret : %s (%d bytes)\n", secretPath, len(sharedSecret))
	return nil
}

// deriveKey reads the shared secret and KEM ciphertext and derives the AES-256 key.
// The caller must clear() the returned key.
func deriveKey(o *options, defaultSecret string) (aesKey, kemCiphertext []byte, err error) {
	secretPath := pathOr(o.secretFile, "HSM_SECRET_FILE", defaultSecret)
	cipherPath := pathOr(o.cipherFile, "HSM_CIPHER_FILE", "./ciphertext.bin")

	secret, err := os.ReadFile(secretPath) // #nosec G304 G703 -- path chosen by the operator (flag or env var) of this local CLI
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read secret file '%s': %w", secretPath, err)
	}
	defer clear(secret)

	kemCiphertext, err = os.ReadFile(cipherPath) // #nosec G304 G703 -- path chosen by the operator (flag or env var) of this local CLI
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read KEM ciphertext file '%s' (bound into the AEAD tag): %w", cipherPath, err)
	}
	if err := hsm.ValidateMLKEMCiphertextLength(kemCiphertext); err != nil {
		return nil, nil, fmt.Errorf("KEM ciphertext '%s': %w", cipherPath, err)
	}

	aesKey, err = sym.DeriveAES256Key(secret, []byte(o.salt), []byte(o.info))
	if err != nil {
		return nil, nil, fmt.Errorf("key derivation failed: %w", err)
	}
	fmt.Printf("[*] Derived AES-256 key via HKDF-SHA256 (%d bytes), bound to KEM ciphertext %s\n", len(aesKey), cipherPath)
	return aesKey, kemCiphertext, nil
}

func runSymEnc(o *options) error {
	plainPath := pathOr(o.inFile, "PLAIN_MSG_FILE", "./msg.txt")
	outPath := pathOr(o.outFile, "ENC_MSG_FILE", "./msg.enc")

	aesKey, kemCiphertext, err := deriveKey(o, "./sender_secret.bin")
	if err != nil {
		return err
	}
	defer clear(aesKey)

	plaintext, err := os.ReadFile(plainPath) // #nosec G304 G703 -- path chosen by the operator (flag or env var) of this local CLI
	if err != nil {
		return fmt.Errorf("failed to read plaintext input file '%s': %w", plainPath, err)
	}
	defer clear(plaintext)

	encrypted, err := sym.EncryptAESGCM(aesKey, plaintext, kemCiphertext)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	if err := os.WriteFile(outPath, encrypted, 0644); err != nil { // #nosec G306 G703 -- AES-256-GCM output is already encrypted; path chosen by the operator (flag or env var) of this local CLI
		return fmt.Errorf("failed to write encrypted output: %w", err)
	}

	fmt.Printf("[+] AES-256-GCM Encryption successful!\n")
	fmt.Printf("    Input Plaintext : %s (%d bytes)\n", plainPath, len(plaintext))
	fmt.Printf("    Encrypted Output: %s (%d bytes [%dB header + %dB nonce + ciphertext + %dB tag])\n",
		outPath, len(encrypted), len(sym.Header), sym.NonceSize, sym.TagSize)
	return nil
}

func runSymDec(o *options) error {
	encPath := pathOr(o.inFile, "ENC_MSG_FILE", "./msg.enc")
	outPath := pathOr(o.outFile, "DEC_MSG_FILE", "./msg.dec")

	aesKey, kemCiphertext, err := deriveKey(o, "./receiver_secret.bin")
	if err != nil {
		return err
	}
	defer clear(aesKey)

	encrypted, err := os.ReadFile(encPath) // #nosec G304 G703 -- path chosen by the operator (flag or env var) of this local CLI
	if err != nil {
		return fmt.Errorf("failed to read encrypted input file '%s': %w", encPath, err)
	}

	decrypted, err := sym.DecryptAESGCM(aesKey, encrypted, kemCiphertext)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}
	defer clear(decrypted)

	if err := writeSecretFile(outPath, decrypted); err != nil {
		return fmt.Errorf("failed to write decrypted output: %w", err)
	}

	fmt.Printf("[+] AES-256-GCM Decryption & Authentication successful!\n")
	fmt.Printf("    Decrypted Payload: %s (%d bytes)\n", outPath, len(decrypted))
	return nil
}

func runConnectionTest(libPath string) error {
	cfgString := os.Getenv("BOUNCY_HSM_CFG_STRING")
	if cfgString == "" {
		fmt.Fprintln(os.Stderr, "[WARN] BOUNCY_HSM_CFG_STRING is not set.")
	} else {
		fmt.Printf("[*] BOUNCY_HSM_CFG_STRING: %s\n", cfgString)
	}

	fmt.Printf("[*] Loading PKCS#11 library from: %s\n", libPath)
	client, err := hsm.NewClient(libPath)
	if err != nil {
		return fmt.Errorf("initialization error: %w", err)
	}
	defer client.Close()

	info, err := client.GetInfo()
	if err != nil {
		return fmt.Errorf("C_GetInfo failed: %w", err)
	}

	fmt.Printf("[+] Successfully connected to Bouncy HSM!\n")
	fmt.Printf("    Manufacturer : %s\n", info.ManufacturerID)
	fmt.Printf("    Library Desc : %s\n", info.LibraryDescription)
	fmt.Printf("    Spec Version : %d.%d\n", info.CryptokiVersion.Major, info.CryptokiVersion.Minor)

	tokens, err := client.InspectTokens()
	if err != nil {
		return fmt.Errorf("token inspection failed: %w", err)
	}

	if len(tokens) == 0 {
		fmt.Println("[!] No tokens found.")
		return nil
	}

	fmt.Printf("[+] Discovered %d active token(s):\n", len(tokens))
	for _, t := range tokens {
		fmt.Printf("    -> Slot ID   : %d (%s)\n", t.SlotID, t.SlotDescription)
		fmt.Printf("       Label     : %s\n", t.TokenLabel)
		fmt.Printf("       Model/S/N : %s (SN: %s)\n", t.Model, t.SerialNumber)
		fmt.Printf("       Mechanisms: %d supported\n", t.MechanismCount)
	}

	return nil
}
