package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/alain2sf/bhsm-pqc-demo/internal/hsm"
	"github.com/alain2sf/bhsm-pqc-demo/internal/sym"
)

func requireEnv(key string) (string, error) {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return "", fmt.Errorf("required environment variable '%s' is not set", key)
	}
	return val, nil
}

func getEnvOrDefault(key, fallback string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	return fallback
}

func main() {
	// Action Flags (Mutually Exclusive)
	connTest := flag.Bool("c", false, "Run PKCS#11 connection and diagnostic test")
	genPKey := flag.String("g", "", "Generate ML-KEM key pair (e.g. -g ML-KEM-768)")
	exportPub := flag.Bool("p", false, "Export public key from HSM to PEM format")
	encapFlag := flag.Bool("e", false, "Perform ML-KEM encapsulation")
	decapFlag := flag.Bool("d", false, "Perform ML-KEM decapsulation using the HSM private key")
	symEncFlag := flag.Bool("sym-enc", false, "Encrypt plaintext using HKDF-derived AES-256-GCM key")
	symDecFlag := flag.Bool("sym-dec", false, "Decrypt ciphertext using HKDF-derived AES-256-GCM key")

	// Option Flags
	outputFile := flag.String("o", "", "Output file path (for -p public key)")
	inFile := flag.String("in", "", "Input file path (-in <pubkey.pem> for -e, -in <msg.txt> for -sym-enc, -in <msg.enc> for -sym-dec)")
	outFile := flag.String("out", "", "Output file path for symmetric payload (-sym-enc / -sym-dec)")
	cipherFile := flag.String("cipher", "", "Path for KEM ciphertext file (-e output, -d input, default: ./ciphertext.bin)")
	secretFile := flag.String("secret", "", "Path for shared secret file (-e, -d, -sym-enc, -sym-dec)")
	saltFlag := flag.String("salt", "", "Optional HKDF salt (default: 'bhsm-demo-hkdf-salt-v1')")
	infoFlag := flag.String("info", "", "Optional HKDF context info (default: 'bhsm-demo aes-256-gcm v1')")
	libPathFlag := flag.String("lib", "", "Path to BouncyHsm.Pkcs11Lib library (.dylib/.so)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nActions (mutually exclusive - pick exactly one):\n")
		fmt.Fprintf(os.Stderr, "  -c                      Run connection and slot check\n")
		fmt.Fprintf(os.Stderr, "  -g <algorithm>          Generate key pair (e.g., -g ML-KEM-768)\n")
		fmt.Fprintf(os.Stderr, "  -p                      Export public key to PEM format\n")
		fmt.Fprintf(os.Stderr, "  -e                      Encapsulate shared secret against public key\n")
		fmt.Fprintf(os.Stderr, "  -d                      Decapsulate shared secret using HSM private key\n")
		fmt.Fprintf(os.Stderr, "  -sym-enc                Encrypt plaintext with HKDF-derived AES-256-GCM\n")
		fmt.Fprintf(os.Stderr, "  -sym-dec                Decrypt ciphertext with HKDF-derived AES-256-GCM\n")
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		fmt.Fprintf(os.Stderr, "  -in <path>              Input file path\n")
		fmt.Fprintf(os.Stderr, "  -out <path>             Output file path for symmetric payload\n")
		fmt.Fprintf(os.Stderr, "  -cipher <path>          KEM ciphertext file path (default: ./ciphertext.bin)\n")
		fmt.Fprintf(os.Stderr, "  -secret <path>          Shared secret file path\n")
		fmt.Fprintf(os.Stderr, "  -salt <string>          HKDF salt\n")
		fmt.Fprintf(os.Stderr, "  -info <string>          HKDF domain separation context\n")
		fmt.Fprintf(os.Stderr, "  -o <path>               Output file path for public key (for -p)\n")
		fmt.Fprintf(os.Stderr, "  -lib <path>             Path to PKCS#11 dynamic library\n")
	}

	flag.Parse()

	// 1. Enforce mutually exclusive actions
	actionsCount := 0
	if *connTest {
		actionsCount++
	}
	if *genPKey != "" {
		actionsCount++
	}
	if *exportPub {
		actionsCount++
	}
	if *encapFlag {
		actionsCount++
	}
	if *decapFlag {
		actionsCount++
	}
	if *symEncFlag {
		actionsCount++
	}
	if *symDecFlag {
		actionsCount++
	}

	if actionsCount == 0 {
		fmt.Println("[!] No action specified.")
		flag.Usage()
		os.Exit(1)
	}

	if actionsCount > 1 {
		log.Fatalf("[-] Only one action flag can be specified at a time.")
	}

	// 2. Resolve PKCS#11 library path
	libPath := *libPathFlag
	if libPath == "" {
		libPath = os.Getenv("PKCS11_LIB_PATH")
	}
	if libPath == "" {
		libPath = "./libBouncyHsm.Pkcs11Lib.dylib"
	}

	// 3. Dispatch selected action
	switch {
	case *connTest:
		if err := runConnectionTest(libPath); err != nil {
			log.Fatalf("[-] Connection test failed: %v", err)
		}

	case *genPKey != "":
		tokenLabel, err := requireEnv("HSM_TOKEN_LABEL")
		if err != nil {
			log.Fatalf("[-] %v", err)
		}
		objectLabel, err := requireEnv("HSM_OBJECT_LABEL")
		if err != nil {
			log.Fatalf("[-] %v", err)
		}
		pinFile, err := requireEnv("HSM_PIN_FILE")
		if err != nil {
			log.Fatalf("[-] %v", err)
		}

		fmt.Printf("[*] Target Token : %s\n", tokenLabel)
		fmt.Printf("[*] Object Label : %s\n", objectLabel)
		fmt.Printf("[*] PIN File     : %s\n", pinFile)

		client, err := hsm.NewClient(libPath)
		if err != nil {
			log.Fatalf("[-] Initialization error: %v", err)
		}
		defer client.Close()

		if err := client.GenerateMLKEMKeyPair(tokenLabel, objectLabel, pinFile, *genPKey); err != nil {
			log.Fatalf("[-] Key generation failed: %v", err)
		}

	case *exportPub:
		if *outputFile == "" {
			log.Fatalf("[-] Missing output file. Flag '-p' requires '-o <path>' (e.g. -p -o mlkem768_pub.pem).")
		}

		tokenLabel, err := requireEnv("HSM_TOKEN_LABEL")
		if err != nil {
			log.Fatalf("[-] %v", err)
		}
		objectLabel, err := requireEnv("HSM_OBJECT_LABEL")
		if err != nil {
			log.Fatalf("[-] %v", err)
		}

		fmt.Printf("[*] Target Token : %s\n", tokenLabel)
		fmt.Printf("[*] Object Label : %s\n", objectLabel)
		fmt.Printf("[*] Output PEM   : %s\n", *outputFile)

		client, err := hsm.NewClient(libPath)
		if err != nil {
			log.Fatalf("[-] Initialization error: %v", err)
		}
		defer client.Close()

		if err := client.ExportPublicKeyPEM(tokenLabel, objectLabel, *outputFile); err != nil {
			log.Fatalf("[-] Public key export failed: %v", err)
		}

	case *encapFlag:
		targetCipherFile := *cipherFile
		if targetCipherFile == "" {
			targetCipherFile = getEnvOrDefault("HSM_CIPHER_FILE", "./ciphertext.bin")
		}

		targetSecretFile := *secretFile
		if targetSecretFile == "" {
			targetSecretFile = getEnvOrDefault("HSM_SECRET_FILE", "./sender_secret.bin")
		}

		inputPubFile := *inFile
		if inputPubFile == "" {
			inputPubFile = os.Getenv("HSM_PUBKEY_FILE")
		}

		var ciphertext, sharedSecret []byte
		var algName string

		if inputPubFile != "" {
			fmt.Printf("[*] Reading public key from PEM file: %s\n", inputPubFile)
			var err error
			ciphertext, sharedSecret, algName, err = hsm.EncapsulateFromPEM(inputPubFile)
			if err != nil {
				log.Fatalf("[-] PEM encapsulation failed: %v", err)
			}
		} else {
			tokenLabel, err := requireEnv("HSM_TOKEN_LABEL")
			if err != nil {
				log.Fatalf("[-] %v (or supply -in <pubkey.pem>)", err)
			}
			objectLabel, err := requireEnv("HSM_OBJECT_LABEL")
			if err != nil {
				log.Fatalf("[-] %v (or supply -in <pubkey.pem>)", err)
			}

			fmt.Printf("[*] Fetching public key from HSM Token '%s' (Object: '%s')...\n", tokenLabel, objectLabel)
			client, err := hsm.NewClient(libPath)
			if err != nil {
				log.Fatalf("[-] Initialization error: %v", err)
			}
			defer client.Close()

			rawKey, err := client.FetchRawPublicKey(tokenLabel, objectLabel)
			if err != nil {
				log.Fatalf("[-] Public key retrieval failed: %v", err)
			}

			ciphertext, sharedSecret, algName, err = hsm.EncapsulateFromRawKey(rawKey)
			if err != nil {
				log.Fatalf("[-] HSM key encapsulation failed: %v", err)
			}
		}

		if err := os.WriteFile(targetCipherFile, ciphertext, 0644); err != nil {
			log.Fatalf("[-] Failed to write ciphertext: %v", err)
		}
		if err := os.WriteFile(targetSecretFile, sharedSecret, 0644); err != nil {
			log.Fatalf("[-] Failed to write shared secret: %v", err)
		}

		fmt.Printf("[+] Encapsulation successful (%s)!\n", algName)
		fmt.Printf("    Ciphertext    : %s (%d bytes)\n", targetCipherFile, len(ciphertext))
		fmt.Printf("    Shared Secret : %s (%d bytes)\n", targetSecretFile, len(sharedSecret))

	case *decapFlag:
		tokenLabel, err := requireEnv("HSM_TOKEN_LABEL")
		if err != nil {
			log.Fatalf("[-] %v", err)
		}
		objectLabel, err := requireEnv("HSM_OBJECT_LABEL")
		if err != nil {
			log.Fatalf("[-] %v", err)
		}
		pinFile, err := requireEnv("HSM_PIN_FILE")
		if err != nil {
			log.Fatalf("[-] %v", err)
		}

		targetCipherFile := *cipherFile
		if targetCipherFile == "" {
			targetCipherFile = getEnvOrDefault("HSM_CIPHER_FILE", "./ciphertext.bin")
		}

		targetSecretFile := *secretFile
		if targetSecretFile == "" {
			targetSecretFile = getEnvOrDefault("HSM_SECRET_FILE", "./receiver_secret.bin")
		}

		fmt.Printf("[*] Reading ciphertext from: %s\n", targetCipherFile)
		ciphertext, err := os.ReadFile(targetCipherFile)
		if err != nil {
			log.Fatalf("[-] Failed to read ciphertext file '%s': %v", targetCipherFile, err)
		}

		fmt.Printf("[*] Decapsulating using HSM Token '%s' (Object: '%s', PIN: '%s')...\n", tokenLabel, objectLabel, pinFile)
		client, err := hsm.NewClient(libPath)
		if err != nil {
			log.Fatalf("[-] Initialization error: %v", err)
		}
		defer client.Close()

		sharedSecret, err := client.Decapsulate(tokenLabel, objectLabel, pinFile, ciphertext)
		if err != nil {
			log.Fatalf("[-] Decapsulation failed: %v", err)
		}

		if err := os.WriteFile(targetSecretFile, sharedSecret, 0644); err != nil {
			log.Fatalf("[-] Failed to write shared secret: %v", err)
		}

		fmt.Printf("[+] Decapsulation successful!\n")
		fmt.Printf("    Receiver Shared Secret : %s (%d bytes)\n", targetSecretFile, len(sharedSecret))

	case *symEncFlag:
		secFile := *secretFile
		if secFile == "" {
			secFile = getEnvOrDefault("HSM_SECRET_FILE", "./sender_secret.bin")
		}

		inputPlainFile := *inFile
		if inputPlainFile == "" {
			inputPlainFile = getEnvOrDefault("PLAIN_MSG_FILE", "./msg.txt")
		}

		targetOutFile := *outFile
		if targetOutFile == "" {
			targetOutFile = getEnvOrDefault("ENC_MSG_FILE", "./msg.enc")
		}

		secretBytes, err := os.ReadFile(secFile)
		if err != nil {
			log.Fatalf("[-] Failed to read secret file '%s': %v", secFile, err)
		}

		plainBytes, err := os.ReadFile(inputPlainFile)
		if err != nil {
			log.Fatalf("[-] Failed to read plaintext input file '%s': %v", inputPlainFile, err)
		}

		salt := []byte(*saltFlag)
		info := []byte(*infoFlag)

		// 1. Derive AES-256 Key via HKDF
		aesKey, err := sym.DeriveAES256Key(secretBytes, salt, info)
		if err != nil {
			log.Fatalf("[-] Key derivation failed: %v", err)
		}
		fmt.Printf("[*] Derived AES-256 Key (HKDF): %s\n", hex.EncodeToString(aesKey))

		// 2. Encrypt with AES-256-GCM
		encryptedBytes, err := sym.EncryptAESGCM(aesKey, plainBytes)
		if err != nil {
			log.Fatalf("[-] Encryption failed: %v", err)
		}

		if err := os.WriteFile(targetOutFile, encryptedBytes, 0644); err != nil {
			log.Fatalf("[-] Failed to write encrypted output: %v", err)
		}

		fmt.Printf("[+] AES-256-GCM Encryption successful!\n")
		fmt.Printf("    Input Plaintext : %s (%d bytes)\n", inputPlainFile, len(plainBytes))
		fmt.Printf("    Encrypted Output: %s (%d bytes [12B Nonce + Ciphertext + 16B Tag])\n", targetOutFile, len(encryptedBytes))

	case *symDecFlag:
		secFile := *secretFile
		if secFile == "" {
			secFile = getEnvOrDefault("HSM_SECRET_FILE", "./receiver_secret.bin")
		}

		inputEncFile := *inFile
		if inputEncFile == "" {
			inputEncFile = getEnvOrDefault("ENC_MSG_FILE", "./msg.enc")
		}

		targetOutFile := *outFile
		if targetOutFile == "" {
			targetOutFile = getEnvOrDefault("DEC_MSG_FILE", "./msg.dec")
		}

		secretBytes, err := os.ReadFile(secFile)
		if err != nil {
			log.Fatalf("[-] Failed to read secret file '%s': %v", secFile, err)
		}

		encBytes, err := os.ReadFile(inputEncFile)
		if err != nil {
			log.Fatalf("[-] Failed to read encrypted input file '%s': %v", inputEncFile, err)
		}

		salt := []byte(*saltFlag)
		info := []byte(*infoFlag)

		// 1. Derive AES-256 Key via HKDF
		aesKey, err := sym.DeriveAES256Key(secretBytes, salt, info)
		if err != nil {
			log.Fatalf("[-] Key derivation failed: %v", err)
		}
		fmt.Printf("[*] Derived AES-256 Key (HKDF): %s\n", hex.EncodeToString(aesKey))

		// 2. Decrypt & Authenticate with AES-256-GCM
		decryptedBytes, err := sym.DecryptAESGCM(aesKey, encBytes)
		if err != nil {
			log.Fatalf("[-] Decryption failed: %v", err)
		}

		if err := os.WriteFile(targetOutFile, decryptedBytes, 0644); err != nil {
			log.Fatalf("[-] Failed to write decrypted output: %v", err)
		}

		fmt.Printf("[+] AES-256-GCM Decryption & Authentication successful!\n")
		fmt.Printf("    Decrypted Payload: %s (%d bytes)\n", targetOutFile, len(decryptedBytes))
		fmt.Printf("    Recovered Text   : %q\n", string(decryptedBytes))
	}
}

func runConnectionTest(libPath string) error {
	cfgString := os.Getenv("BOUNCY_HSM_CFG_STRING")
	if cfgString == "" {
		log.Println("[WARN] BOUNCY_HSM_CFG_STRING is not set.")
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
