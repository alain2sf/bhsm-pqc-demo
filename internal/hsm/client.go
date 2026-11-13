// Package hsm provides high-level abstractions over the OASIS PKCS#11 standard
// interface for Bouncy HSM and Post-Quantum Cryptography (PQC) operations.
package hsm

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/alain2sf/bhsm-pqc-demo/internal/pkcs11v3"
	"github.com/miekg/pkcs11"
)

// PKCS#11 v3.2 Post-Quantum Cryptography & Attribute Constants
const (
	CKA_UNIQUE_ID           = 0x00000004
	CKK_ML_KEM              = 0x00000049
	CKM_ML_KEM_KEY_PAIR_GEN = 0x0000000F
	CKM_ML_KEM              = 0x00000017
	CKA_PARAMETER_SET       = 0x0000061D
	CKA_ENCAPSULATE         = 0x00000633
	CKA_DECAPSULATE         = 0x00000634

	CKP_ML_KEM_512  = 1
	CKP_ML_KEM_768  = 2
	CKP_ML_KEM_1024 = 3
)

// FIPS 203 ML-KEM ciphertext sizes in bytes.
const (
	MLKEM512CiphertextSize  = 768
	MLKEM768CiphertextSize  = 1088
	MLKEM1024CiphertextSize = 1568
)

// NIST FIPS 203 / IETF OIDs for ML-KEM
var (
	OIDMLKEM512  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 1}
	OIDMLKEM768  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
	OIDMLKEM1024 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}
)

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type SubjectPublicKeyInfo struct {
	Algorithm AlgorithmIdentifier
	PublicKey asn1.BitString
}

type Client struct {
	ctx     *pkcs11.Ctx
	v3      *pkcs11v3.Driver
	libPath string
}

type TokenSummary struct {
	SlotID          uint
	SlotDescription string
	TokenLabel      string
	Model           string
	SerialNumber    string
	MechanismCount  int
}

func NewClient(libPath string) (*Client, error) {
	if strings.TrimSpace(libPath) == "" {
		return nil, fmt.Errorf("PKCS#11 library path cannot be empty")
	}

	v3Driver, err := pkcs11v3.Open(libPath)
	if err != nil {
		return nil, err
	}

	ctx := pkcs11.New(libPath)
	if ctx == nil {
		v3Driver.Close()
		return nil, fmt.Errorf("failed to load PKCS#11 module from: %s", libPath)
	}

	if err := ctx.Initialize(); err != nil {
		ctx.Destroy()
		v3Driver.Close()
		return nil, fmt.Errorf("failed to initialize PKCS#11 module: %w", err)
	}

	return &Client{
		ctx:     ctx,
		v3:      v3Driver,
		libPath: libPath,
	}, nil
}

func (c *Client) Close() {
	if c.ctx != nil {
		_ = c.ctx.Finalize()
		c.ctx.Destroy()
		c.ctx = nil
	}
	if c.v3 != nil {
		c.v3.Close()
		c.v3 = nil
	}
}

func (c *Client) GetInfo() (pkcs11.Info, error) {
	return c.ctx.GetInfo()
}

func (c *Client) InspectTokens() ([]TokenSummary, error) {
	slots, err := c.ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("failed to get slot list: %w", err)
	}

	var summaries []TokenSummary
	for _, slotID := range slots {
		slotInfo, err := c.ctx.GetSlotInfo(slotID)
		if err != nil {
			return nil, fmt.Errorf("failed to get info for slot %d: %w", slotID, err)
		}

		tokenInfo, err := c.ctx.GetTokenInfo(slotID)
		if err != nil {
			return nil, fmt.Errorf("failed to get token info for slot %d: %w", slotID, err)
		}

		mechs, err := c.ctx.GetMechanismList(slotID)
		if err != nil {
			return nil, fmt.Errorf("failed to get mechanism list for slot %d: %w", slotID, err)
		}

		summaries = append(summaries, TokenSummary{
			SlotID:          slotID,
			SlotDescription: strings.TrimSpace(slotInfo.SlotDescription),
			TokenLabel:      strings.TrimSpace(tokenInfo.Label),
			Model:           strings.TrimSpace(tokenInfo.Model),
			SerialNumber:    strings.TrimSpace(tokenInfo.SerialNumber),
			MechanismCount:  len(mechs),
		})
	}

	return summaries, nil
}

func (c *Client) FindSlotByTokenLabel(targetLabel string) (uint, error) {
	slots, err := c.ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("failed to query slots: %w", err)
	}

	for _, slotID := range slots {
		tokenInfo, err := c.ctx.GetTokenInfo(slotID)
		if err != nil {
			continue
		}
		if strings.TrimSpace(tokenInfo.Label) == targetLabel {
			return slotID, nil
		}
	}

	return 0, fmt.Errorf("token with label '%s' not found on HSM", targetLabel)
}

// GetUniqueID queries the CKA_UNIQUE_ID attribute for any PKCS#11 object.
func (c *Client) GetUniqueID(session pkcs11.SessionHandle, obj pkcs11.ObjectHandle) string {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(CKA_UNIQUE_ID, nil),
	}
	attrs, err := c.ctx.GetAttributeValue(session, obj, template)
	if err != nil || len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return "N/A"
	}

	val := attrs[0].Value
	// Return string representation if printable UTF-8, else hex-encoded
	strVal := string(val)
	for _, r := range strVal {
		if r < 32 || r > 126 {
			return fmt.Sprintf("%x", val)
		}
	}
	return strVal
}

// findObjects returns every object handle matching the template.
func (c *Client) findObjects(session pkcs11.SessionHandle, template []*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	if err := c.ctx.FindObjectsInit(session, template); err != nil {
		return nil, fmt.Errorf("C_FindObjectsInit failed: %w", err)
	}

	var all []pkcs11.ObjectHandle
	for {
		objs, _, err := c.ctx.FindObjects(session, 50)
		if err != nil {
			_ = c.ctx.FindObjectsFinal(session)
			return nil, fmt.Errorf("C_FindObjects failed: %w", err)
		}
		if len(objs) == 0 {
			break
		}
		all = append(all, objs...)
	}

	if err := c.ctx.FindObjectsFinal(session); err != nil {
		return nil, fmt.Errorf("C_FindObjectsFinal failed: %w", err)
	}
	return all, nil
}

// findUniqueMLKEMKey locates exactly one ML-KEM key of the given class and label.
// Zero matches or more than one match are errors: an ambiguous label could let a
// planted object stand in for the real key.
func (c *Client) findUniqueMLKEMKey(session pkcs11.SessionHandle, class uint, objectLabel, tokenLabel string) (pkcs11.ObjectHandle, error) {
	kind := "public"
	if class == pkcs11.CKO_PRIVATE_KEY {
		kind = "private"
	}

	objs, err := c.findObjects(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_ML_KEM),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, objectLabel),
	})
	if err != nil {
		return 0, err
	}

	switch len(objs) {
	case 0:
		return 0, fmt.Errorf("ML-KEM %s key '%s' not found on token '%s'", kind, objectLabel, tokenLabel)
	case 1:
		return objs[0], nil
	default:
		return 0, fmt.Errorf("ambiguous: %d ML-KEM %s keys labelled '%s' on token '%s'", len(objs), kind, objectLabel, tokenLabel)
	}
}

// DeleteObjectsByLabel searches for, logs CKA_UNIQUE_ID, and deletes all existing
// objects matching the specified label on the active token, except handles in keep.
func (c *Client) DeleteObjectsByLabel(session pkcs11.SessionHandle, objectLabel string, keep map[pkcs11.ObjectHandle]bool) error {
	classes := []struct {
		id   uint
		name string
	}{
		{id: pkcs11.CKO_PUBLIC_KEY, name: "Public Key"},
		{id: pkcs11.CKO_PRIVATE_KEY, name: "Private Key"},
		{id: pkcs11.CKO_SECRET_KEY, name: "Secret Key"},
	}

	var deletedLog []string

	for _, cls := range classes {
		// Collect handles first, then destroy outside the active search.
		objs, err := c.findObjects(session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, cls.id),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, objectLabel),
		})
		if err != nil {
			return fmt.Errorf("%s search failed: %w", cls.name, err)
		}

		for _, obj := range objs {
			if keep[obj] {
				continue
			}

			// Query CKA_UNIQUE_ID before destroying the object
			uniqueID := c.GetUniqueID(session, obj)

			if err := c.ctx.DestroyObject(session, obj); err != nil {
				return fmt.Errorf("failed to destroy %s (handle %d): %w", cls.name, obj, err)
			}

			deletedLog = append(deletedLog, fmt.Sprintf("    -> Deleted %-11s (Handle: %d, CKA_UNIQUE_ID: %s)", cls.name, obj, uniqueID))
		}
	}

	if len(deletedLog) > 0 {
		fmt.Printf("[*] Cleaned up %d previous object(s) with label '%s':\n", len(deletedLog), objectLabel)
		for _, line := range deletedLog {
			fmt.Println(line)
		}
	} else {
		fmt.Printf("[*] No existing objects with label '%s' found to clean up.\n", objectLabel)
	}

	return nil
}

// ReadPINFile reads the token user PIN, refusing files that group or others can
// access. The raw buffer is cleared after use; the returned string cannot be
// (Go strings are immutable), so callers should keep it no longer than needed.
func ReadPINFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("could not stat PIN file '%s': %w", path, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("PIN file '%s' has permissions %04o; it must not be accessible by group or others (run: chmod 600 %s)", path, perm, path)
	}

	pinBytes, err := os.ReadFile(path) // #nosec G304 -- HSM_PIN_FILE set by the operator; owner-only mode checked above
	if err != nil {
		return "", fmt.Errorf("could not read PIN file '%s': %w", path, err)
	}
	defer clear(pinBytes)

	pin := strings.TrimRight(string(pinBytes), "\r\n")
	if pin == "" {
		return "", fmt.Errorf("PIN file '%s' is empty", path)
	}
	return pin, nil
}

// readValue reads a non-empty CKA_VALUE, reporting PKCS#11 errors and empty values separately.
func (c *Client) readValue(session pkcs11.SessionHandle, obj pkcs11.ObjectHandle, what string) ([]byte, error) {
	attrs, err := c.ctx.GetAttributeValue(session, obj, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read %s CKA_VALUE: %w", what, err)
	}
	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return nil, fmt.Errorf("%s CKA_VALUE is empty", what)
	}
	return attrs[0].Value, nil
}

func (c *Client) GenerateMLKEMKeyPair(tokenLabel, objectLabel, pinFilePath, algorithm string) error {
	paramSet, err := ParseMLKEMAlgorithm(algorithm)
	if err != nil {
		return err
	}

	pin, err := ReadPINFile(pinFilePath)
	if err != nil {
		return err
	}

	slotID, err := c.FindSlotByTokenLabel(tokenLabel)
	if err != nil {
		return err
	}
	fmt.Printf("[*] Found token '%s' on Slot ID: %d\n", tokenLabel, slotID)

	session, err := c.ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("failed to open session on slot %d: %w", slotID, err)
	}
	defer c.ctx.CloseSession(session)

	if err := c.ctx.Login(session, pkcs11.CKU_USER, pin); err != nil {
		return fmt.Errorf("failed to login to token: %w", err)
	}
	defer c.ctx.Logout(session)

	fmt.Printf("[*] Generating %s key pair (Object Label: '%s')...\n", algorithm, objectLabel)

	// Random CKA_ID shared by both halves so the pair can be matched unambiguously.
	keyID := make([]byte, 16)
	if _, err := rand.Read(keyID); err != nil {
		return fmt.Errorf("failed to generate CKA_ID: %w", err)
	}

	mech := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(CKM_ML_KEM_KEY_PAIR_GEN, nil),
	}

	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, objectLabel),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(CKA_PARAMETER_SET, paramSet),
		pkcs11.NewAttribute(CKA_ENCAPSULATE, true),
	}

	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, objectLabel),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		pkcs11.NewAttribute(CKA_PARAMETER_SET, paramSet),
		pkcs11.NewAttribute(CKA_DECAPSULATE, true),
	}

	// Generate first, so a failure here leaves any existing key pair intact.
	pubHandle, privHandle, err := c.ctx.GenerateKeyPair(session, mech, pubTemplate, privTemplate)
	if err != nil {
		return fmt.Errorf("C_GenerateKeyPair failed (existing keys left untouched): %w", err)
	}

	// Now remove the previous objects with this label, keeping the new pair.
	keep := map[pkcs11.ObjectHandle]bool{pubHandle: true, privHandle: true}
	if err := c.DeleteObjectsByLabel(session, objectLabel, keep); err != nil {
		return fmt.Errorf("new key pair created (pub %d, priv %d) but cleanup of old '%s' objects failed; "+
			"lookups will refuse the label as ambiguous until it is resolved: %w", pubHandle, privHandle, objectLabel, err)
	}

	// Query CKA_UNIQUE_ID for both generated keys
	pubUniqueID := c.GetUniqueID(session, pubHandle)
	privUniqueID := c.GetUniqueID(session, privHandle)

	fmt.Printf("[+] Key pair generated successfully!\n")
	fmt.Printf("    Public Key Handle     : %d (0x%X)\n", pubHandle, pubHandle)
	fmt.Printf("    Public Key Unique ID  : %s\n", pubUniqueID)
	fmt.Printf("    Private Key Handle    : %d (0x%X)\n", privHandle, privHandle)
	fmt.Printf("    Private Key Unique ID : %s\n", privUniqueID)
	return nil
}

// FetchRawPublicKey reads the ML-KEM public key labelled objectLabel.
//
// With an empty pinFilePath it uses a public session and only checks that the
// label is unambiguous. With a PIN file it logs in and also proves the public key
// belongs to the private key of the same label (see verifyKeyPair). This matters
// because the public object can be replaced without the PIN, and whoever holds
// the matching private key could then read everything encrypted to it.
func (c *Client) FetchRawPublicKey(tokenLabel, objectLabel, pinFilePath string) ([]byte, error) {
	slotID, err := c.FindSlotByTokenLabel(tokenLabel)
	if err != nil {
		return nil, err
	}

	session, err := c.ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, fmt.Errorf("failed to open session on slot %d: %w", slotID, err)
	}
	defer c.ctx.CloseSession(session)

	if pinFilePath != "" {
		pin, err := ReadPINFile(pinFilePath)
		if err != nil {
			return nil, err
		}
		if err := c.ctx.Login(session, pkcs11.CKU_USER, pin); err != nil {
			return nil, fmt.Errorf("failed to login to token: %w", err)
		}
		defer c.ctx.Logout(session)
	}

	pubHandle, err := c.findUniqueMLKEMKey(session, pkcs11.CKO_PUBLIC_KEY, objectLabel, tokenLabel)
	if err != nil {
		return nil, err
	}

	rawKey, err := c.readValue(session, pubHandle, "public key")
	if err != nil {
		return nil, err
	}

	if pinFilePath == "" {
		fmt.Println("[!] Warning: no HSM_PIN_FILE set; public/private key pairing not verified")
		return rawKey, nil
	}
	if err := c.verifyKeyPair(session, pubHandle, rawKey, objectLabel, tokenLabel); err != nil {
		return nil, err
	}
	return rawKey, nil
}

// verifyKeyPair checks, in a logged-in session, that the public key belongs to the
// unique private key of the same label:
//
//  1. both carry the same non-empty CKA_ID (set at keygen; catches stale or
//     mismatched objects, but CKA_ID is public and can be copied);
//  2. a fresh local encapsulation to rawKey decapsulates on the HSM to the same
//     shared secret, which only the matching private key can do.
//
// ML-KEM-512 cannot be encapsulated locally, so only step 1 runs for it.
func (c *Client) verifyKeyPair(session pkcs11.SessionHandle, pubHandle pkcs11.ObjectHandle, rawKey []byte, objectLabel, tokenLabel string) error {
	privHandle, err := c.findUniqueMLKEMKey(session, pkcs11.CKO_PRIVATE_KEY, objectLabel, tokenLabel)
	if err != nil {
		return err
	}

	pubID, err := c.readID(session, pubHandle, "public key")
	if err != nil {
		return err
	}
	privID, err := c.readID(session, privHandle, "private key")
	if err != nil {
		return err
	}
	if !bytes.Equal(pubID, privID) {
		return fmt.Errorf("key pair mismatch: public key CKA_ID %x differs from private key CKA_ID %x", pubID, privID)
	}

	if len(rawKey) == 800 {
		fmt.Printf("[!] Warning: ML-KEM-512 cannot be encapsulated locally; pairing checked by CKA_ID (%x) only\n", pubID)
		return nil
	}

	ciphertext, want, _, err := EncapsulateFromRawKey(rawKey)
	if err != nil {
		return fmt.Errorf("pairing check encapsulation failed: %w", err)
	}
	defer clear(want)

	got, err := c.decapsulateWith(session, privHandle, ciphertext)
	if err != nil {
		return fmt.Errorf("pairing check decapsulation failed: %w", err)
	}
	defer clear(got)

	if subtle.ConstantTimeCompare(got, want) != 1 {
		return errors.New("key pair mismatch: the HSM private key does not decapsulate to the public key's shared secret")
	}
	fmt.Printf("[+] Key pair verified: CKA_ID %x, encapsulation round-trip on HSM succeeded\n", pubID)
	return nil
}

// readID reads a non-empty CKA_ID.
func (c *Client) readID(session pkcs11.SessionHandle, obj pkcs11.ObjectHandle, what string) ([]byte, error) {
	attrs, err := c.ctx.GetAttributeValue(session, obj, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read %s CKA_ID: %w", what, err)
	}
	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return nil, fmt.Errorf("%s has no CKA_ID (generated before key pairing was recorded? re-run -g)", what)
	}
	return attrs[0].Value, nil
}

func (c *Client) ExportPublicKeyPEM(tokenLabel, objectLabel, pinFilePath, outputPath string) error {
	rawPubKey, err := c.FetchRawPublicKey(tokenLabel, objectLabel, pinFilePath)
	if err != nil {
		return err
	}

	pemBytes, algName, err := EncodeRawPublicKeyToPEM(rawPubKey)
	if err != nil {
		return err
	}
	fingerprint, err := PublicKeyFingerprint(rawPubKey)
	if err != nil {
		return err
	}
	fmt.Printf("[*] Extracted %s raw public key (%d bytes)\n", algName, len(rawPubKey))
	fmt.Printf("[*] Fingerprint  : %s\n", fingerprint)

	if err := os.WriteFile(outputPath, pemBytes, 0644); err != nil { // #nosec G306 -- a public key, meant to be shared
		return fmt.Errorf("failed to write PEM output to '%s': %w", outputPath, err)
	}

	fmt.Printf("[+] Public key successfully exported to: %s\n", outputPath)
	return nil
}

// ValidateMLKEMCiphertextLength rejects ciphertexts whose length matches no
// ML-KEM parameter set (FIPS 203: 768, 1088, or 1568 bytes).
func ValidateMLKEMCiphertextLength(ciphertext []byte) error {
	switch len(ciphertext) {
	case MLKEM512CiphertextSize, MLKEM768CiphertextSize, MLKEM1024CiphertextSize:
		return nil
	default:
		return fmt.Errorf("invalid ML-KEM ciphertext length: %d bytes (expected %d, %d, or %d)",
			len(ciphertext), MLKEM512CiphertextSize, MLKEM768CiphertextSize, MLKEM1024CiphertextSize)
	}
}

func (c *Client) Decapsulate(tokenLabel, objectLabel, pinFilePath string, ciphertext []byte) ([]byte, error) {
	if err := ValidateMLKEMCiphertextLength(ciphertext); err != nil {
		return nil, err
	}

	pin, err := ReadPINFile(pinFilePath)
	if err != nil {
		return nil, err
	}

	slotID, err := c.FindSlotByTokenLabel(tokenLabel)
	if err != nil {
		return nil, err
	}
	fmt.Printf("[*] Found token '%s' on Slot ID: %d\n", tokenLabel, slotID)

	session, err := c.ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("failed to open session on slot %d: %w", slotID, err)
	}
	defer c.ctx.CloseSession(session)

	if err := c.ctx.Login(session, pkcs11.CKU_USER, pin); err != nil {
		return nil, fmt.Errorf("failed to login to token: %w", err)
	}
	defer c.ctx.Logout(session)

	privHandle, err := c.findUniqueMLKEMKey(session, pkcs11.CKO_PRIVATE_KEY, objectLabel, tokenLabel)
	if err != nil {
		return nil, err
	}
	privUniqueID := c.GetUniqueID(session, privHandle)
	fmt.Printf("[*] Located private key object handle: %d (0x%X, CKA_UNIQUE_ID: %s)\n", privHandle, privHandle, privUniqueID)

	// The caller owns the returned secret and should clear() it after use.
	sharedSecret, err := c.decapsulateWith(session, privHandle, ciphertext)
	if err != nil {
		return nil, err
	}

	fmt.Printf("[+] HSM Decapsulation completed natively on server!\n")
	return sharedSecret, nil
}

// decapsulateWith runs C_DecapsulateKey with privHandle in a logged-in session and
// returns the shared secret, destroying the temporary derived key object.
func (c *Client) decapsulateWith(session pkcs11.SessionHandle, privHandle pkcs11.ObjectHandle, ciphertext []byte) ([]byte, error) {
	derivedKeyHandle, err := c.v3.DecapsulateKey(uint(session), CKM_ML_KEM, uint(privHandle), ciphertext)
	if err != nil {
		return nil, fmt.Errorf("HSM C_DecapsulateKey failed: %w", err)
	}
	defer c.ctx.DestroyObject(session, pkcs11.ObjectHandle(derivedKeyHandle))

	return c.readValue(session, pkcs11.ObjectHandle(derivedKeyHandle), "derived shared secret")
}

func EncapsulateFromRawKey(rawKey []byte) (ciphertext []byte, sharedSecret []byte, algName string, err error) {
	switch len(rawKey) {
	case 800:
		return nil, nil, "", fmt.Errorf("ML-KEM-512 is not supported by Go crypto/mlkem; use ML-KEM-768 or ML-KEM-1024")
	case 1184:
		algName = "ML-KEM-768"
		encapKey, err := mlkem.NewEncapsulationKey768(rawKey)
		if err != nil {
			return nil, nil, "", fmt.Errorf("failed to parse ML-KEM-768 key: %w", err)
		}
		ss, ct := encapKey.Encapsulate()
		return ct, ss, algName, nil
	case 1568:
		algName = "ML-KEM-1024"
		encapKey, err := mlkem.NewEncapsulationKey1024(rawKey)
		if err != nil {
			return nil, nil, "", fmt.Errorf("failed to parse ML-KEM-1024 key: %w", err)
		}
		ss, ct := encapKey.Encapsulate()
		return ct, ss, algName, nil
	default:
		return nil, nil, "", fmt.Errorf("unexpected public key length: %d bytes", len(rawKey))
	}
}

// EncapsulateFromPEM reads and validates an ML-KEM SPKI PEM file, then
// encapsulates against it. It does not check where the key came from: callers
// that need that should use ReadPublicKeyPEM and CheckPublicKeyFingerprint.
func EncapsulateFromPEM(pemPath string) (ciphertext []byte, sharedSecret []byte, algName string, err error) {
	rawKey, err := ReadPublicKeyPEM(pemPath)
	if err != nil {
		return nil, nil, "", err
	}
	return EncapsulateFromRawKey(rawKey)
}

// ReadPublicKeyPEM reads an ML-KEM SubjectPublicKeyInfo PEM file and returns the
// raw encapsulation key after strict structural checks (no trailing DER, absent
// parameters, whole-byte BIT STRING, OID matching the key length).
func ReadPublicKeyPEM(pemPath string) ([]byte, error) {
	pemData, err := os.ReadFile(pemPath) // #nosec G304 -- path chosen by the caller (CLI flag or env var); contents strictly validated below
	if err != nil {
		return nil, fmt.Errorf("failed to read public key PEM file '%s': %w", pemPath, err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("invalid PEM file: missing 'PUBLIC KEY' block")
	}

	var spki SubjectPublicKeyInfo
	rest, err := asn1.Unmarshal(block.Bytes, &spki)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal SubjectPublicKeyInfo: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("invalid SubjectPublicKeyInfo: %d trailing bytes after DER structure", len(rest))
	}
	if len(spki.Algorithm.Parameters.FullBytes) != 0 {
		return nil, fmt.Errorf("invalid ML-KEM AlgorithmIdentifier: parameters must be absent")
	}

	rawKey := spki.PublicKey.Bytes
	if spki.PublicKey.BitLength != len(rawKey)*8 {
		return nil, fmt.Errorf("invalid public key BIT STRING: %d bits is not a whole number of bytes", spki.PublicKey.BitLength)
	}

	wantOID, name, ok := mlkemOIDForKeyLength(len(rawKey))
	if !ok {
		return nil, fmt.Errorf("unexpected public key length: %d bytes", len(rawKey))
	}
	if !spki.Algorithm.Algorithm.Equal(wantOID) {
		return nil, fmt.Errorf("algorithm OID %s does not match %d-byte %s key (expected %s)",
			spki.Algorithm.Algorithm, len(rawKey), name, wantOID)
	}

	return rawKey, nil
}

// FingerprintPrefix labels fingerprints printed by the CLI; it is optional on input.
const FingerprintPrefix = "SHA256:"

// PublicKeyFingerprint returns "SHA256:" followed by the lowercase hex SHA-256 of
// the key's canonical DER SubjectPublicKeyInfo. Hashing the canonical encoding
// (rather than the file bytes) makes the HSM key and its PEM export produce the
// same value, equal to:
//
//	openssl pkey -pubin -in key.pem -outform DER | openssl dgst -sha256
func PublicKeyFingerprint(rawKey []byte) (string, error) {
	der, _, err := marshalSPKI(rawKey)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return FingerprintPrefix + hex.EncodeToString(sum[:]), nil
}

// ParseFingerprint accepts a SHA-256 fingerprint as 64 hex digits, optionally
// prefixed with "SHA256:" (any case) and/or separated by colons, and returns the
// 32-byte digest.
func ParseFingerprint(s string) ([]byte, error) {
	v := strings.TrimSpace(s)
	if len(v) >= len(FingerprintPrefix) && strings.EqualFold(v[:len(FingerprintPrefix)], FingerprintPrefix) {
		v = v[len(FingerprintPrefix):]
	}
	v = strings.ReplaceAll(v, ":", "")
	digest, err := hex.DecodeString(v)
	if err != nil || len(digest) != sha256.Size {
		return nil, fmt.Errorf("invalid fingerprint %q: expected %d hex digits (optionally prefixed %q)", s, 2*sha256.Size, FingerprintPrefix)
	}
	return digest, nil
}

// CheckPublicKeyFingerprint returns the key's fingerprint, and an error if it
// differs from want (see ParseFingerprint for accepted forms).
func CheckPublicKeyFingerprint(rawKey []byte, want string) (string, error) {
	wantDigest, err := ParseFingerprint(want)
	if err != nil {
		return "", err
	}
	got, err := PublicKeyFingerprint(rawKey)
	if err != nil {
		return "", err
	}
	gotDigest, _ := ParseFingerprint(got)
	if !bytes.Equal(gotDigest, wantDigest) {
		return got, fmt.Errorf("public key fingerprint mismatch: got %s, expected %s%s",
			got, FingerprintPrefix, hex.EncodeToString(wantDigest))
	}
	return got, nil
}

// mlkemOIDForKeyLength maps an ML-KEM encapsulation key length to its NIST OID and name.
func mlkemOIDForKeyLength(n int) (asn1.ObjectIdentifier, string, bool) {
	switch n {
	case 800:
		return OIDMLKEM512, "ML-KEM-512", true
	case 1184:
		return OIDMLKEM768, "ML-KEM-768", true
	case 1568:
		return OIDMLKEM1024, "ML-KEM-1024", true
	default:
		return nil, "", false
	}
}

func ParseMLKEMAlgorithm(alg string) (uint, error) {
	switch strings.ToUpper(strings.TrimSpace(alg)) {
	case "ML-KEM-512":
		return CKP_ML_KEM_512, nil
	case "ML-KEM-768":
		return CKP_ML_KEM_768, nil
	case "ML-KEM-1024":
		return CKP_ML_KEM_1024, nil
	default:
		return 0, fmt.Errorf("unsupported algorithm: %s (supported: ML-KEM-512, ML-KEM-768, ML-KEM-1024)", alg)
	}
}

// marshalSPKI wraps a raw ML-KEM encapsulation key in a DER SubjectPublicKeyInfo.
func marshalSPKI(rawKey []byte) ([]byte, string, error) {
	algOID, algName, ok := mlkemOIDForKeyLength(len(rawKey))
	if !ok {
		return nil, "", fmt.Errorf("unexpected public key length: %d bytes (expected 800, 1184, or 1568)", len(rawKey))
	}

	spki := SubjectPublicKeyInfo{
		Algorithm: AlgorithmIdentifier{
			Algorithm: algOID,
		},
		PublicKey: asn1.BitString{
			Bytes:     rawKey,
			BitLength: len(rawKey) * 8,
		},
	}

	derBytes, err := asn1.Marshal(spki)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal ASN.1 SubjectPublicKeyInfo: %w", err)
	}
	return derBytes, algName, nil
}

func EncodeRawPublicKeyToPEM(rawKey []byte) ([]byte, string, error) {
	derBytes, algName, err := marshalSPKI(rawKey)
	if err != nil {
		return nil, "", err
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}

	return pem.EncodeToMemory(pemBlock), algName, nil
}
