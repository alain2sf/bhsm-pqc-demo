// Package hsm provides high-level abstractions over the OASIS PKCS#11 standard
// interface for Bouncy HSM and Post-Quantum Cryptography (PQC) operations.
package hsm

import (
	"crypto/mlkem"
	"encoding/asn1"
	"encoding/pem"
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

// DeleteObjectsByLabel searches for, logs CKA_UNIQUE_ID, and deletes all existing
// objects matching the specified label on the active token.
func (c *Client) DeleteObjectsByLabel(session pkcs11.SessionHandle, objectLabel string) error {
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
		template := []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, cls.id),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, objectLabel),
		}

		if err := c.ctx.FindObjectsInit(session, template); err != nil {
			return fmt.Errorf("FindObjectsInit failed for %s: %w", cls.name, err)
		}

		for {
			objs, _, err := c.ctx.FindObjects(session, 50)
			if err != nil {
				_ = c.ctx.FindObjectsFinal(session)
				return fmt.Errorf("FindObjects failed for %s: %w", cls.name, err)
			}
			if len(objs) == 0 {
				break
			}

			for _, obj := range objs {
				// Query CKA_UNIQUE_ID before destroying the object
				uniqueID := c.GetUniqueID(session, obj)

				if err := c.ctx.DestroyObject(session, obj); err != nil {
					_ = c.ctx.FindObjectsFinal(session)
					return fmt.Errorf("failed to destroy %s (handle %d): %w", cls.name, obj, err)
				}

				deletedLog = append(deletedLog, fmt.Sprintf("    -> Deleted %-11s (Handle: %d, CKA_UNIQUE_ID: %s)", cls.name, obj, uniqueID))
			}
		}

		if err := c.ctx.FindObjectsFinal(session); err != nil {
			return fmt.Errorf("FindObjectsFinal failed for %s: %w", cls.name, err)
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

func (c *Client) GenerateMLKEMKeyPair(tokenLabel, objectLabel, pinFilePath, algorithm string) error {
	paramSet, err := ParseMLKEMAlgorithm(algorithm)
	if err != nil {
		return err
	}

	pinBytes, err := os.ReadFile(pinFilePath)
	if err != nil {
		return fmt.Errorf("could not read PIN file '%s': %w", pinFilePath, err)
	}
	pin := strings.TrimRight(string(pinBytes), "\r\n")

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

	// Clean up any existing keys matching the label before generating new ones
	if err := c.DeleteObjectsByLabel(session, objectLabel); err != nil {
		return fmt.Errorf("pre-generation cleanup failed: %w", err)
	}

	fmt.Printf("[*] Generating %s key pair (Object Label: '%s')...\n", algorithm, objectLabel)

	mech := []*pkcs11.Mechanism{
		pkcs11.NewMechanism(CKM_ML_KEM_KEY_PAIR_GEN, nil),
	}

	pubTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, objectLabel),
		pkcs11.NewAttribute(CKA_PARAMETER_SET, paramSet),
		pkcs11.NewAttribute(CKA_ENCAPSULATE, true),
	}

	privTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, objectLabel),
		pkcs11.NewAttribute(CKA_PARAMETER_SET, paramSet),
		pkcs11.NewAttribute(CKA_DECAPSULATE, true),
	}

	pubHandle, privHandle, err := c.ctx.GenerateKeyPair(session, mech, pubTemplate, privTemplate)
	if err != nil {
		return fmt.Errorf("C_GenerateKeyPair failed: %w", err)
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

func (c *Client) FetchRawPublicKey(tokenLabel, objectLabel string) ([]byte, error) {
	slotID, err := c.FindSlotByTokenLabel(tokenLabel)
	if err != nil {
		return nil, err
	}

	session, err := c.ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, fmt.Errorf("failed to open public session on slot %d: %w", slotID, err)
	}
	defer c.ctx.CloseSession(session)

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, objectLabel),
	}

	if err := c.ctx.FindObjectsInit(session, template); err != nil {
		return nil, fmt.Errorf("C_FindObjectsInit failed: %w", err)
	}

	objs, _, err := c.ctx.FindObjects(session, 1)
	if err != nil {
		_ = c.ctx.FindObjectsFinal(session)
		return nil, fmt.Errorf("C_FindObjects failed: %w", err)
	}
	_ = c.ctx.FindObjectsFinal(session)

	if len(objs) == 0 {
		return nil, fmt.Errorf("public key '%s' not found on token '%s'", objectLabel, tokenLabel)
	}

	attrTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	}
	attrs, err := c.ctx.GetAttributeValue(session, objs[0], attrTemplate)
	if err != nil || len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return nil, fmt.Errorf("failed to read public key CKA_VALUE: %w", err)
	}

	return attrs[0].Value, nil
}

func (c *Client) ExportPublicKeyPEM(tokenLabel, objectLabel, outputPath string) error {
	rawPubKey, err := c.FetchRawPublicKey(tokenLabel, objectLabel)
	if err != nil {
		return err
	}

	pemBytes, algName, err := EncodeRawPublicKeyToPEM(rawPubKey)
	if err != nil {
		return err
	}
	fmt.Printf("[*] Extracted %s raw public key (%d bytes)\n", algName, len(rawPubKey))

	if err := os.WriteFile(outputPath, pemBytes, 0644); err != nil {
		return fmt.Errorf("failed to write PEM output to '%s': %w", outputPath, err)
	}

	fmt.Printf("[+] Public key successfully exported to: %s\n", outputPath)
	return nil
}

func (c *Client) Decapsulate(tokenLabel, objectLabel, pinFilePath string, ciphertext []byte) ([]byte, error) {
	pinBytes, err := os.ReadFile(pinFilePath)
	if err != nil {
		return nil, fmt.Errorf("could not read PIN file '%s': %w", pinFilePath, err)
	}
	pin := strings.TrimRight(string(pinBytes), "\r\n")

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

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, objectLabel),
	}

	if err := c.ctx.FindObjectsInit(session, template); err != nil {
		return nil, fmt.Errorf("C_FindObjectsInit failed: %w", err)
	}

	objs, _, err := c.ctx.FindObjects(session, 1)
	if err != nil {
		_ = c.ctx.FindObjectsFinal(session)
		return nil, fmt.Errorf("C_FindObjects failed: %w", err)
	}
	_ = c.ctx.FindObjectsFinal(session)

	if len(objs) == 0 {
		return nil, fmt.Errorf("private key '%s' not found on token '%s'", objectLabel, tokenLabel)
	}
	privHandle := objs[0]
	privUniqueID := c.GetUniqueID(session, privHandle)
	fmt.Printf("[*] Located private key object handle: %d (0x%X, CKA_UNIQUE_ID: %s)\n", privHandle, privHandle, privUniqueID)

	derivedKeyHandle, err := c.v3.DecapsulateKey(uint(session), CKM_ML_KEM, uint(privHandle), ciphertext)
	if err != nil {
		return nil, fmt.Errorf("HSM C_DecapsulateKey failed: %w", err)
	}
	defer c.ctx.DestroyObject(session, pkcs11.ObjectHandle(derivedKeyHandle))

	valAttrs, err := c.ctx.GetAttributeValue(session, pkcs11.ObjectHandle(derivedKeyHandle), []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	if err != nil || len(valAttrs) == 0 || len(valAttrs[0].Value) == 0 {
		return nil, fmt.Errorf("failed to read derived shared secret CKA_VALUE: %w", err)
	}

	fmt.Printf("[+] HSM Decapsulation completed natively on server!\n")
	return valAttrs[0].Value, nil
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

func EncapsulateFromPEM(pemPath string) (ciphertext []byte, sharedSecret []byte, algName string, err error) {
	pemData, err := os.ReadFile(pemPath)
	if err != nil {
		return nil, nil, "", fmt.Errorf("failed to read public key PEM file '%s': %w", pemPath, err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, nil, "", fmt.Errorf("invalid PEM file: missing 'PUBLIC KEY' block")
	}

	var spki SubjectPublicKeyInfo
	if _, err := asn1.Unmarshal(block.Bytes, &spki); err != nil {
		return nil, nil, "", fmt.Errorf("failed to unmarshal SubjectPublicKeyInfo: %w", err)
	}

	return EncapsulateFromRawKey(spki.PublicKey.Bytes)
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

func EncodeRawPublicKeyToPEM(rawKey []byte) ([]byte, string, error) {
	var algOID asn1.ObjectIdentifier
	var algName string

	switch len(rawKey) {
	case 800:
		algOID = OIDMLKEM512
		algName = "ML-KEM-512"
	case 1184:
		algOID = OIDMLKEM768
		algName = "ML-KEM-768"
	case 1568:
		algOID = OIDMLKEM1024
		algName = "ML-KEM-1024"
	default:
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

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}

	return pem.EncodeToMemory(pemBlock), algName, nil
}
