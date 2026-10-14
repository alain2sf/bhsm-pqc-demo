// Package pkcs11v3 provides an isolated CGO bridge for PKCS#11 v3.2 features
// (such as C_DecapsulateKey) that are not yet available in standard Go wrappers.
package pkcs11v3

/*
#cgo !darwin LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>
#include <stdint.h>

typedef unsigned long CK_RV;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_OBJECT_HANDLE;
typedef unsigned long CK_ULONG;
typedef unsigned char CK_BYTE;

typedef struct {
    unsigned long mechanism;
    void *pParameter;
    unsigned long ulParameterLen;
} CK_MECHANISM;

typedef struct {
    unsigned long attrType;
    void *pValue;
    unsigned long ulValueLen;
} CK_ATTRIBUTE;

typedef CK_RV (*CK_C_DecapsulateKey)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM *pMechanism,
    CK_OBJECT_HANDLE hPrivateKey,
    CK_ATTRIBUTE *pTemplate,
    CK_ULONG ulAttributeCount,
    CK_BYTE *pCiphertext,
    CK_ULONG ulCiphertextLen,
    CK_OBJECT_HANDLE *phKey
);

// call_C_DecapsulateKey builds all attribute structures strictly in C memory.
static CK_RV call_C_DecapsulateKey(
    void *dlHandle,
    CK_SESSION_HANDLE hSession,
    unsigned long mechanismType,
    CK_OBJECT_HANDLE hPrivateKey,
    unsigned char *pCiphertext,
    CK_ULONG ulCiphertextLen,
    CK_OBJECT_HANDLE *phKey
) {
    if (!dlHandle) {
        return 0x00000006; // CKR_FUNCTION_FAILED
    }
    CK_C_DecapsulateKey fn = (CK_C_DecapsulateKey)dlsym(dlHandle, "C_DecapsulateKey");
    if (!fn) {
        return 0x00000054; // CKR_FUNCTION_NOT_SUPPORTED
    }

    CK_MECHANISM mech;
    mech.mechanism = mechanismType;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    // Allocate PKCS#11 attributes on C call stack
    CK_ULONG cClass = 4;        // CKO_SECRET_KEY
    CK_ULONG cKeyType = 0x10;   // CKK_GENERIC_SECRET
    CK_BYTE cToken = 0;         // false (Session Key)
    CK_BYTE cExtract = 1;       // true
    CK_BYTE cSensitive = 0;     // false
    CK_ULONG cValueLen = 32;    // 32-byte shared secret

    CK_ATTRIBUTE tmpl[6];
    tmpl[0].attrType = 0x00000000; // CKA_CLASS
    tmpl[0].pValue = &cClass;
    tmpl[0].ulValueLen = sizeof(cClass);

    tmpl[1].attrType = 0x00000100; // CKA_KEY_TYPE
    tmpl[1].pValue = &cKeyType;
    tmpl[1].ulValueLen = sizeof(cKeyType);

    tmpl[2].attrType = 0x00000001; // CKA_TOKEN
    tmpl[2].pValue = &cToken;
    tmpl[2].ulValueLen = sizeof(cToken);

    tmpl[3].attrType = 0x00000162; // CKA_EXTRACTABLE
    tmpl[3].pValue = &cExtract;
    tmpl[3].ulValueLen = sizeof(cExtract);

    tmpl[4].attrType = 0x00000103; // CKA_SENSITIVE
    tmpl[4].pValue = &cSensitive;
    tmpl[4].ulValueLen = sizeof(cSensitive);

    tmpl[5].attrType = 0x00000161; // CKA_VALUE_LEN
    tmpl[5].pValue = &cValueLen;
    tmpl[5].ulValueLen = sizeof(cValueLen);

    return fn(hSession, &mech, hPrivateKey, tmpl, 6, pCiphertext, ulCiphertextLen, phKey);
}
*/
import "C"

import (
	"fmt"
	"strings"
	"unsafe"
)

// Driver manages low-level dynamic library symbol dispatching.
type Driver struct {
	dlHandle unsafe.Pointer
}

// Open loads the dynamic library using dlopen.
func Open(libPath string) (*Driver, error) {
	if strings.TrimSpace(libPath) == "" {
		return nil, fmt.Errorf("PKCS#11 library path cannot be empty")
	}

	cPath := C.CString(libPath)
	defer C.free(unsafe.Pointer(cPath))

	dlHandle := C.dlopen(cPath, C.RTLD_NOW|C.RTLD_GLOBAL)
	if dlHandle == nil {
		return nil, fmt.Errorf("failed to dlopen PKCS#11 module: %s", libPath)
	}

	return &Driver{dlHandle: dlHandle}, nil
}

// Close releases the dynamic library handle.
func (d *Driver) Close() {
	if d.dlHandle != nil {
		C.dlclose(d.dlHandle)
		d.dlHandle = nil
	}
}

// DecapsulateKey invokes the native PKCS#11 v3.2 C_DecapsulateKey function on the HSM.
func (d *Driver) DecapsulateKey(session uint, mechanism uint, privKeyHandle uint, ciphertext []byte) (uint, error) {
	if len(ciphertext) == 0 {
		return 0, fmt.Errorf("ciphertext buffer cannot be empty")
	}

	var derivedKeyHandle C.CK_OBJECT_HANDLE

	rv := C.call_C_DecapsulateKey(
		d.dlHandle,
		C.CK_SESSION_HANDLE(session),
		C.ulong(mechanism),
		C.CK_OBJECT_HANDLE(privKeyHandle),
		(*C.uchar)(unsafe.Pointer(&ciphertext[0])),
		C.CK_ULONG(len(ciphertext)),
		&derivedKeyHandle,
	)

	if rv != 0 {
		return 0, fmt.Errorf("C_DecapsulateKey failed with PKCS#11 return code: 0x%X", uint(rv))
	}

	return uint(derivedKeyHandle), nil
}
