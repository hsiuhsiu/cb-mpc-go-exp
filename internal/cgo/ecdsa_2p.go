package cgo

/*
#include "ecdsa_2p.h"
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// Helper to create C session with callbacks
func createCSession(sessionPtr unsafe.Pointer, session Session) (*C.session_t, error) {
	cSession := (*C.session_t)(C.malloc(C.size_t(unsafe.Sizeof(C.session_t{}))))
	if cSession == nil {
		return nil, fmt.Errorf("failed to allocate session")
	}

	cSession.session_data = sessionPtr
	cSession.my_index = C.int(session.MyIndex())
	cSession.party_count = C.int(session.PartyCount())

	// Allocate callbacks in C memory
	cSession.data_transport_callbacks = (*C.data_transport_callbacks_t)(C.malloc(C.size_t(unsafe.Sizeof(callbacks))))
	if cSession.data_transport_callbacks == nil {
		C.free(unsafe.Pointer(cSession))
		return nil, fmt.Errorf("failed to allocate callbacks")
	}

	// Copy the callbacks structure
	*cSession.data_transport_callbacks = callbacks

	return cSession, nil
}

func freeCSession(cSession *C.session_t) {
	if cSession != nil {
		if cSession.data_transport_callbacks != nil {
			C.free(unsafe.Pointer(cSession.data_transport_callbacks))
		}
		C.free(unsafe.Pointer(cSession))
	}
}

// ECDSA2PKey represents a 2-party ECDSA key share
type ECDSA2PKey struct {
	cKey    C.ecdsa_2p_key_t
	session unsafe.Pointer
}

// ECDSA2PKeyGen performs distributed key generation for 2-party ECDSA
func ECDSA2PKeyGen(session Session, curveCode int) (*ECDSA2PKey, error) {
	if session == nil {
		return nil, fmt.Errorf("session cannot be nil")
	}

	// Create session pointer
	sessionPtr, err := setSession(session)
	if err != nil {
		return nil, fmt.Errorf("failed to set session: %v", err)
	}

	// Create C session
	cSession, err := createCSession(sessionPtr, session)
	if err != nil {
		freeSession(sessionPtr)
		return nil, err
	}
	defer freeCSession(cSession)

	var cKey C.ecdsa_2p_key_t
	result := C.ecdsa_2p_keygen(cSession, C.int(curveCode), &cKey)
	if result != 0 {
		freeSession(sessionPtr)
		return nil, fmt.Errorf("ECDSA 2P keygen failed with code %d", result)
	}

	return &ECDSA2PKey{
		cKey:    cKey,
		session: sessionPtr,
	}, nil
}

// Sign creates an ECDSA signature using the 2-party protocol
func (k *ECDSA2PKey) Sign(session Session, messageHash []byte) ([]byte, error) {
	if session == nil {
		return nil, fmt.Errorf("session cannot be nil")
	}
	if len(messageHash) == 0 {
		return nil, fmt.Errorf("message hash cannot be empty")
	}

	// Create session pointer
	sessionPtr, err := setSession(session)
	if err != nil {
		return nil, fmt.Errorf("failed to set session: %v", err)
	}
	defer freeSession(sessionPtr)

	// Create C session
	cSession, err := createCSession(sessionPtr, session)
	if err != nil {
		freeSession(sessionPtr)
		return nil, err
	}
	defer freeCSession(cSession)

	var signature *C.uint8_t
	var sigLen C.size_t

	result := C.ecdsa_2p_sign(cSession, &k.cKey, (*C.uint8_t)(&messageHash[0]), C.size_t(len(messageHash)), &signature, &sigLen)
	if result != 0 {
		return nil, fmt.Errorf("ECDSA 2P sign failed with code %d", result)
	}

	// Convert C buffer to Go slice
	goSig := C.GoBytes(unsafe.Pointer(signature), C.int(sigLen))
	C.ecdsa_2p_free_buffer(signature)

	return goSig, nil
}

// Refresh generates a new key share from an existing one
func (k *ECDSA2PKey) Refresh(session Session) (*ECDSA2PKey, error) {
	if session == nil {
		return nil, fmt.Errorf("session cannot be nil")
	}

	// Create session pointer
	sessionPtr, err := setSession(session)
	if err != nil {
		return nil, fmt.Errorf("failed to set session: %v", err)
	}

	// Create C session
	cSession, err := createCSession(sessionPtr, session)
	if err != nil {
		freeSession(sessionPtr)
		return nil, err
	}
	defer freeCSession(cSession)

	var newCKey C.ecdsa_2p_key_t
	result := C.ecdsa_2p_refresh(cSession, &k.cKey, &newCKey)
	if result != 0 {
		freeSession(sessionPtr)
		return nil, fmt.Errorf("ECDSA 2P refresh failed with code %d", result)
	}

	return &ECDSA2PKey{
		cKey:    newCKey,
		session: sessionPtr,
	}, nil
}

// GetRole returns the party role (0 or 1)
func (k *ECDSA2PKey) GetRole() int {
	return int(C.ecdsa_2p_key_get_role(&k.cKey))
}

// GetCurveCode returns the OpenSSL NID for the curve
func (k *ECDSA2PKey) GetCurveCode() int {
	return int(C.ecdsa_2p_key_get_curve_code(&k.cKey))
}

// GetPublicKey returns the full public key (point Q)
func (k *ECDSA2PKey) GetPublicKey() ([]byte, error) {
	var pubkey *C.uint8_t
	var pubkeyLen C.size_t

	result := C.ecdsa_2p_key_get_public_key(&k.cKey, &pubkey, &pubkeyLen)
	if result != 0 {
		return nil, fmt.Errorf("failed to get public key with code %d", result)
	}

	// Convert C buffer to Go slice
	goPubkey := C.GoBytes(unsafe.Pointer(pubkey), C.int(pubkeyLen))
	C.ecdsa_2p_free_buffer(pubkey)

	return goPubkey, nil
}

// GetPrivateShare returns this party's private key share
func (k *ECDSA2PKey) GetPrivateShare() ([]byte, error) {
	var share *C.uint8_t
	var shareLen C.size_t

	result := C.ecdsa_2p_key_get_private_share(&k.cKey, &share, &shareLen)
	if result != 0 {
		return nil, fmt.Errorf("failed to get private share with code %d", result)
	}

	// Convert C buffer to Go slice
	goShare := C.GoBytes(unsafe.Pointer(share), C.int(shareLen))
	C.ecdsa_2p_free_buffer(share)

	return goShare, nil
}

// Close releases the key resources
func (k *ECDSA2PKey) Close() error {
	if k.session != nil {
		if err := freeSession(k.session); err != nil {
			return err
		}
		k.session = nil
	}
	C.ecdsa_2p_key_free(&k.cKey)
	return nil
}