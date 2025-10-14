package ecdsamp

import (
	"context"
	"errors"
	"runtime"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// Key represents a multi-party ECDSA key share.
//
// Memory Management:
// Keys must be explicitly freed by calling Close() when no longer needed.
// A finalizer is set as a safety net, but relying on it may cause resource leaks.
// Best practice: Always call Close() explicitly, preferably with defer.
//
// Example:
//
//	result, err := ecdsamp.DKG(ctx, job, &ecdsamp.DKGParams{Curve: cbmpc.CurveP256})
//	if err != nil {
//	    return err
//	}
//	defer result.Key.Close()
type Key struct {
	// ckey stores the C pointer as returned from bindings layer
	// The bindings layer uses *C.cbmpc_ecdsamp_key (aliased as backend.ECDSAMPKey)
	// The alias itself is a pointer type, so we store it directly (not as a pointer to it)
	ckey backend.ECDSAMPKey
}

// newKey creates a new Key from a C pointer and sets up a finalizer.
func newKey(ckey backend.ECDSAMPKey) *Key {
	k := &Key{ckey: ckey}
	runtime.SetFinalizer(k, func(key *Key) {
		_ = key.Close()
	})
	return k
}

// Close frees the underlying C++ key. After calling Close(), the key must not be used.
// It is safe to call Close() multiple times.
func (k *Key) Close() error {
	if k == nil || k.ckey == nil {
		return nil
	}
	backend.ECDSAMPKeyFree(k.ckey)
	k.ckey = nil
	runtime.SetFinalizer(k, nil)
	return nil
}

// Bytes returns the serialized key data for persistent storage or network transmission.
// Returns a defensive copy to prevent external modification of internal key data.
//
// SECURITY WARNING:
// The returned bytes contain sensitive cryptographic key material.
// - Call cbmpc.ZeroizeBytes on the returned slice after use to clear it from memory
// - Always encrypt key data before storing it at rest (e.g., using AES-GCM)
// - Never log or print key bytes
//
// Example:
//
//	keyBytes, err := key.Bytes()
//	if err != nil {
//	    return err
//	}
//	defer cbmpc.ZeroizeBytes(keyBytes) // Clear from memory when done
//
//	// Encrypt before storage
//	encrypted, err := encryptKey(keyBytes)
//	if err != nil {
//	    return err
//	}
//	// Store encrypted bytes...
func (k *Key) Bytes() ([]byte, error) {
	if k == nil || k.ckey == nil {
		return nil, errors.New("nil or closed key")
	}
	data, err := backend.ECDSAMPKeySerialize(k.ckey)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	// Return a defensive copy to prevent mutation of internal state
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

// LoadKey deserializes a key from bytes.
// The returned key must be freed with Close() when no longer needed.
func LoadKey(data []byte) (*Key, error) {
	ckey, err := backend.ECDSAMPKeyDeserialize(data)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	return newKey(ckey), nil
}

// PublicKey extracts the public key point Q from the key share.
// Returns the compressed EC point encoding.
// Returns a defensive copy to prevent external modification of internal key data.
func (k *Key) PublicKey() ([]byte, error) {
	if k == nil || k.ckey == nil {
		return nil, errors.New("nil or closed key")
	}
	pubKey, err := backend.ECDSAMPKeyGetPublicKey(k.ckey)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	// Return a defensive copy to prevent mutation of internal state
	result := make([]byte, len(pubKey))
	copy(result, pubKey)
	return result, nil
}

// Curve returns the elliptic curve used by this key.
func (k *Key) Curve() (cbmpc.Curve, error) {
	if k == nil || k.ckey == nil {
		return cbmpc.CurveUnknown, errors.New("nil or closed key")
	}
	curve, err := backend.ECDSAMPKeyGetCurve(k.ckey)
	if err != nil {
		return cbmpc.CurveUnknown, cbmpc.RemapError(err)
	}
	return cbmpc.Curve(curve), nil
}

// DKGParams contains parameters for multi-party ECDSA distributed key generation.
type DKGParams struct {
	Curve cbmpc.Curve
}

// DKGResult contains the output of multi-party ECDSA distributed key generation.
type DKGResult struct {
	Key       *Key
	SessionID cbmpc.SessionID
}

// DKG performs multi-party ECDSA distributed key generation.
// The returned key must be freed with Close() when no longer needed.
//
// Context behavior: ctx is ignored; use cbmpc.NewJobMPWithContext to control cancellation.
//
// See cb-mpc/src/cbmpc/protocol/ecdsa_mp.h for protocol details.
func DKG(_ context.Context, j *cbmpc.JobMP, params *DKGParams) (*DKGResult, error) {
	if j == nil {
		return nil, errors.New("nil job")
	}
	if params == nil {
		return nil, errors.New("nil params")
	}

	ptr, err := j.Ptr()
	if err != nil {
		return nil, err
	}

	nid, err := backend.CurveToNID(backend.Curve(params.Curve))
	if err != nil {
		return nil, err
	}

	keyPtr, sid, err := backend.ECDSAMP_DKG(ptr, nid)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	runtime.KeepAlive(j)

	return &DKGResult{
		Key:       newKey(keyPtr),
		SessionID: cbmpc.NewSessionID(sid),
	}, nil
}

// RefreshParams contains parameters for multi-party ECDSA key refresh.
type RefreshParams struct {
	SessionID cbmpc.SessionID
	Key       *Key
}

// RefreshResult contains the output of multi-party ECDSA key refresh.
type RefreshResult struct {
	NewKey    *Key
	SessionID cbmpc.SessionID
}

// Refresh performs multi-party ECDSA key refresh.
// The returned key must be freed with Close() when no longer needed.
// The input key is not modified and remains valid.
//
// Session ID behavior:
// - If params.SessionID is empty, a new session ID will be generated
// - If params.SessionID is provided, it will be used and updated
// - The updated/generated session ID is returned in RefreshResult.SessionID
//
// Context behavior: ctx is ignored; use cbmpc.NewJobMPWithContext to control cancellation.
//
// See cb-mpc/src/cbmpc/protocol/ecdsa_mp.h for protocol details.
func Refresh(_ context.Context, j *cbmpc.JobMP, params *RefreshParams) (*RefreshResult, error) {
	if j == nil {
		return nil, errors.New("nil job")
	}
	if params == nil {
		return nil, errors.New("nil params")
	}
	if params.Key == nil || params.Key.ckey == nil {
		return nil, errors.New("nil or closed key")
	}

	ptr, err := j.Ptr()
	if err != nil {
		return nil, err
	}

	newKeyCkey, newSid, err := backend.ECDSAMPRefresh(ptr, params.Key.ckey, params.SessionID.Bytes())
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	runtime.KeepAlive(j)
	runtime.KeepAlive(params.Key)

	return &RefreshResult{
		NewKey:    newKey(newKeyCkey),
		SessionID: cbmpc.NewSessionID(newSid),
	}, nil
}

// SignParams contains parameters for multi-party ECDSA signing.
type SignParams struct {
	Key         *Key   // Key share to sign with
	Message     []byte // Message hash to sign (must be pre-hashed, max size = curve order size)
	SigReceiver int    // Party index that will receive the final signature (0-based)
}

// SignResult contains the output of multi-party ECDSA signing.
type SignResult struct {
	Signature []byte // ECDSA signature (empty for non-receiver parties)
}

// Sign performs multi-party ECDSA signing.
//
// The message must be the hash of the actual message to sign.
// The input key is not modified and remains valid.
//
// Only the party with index matching SigReceiver will receive a non-empty signature.
// All other parties will receive an empty signature.
//
// Context behavior: ctx is ignored; use cbmpc.NewJobMPWithContext to control cancellation.
//
// See cb-mpc/src/cbmpc/protocol/ecdsa_mp.h for protocol details.
func Sign(_ context.Context, j *cbmpc.JobMP, params *SignParams) (*SignResult, error) {
	if j == nil {
		return nil, errors.New("nil job")
	}
	if params == nil {
		return nil, errors.New("nil params")
	}
	if params.Key == nil || params.Key.ckey == nil {
		return nil, errors.New("nil or closed key")
	}
	if len(params.Message) == 0 {
		return nil, errors.New("empty message hash")
	}

	// Validate message hash size
	curve, err := params.Key.Curve()
	if err != nil {
		return nil, err
	}
	maxSize := curve.MaxHashSize()
	if maxSize > 0 && len(params.Message) > maxSize {
		return nil, errors.New("message hash exceeds curve order size")
	}

	ptr, err := j.Ptr()
	if err != nil {
		return nil, err
	}

	sig, err := backend.ECDSAMPSign(ptr, params.Key.ckey, params.Message, params.SigReceiver)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	runtime.KeepAlive(j)
	runtime.KeepAlive(params.Key)

	return &SignResult{
		Signature: sig,
	}, nil
}
