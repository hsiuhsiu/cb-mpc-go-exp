package cbmpc

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/coinbase/cb-mpc-go/internal/bindings"
)

// ECDSA2PKey represents a 2-party ECDSA key share.
//
// Memory Management:
// Keys must be explicitly freed by calling Close() when no longer needed.
// A finalizer is set as a safety net, but relying on it may cause resource leaks.
// Best practice: Always call Close() explicitly, preferably with defer.
//
// Example:
//
//	result, err := cbmpc.DKG(ctx, job, &cbmpc.DKGParams{Curve: cbmpc.CurveP256})
//	if err != nil {
//	    return err
//	}
//	defer result.Key.Close()
type ECDSA2PKey struct {
	ptr unsafe.Pointer
}

// newECDSA2PKey creates a new ECDSA2PKey from a C pointer and sets up a finalizer.
func newECDSA2PKey(ptr unsafe.Pointer) *ECDSA2PKey {
	k := &ECDSA2PKey{ptr: ptr}
	runtime.SetFinalizer(k, func(key *ECDSA2PKey) {
		_ = key.Close()
	})
	return k
}

// Close frees the underlying C++ key. After calling Close(), the key must not be used.
// It is safe to call Close() multiple times.
func (k *ECDSA2PKey) Close() error {
	if k == nil || k.ptr == nil {
		return nil
	}
	bindings.ECDSA2PKeyFree(k.ptr)
	k.ptr = nil
	runtime.SetFinalizer(k, nil)
	return nil
}

// Bytes returns the serialized key data for persistent storage or network transmission.
func (k *ECDSA2PKey) Bytes() ([]byte, error) {
	if k == nil || k.ptr == nil {
		return nil, errors.New("nil or closed key")
	}
	data, err := bindings.ECDSA2PKeySerialize(k.ptr)
	if err != nil {
		return nil, remapError(err)
	}
	return data, nil
}

// LoadECDSA2PKey deserializes a key from bytes.
// The returned key must be freed with Close() when no longer needed.
func LoadECDSA2PKey(data []byte) (*ECDSA2PKey, error) {
	ptr, err := bindings.ECDSA2PKeyDeserialize(data)
	if err != nil {
		return nil, remapError(err)
	}
	return newECDSA2PKey(ptr), nil
}

// PublicKey extracts the public key point Q from the key share.
// Returns the compressed EC point encoding.
func (k *ECDSA2PKey) PublicKey() ([]byte, error) {
	if k == nil || k.ptr == nil {
		return nil, errors.New("nil or closed key")
	}
	pubKey, err := bindings.ECDSA2PKeyGetPublicKey(k.ptr)
	if err != nil {
		return nil, remapError(err)
	}
	return pubKey, nil
}

// Curve returns the elliptic curve used by this key.
func (k *ECDSA2PKey) Curve() (Curve, error) {
	if k == nil || k.ptr == nil {
		return Curve{}, errors.New("nil or closed key")
	}
	nid, err := bindings.ECDSA2PKeyGetCurveNID(k.ptr)
	if err != nil {
		return Curve{}, remapError(err)
	}
	return Curve{nid: nid}, nil
}

// DKGParams contains parameters for 2-party ECDSA distributed key generation.
type DKGParams struct {
	Curve Curve
}

// DKGResult contains the output of 2-party ECDSA distributed key generation.
type DKGResult struct {
	Key *ECDSA2PKey
}

// DKG performs 2-party ECDSA distributed key generation.
// The returned key must be freed with Close() when no longer needed.
// See cb-mpc/src/cbmpc/protocol/ecdsa_2p.h for protocol details.
func DKG(_ context.Context, j *Job2P, params *DKGParams) (*DKGResult, error) {
	if j == nil {
		return nil, errors.New("nil job")
	}
	if params == nil {
		return nil, errors.New("nil params")
	}

	ptr, err := j.ptr()
	if err != nil {
		return nil, err
	}

	keyPtr, err := bindings.ECDSA2PDKG(ptr, params.Curve.nid)
	if err != nil {
		return nil, remapError(err)
	}
	runtime.KeepAlive(j)

	return &DKGResult{
		Key: newECDSA2PKey(keyPtr),
	}, nil
}

// RefreshParams contains parameters for 2-party ECDSA key refresh.
type RefreshParams struct {
	Key *ECDSA2PKey
}

// RefreshResult contains the output of 2-party ECDSA key refresh.
type RefreshResult struct {
	NewKey *ECDSA2PKey
}

// Refresh performs 2-party ECDSA key refresh.
// The returned key must be freed with Close() when no longer needed.
// The input key is not modified and remains valid.
// See cb-mpc/src/cbmpc/protocol/ecdsa_2p.h for protocol details.
func Refresh(_ context.Context, j *Job2P, params *RefreshParams) (*RefreshResult, error) {
	if j == nil {
		return nil, errors.New("nil job")
	}
	if params == nil {
		return nil, errors.New("nil params")
	}
	if params.Key == nil || params.Key.ptr == nil {
		return nil, errors.New("nil or closed key")
	}

	ptr, err := j.ptr()
	if err != nil {
		return nil, err
	}

	newKeyPtr, err := bindings.ECDSA2PRefresh(ptr, params.Key.ptr)
	if err != nil {
		return nil, remapError(err)
	}
	runtime.KeepAlive(j)
	runtime.KeepAlive(params.Key)

	return &RefreshResult{
		NewKey: newECDSA2PKey(newKeyPtr),
	}, nil
}

// SignParams contains parameters for 2-party ECDSA signing.
type SignParams struct {
	SessionID []byte      // Session ID (in/out parameter)
	Key       *ECDSA2PKey // Key share to sign with
	Message   []byte      // Message hash to sign (must be pre-hashed, max size = curve order size)
}

// SignResult contains the output of 2-party ECDSA signing.
type SignResult struct {
	SessionID []byte // Updated session ID
	Signature []byte // ECDSA signature
}

// Sign performs 2-party ECDSA signing.
// The message must be the hash of the actual message to sign.
// The input key is not modified and remains valid.
// See cb-mpc/src/cbmpc/protocol/ecdsa_2p.h for protocol details.
func Sign(_ context.Context, j *Job2P, params *SignParams) (*SignResult, error) {
	if j == nil {
		return nil, errors.New("nil job")
	}
	if params == nil {
		return nil, errors.New("nil params")
	}
	if params.Key == nil || params.Key.ptr == nil {
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

	ptr, err := j.ptr()
	if err != nil {
		return nil, err
	}

	newSID, sig, err := bindings.ECDSA2PSign(ptr, params.Key.ptr, params.SessionID, params.Message)
	if err != nil {
		return nil, remapError(err)
	}
	runtime.KeepAlive(j)
	runtime.KeepAlive(params.Key)

	return &SignResult{
		SessionID: newSID,
		Signature: sig,
	}, nil
}

// SignBatchParams contains parameters for 2-party ECDSA batch signing.
type SignBatchParams struct {
	SessionID []byte      // Session ID (in/out parameter)
	Key       *ECDSA2PKey // Key share to sign with
	Messages  [][]byte    // Message hashes to sign (must be pre-hashed, max size = curve order size)
}

// SignBatchResult contains the output of 2-party ECDSA batch signing.
type SignBatchResult struct {
	SessionID  []byte   // Updated session ID
	Signatures [][]byte // ECDSA signatures (one per message)
}

// SignBatch performs 2-party ECDSA batch signing.
// See cb-mpc/src/cbmpc/protocol/ecdsa_2p.h for protocol details.
func SignBatch(_ context.Context, j *Job2P, params *SignBatchParams) (*SignBatchResult, error) {
	if j == nil {
		return nil, errors.New("nil job")
	}
	if params == nil {
		return nil, errors.New("nil params")
	}
	if params.Key == nil || params.Key.ptr == nil {
		return nil, errors.New("nil or closed key")
	}
	if len(params.Messages) == 0 {
		return nil, errors.New("empty messages")
	}

	// Validate all message hash sizes
	curve, err := params.Key.Curve()
	if err != nil {
		return nil, err
	}
	maxSize := curve.MaxHashSize()
	if maxSize > 0 {
		for i, msg := range params.Messages {
			if len(msg) == 0 {
				return nil, fmt.Errorf("empty message hash at index %d", i)
			}
			if len(msg) > maxSize {
				return nil, fmt.Errorf("message hash exceeds curve order size at index %d", i)
			}
		}
	}

	ptr, err := j.ptr()
	if err != nil {
		return nil, err
	}

	newSID, sigs, err := bindings.ECDSA2PSignBatch(ptr, params.Key.ptr, params.SessionID, params.Messages)
	if err != nil {
		return nil, remapError(err)
	}
	runtime.KeepAlive(j)
	runtime.KeepAlive(params.Key)

	return &SignBatchResult{
		SessionID:  newSID,
		Signatures: sigs,
	}, nil
}

// SignWithGlobalAbort performs 2-party ECDSA signing with global abort mode.
// Returns ErrBitLeak if signature verification fails (indicates potential key leak).
// See cb-mpc/src/cbmpc/protocol/ecdsa_2p.h for protocol details.
func SignWithGlobalAbort(_ context.Context, j *Job2P, params *SignParams) (*SignResult, error) {
	if j == nil {
		return nil, errors.New("nil job")
	}
	if params == nil {
		return nil, errors.New("nil params")
	}
	if params.Key == nil || params.Key.ptr == nil {
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

	ptr, err := j.ptr()
	if err != nil {
		return nil, err
	}

	newSID, sig, err := bindings.ECDSA2PSignWithGlobalAbort(ptr, params.Key.ptr, params.SessionID, params.Message)
	if err != nil {
		return nil, remapError(err)
	}
	runtime.KeepAlive(j)
	runtime.KeepAlive(params.Key)

	return &SignResult{
		SessionID: newSID,
		Signature: sig,
	}, nil
}

// SignWithGlobalAbortBatch performs 2-party ECDSA batch signing with global abort mode.
// Returns ErrBitLeak if signature verification fails (indicates potential key leak).
// See cb-mpc/src/cbmpc/protocol/ecdsa_2p.h for protocol details.
func SignWithGlobalAbortBatch(_ context.Context, j *Job2P, params *SignBatchParams) (*SignBatchResult, error) {
	if j == nil {
		return nil, errors.New("nil job")
	}
	if params == nil {
		return nil, errors.New("nil params")
	}
	if params.Key == nil || params.Key.ptr == nil {
		return nil, errors.New("nil or closed key")
	}
	if len(params.Messages) == 0 {
		return nil, errors.New("empty messages")
	}

	// Validate all message hash sizes
	curve, err := params.Key.Curve()
	if err != nil {
		return nil, err
	}
	maxSize := curve.MaxHashSize()
	if maxSize > 0 {
		for i, msg := range params.Messages {
			if len(msg) == 0 {
				return nil, fmt.Errorf("empty message hash at index %d", i)
			}
			if len(msg) > maxSize {
				return nil, fmt.Errorf("message hash exceeds curve order size at index %d", i)
			}
		}
	}

	ptr, err := j.ptr()
	if err != nil {
		return nil, err
	}

	newSID, sigs, err := bindings.ECDSA2PSignWithGlobalAbortBatch(ptr, params.Key.ptr, params.SessionID, params.Messages)
	if err != nil {
		return nil, remapError(err)
	}
	runtime.KeepAlive(j)
	runtime.KeepAlive(params.Key)

	return &SignBatchResult{
		SessionID:  newSID,
		Signatures: sigs,
	}, nil
}
