package ecdsa2p

import (
	"context"
	"errors"
	"fmt"
	"runtime"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// Key represents a 2-party ECDSA key share.
//
// Memory Management:
// Keys must be explicitly freed by calling Close() when no longer needed.
// A finalizer is set as a safety net, but relying on it may cause resource leaks.
// Best practice: Always call Close() explicitly, preferably with defer.
//
// Example:
//
//	result, err := ecdsa2p.DKG(ctx, job, &ecdsa2p.DKGParams{Curve: cbmpc.CurveP256})
//	if err != nil {
//	    return err
//	}
//	defer result.Key.Close()
type Key struct {
	// ckey stores the C pointer as returned from bindings layer
	// The bindings layer uses *C.cbmpc_ecdsa2p_key (aliased as backend.ECDSA2PKey)
	// The alias itself is a pointer type, so we store it directly (not as a pointer to it)
	ckey backend.ECDSA2PKey
}

// newKey creates a new Key from a C pointer and sets up a finalizer.
func newKey(ckey backend.ECDSA2PKey) *Key {
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
	backend.ECDSA2PKeyFree(k.ckey)
	k.ckey = nil
	runtime.SetFinalizer(k, nil)
	return nil
}

// Bytes returns the serialized key data for persistent storage or network transmission.
func (k *Key) Bytes() ([]byte, error) {
	if k == nil || k.ckey == nil {
		return nil, errors.New("nil or closed key")
	}
	data, err := backend.ECDSA2PKeySerialize(k.ckey)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	return data, nil
}

// LoadKey deserializes a key from bytes.
// The returned key must be freed with Close() when no longer needed.
func LoadKey(data []byte) (*Key, error) {
	ckey, err := backend.ECDSA2PKeyDeserialize(data)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	return newKey(ckey), nil
}

// PublicKey extracts the public key point Q from the key share.
// Returns the compressed EC point encoding.
func (k *Key) PublicKey() ([]byte, error) {
	if k == nil || k.ckey == nil {
		return nil, errors.New("nil or closed key")
	}
	pubKey, err := backend.ECDSA2PKeyGetPublicKey(k.ckey)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	return pubKey, nil
}

// Curve returns the elliptic curve used by this key.
func (k *Key) Curve() (cbmpc.Curve, error) {
	if k == nil || k.ckey == nil {
		return cbmpc.Curve{}, errors.New("nil or closed key")
	}
	nid, err := backend.ECDSA2PKeyGetCurveNID(k.ckey)
	if err != nil {
		return cbmpc.Curve{}, cbmpc.RemapError(err)
	}
	return cbmpc.NewCurveFromNID(nid), nil
}

// DKGParams contains parameters for 2-party ECDSA distributed key generation.
type DKGParams struct {
	Curve cbmpc.Curve
}

// DKGResult contains the output of 2-party ECDSA distributed key generation.
type DKGResult struct {
	Key *Key
}

// DKG performs 2-party ECDSA distributed key generation.
// The returned key must be freed with Close() when no longer needed.
// See cb-mpc/src/cbmpc/protocol/ecdsa_2p.h for protocol details.
func DKG(_ context.Context, j *cbmpc.Job2P, params *DKGParams) (*DKGResult, error) {
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

	keyPtr, err := backend.ECDSA2PDKG(ptr, params.Curve.NID())
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	runtime.KeepAlive(j)

	return &DKGResult{
		Key: newKey(keyPtr),
	}, nil
}

// RefreshParams contains parameters for 2-party ECDSA key refresh.
type RefreshParams struct {
	Key *Key
}

// RefreshResult contains the output of 2-party ECDSA key refresh.
type RefreshResult struct {
	NewKey *Key
}

// Refresh performs 2-party ECDSA key refresh.
// The returned key must be freed with Close() when no longer needed.
// The input key is not modified and remains valid.
// See cb-mpc/src/cbmpc/protocol/ecdsa_2p.h for protocol details.
func Refresh(_ context.Context, j *cbmpc.Job2P, params *RefreshParams) (*RefreshResult, error) {
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

	newKeyCkey, err := backend.ECDSA2PRefresh(ptr, params.Key.ckey)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	runtime.KeepAlive(j)
	runtime.KeepAlive(params.Key)

	return &RefreshResult{
		NewKey: newKey(newKeyCkey),
	}, nil
}

// SignParams contains parameters for 2-party ECDSA signing.
type SignParams struct {
	SessionID []byte // Session ID (in/out parameter)
	Key       *Key   // Key share to sign with
	Message   []byte // Message hash to sign (must be pre-hashed, max size = curve order size)
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
func Sign(_ context.Context, j *cbmpc.Job2P, params *SignParams) (*SignResult, error) {
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

	newSID, sig, err := backend.ECDSA2PSign(ptr, params.Key.ckey, params.SessionID, params.Message)
	if err != nil {
		return nil, cbmpc.RemapError(err)
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
	SessionID []byte   // Session ID (in/out parameter)
	Key       *Key     // Key share to sign with
	Messages  [][]byte // Message hashes to sign (must be pre-hashed, max size = curve order size)
}

// SignBatchResult contains the output of 2-party ECDSA batch signing.
type SignBatchResult struct {
	SessionID  []byte   // Updated session ID
	Signatures [][]byte // ECDSA signatures (one per message)
}

// SignBatch performs 2-party ECDSA batch signing.
// See cb-mpc/src/cbmpc/protocol/ecdsa_2p.h for protocol details.
func SignBatch(_ context.Context, j *cbmpc.Job2P, params *SignBatchParams) (*SignBatchResult, error) {
	if j == nil {
		return nil, errors.New("nil job")
	}
	if params == nil {
		return nil, errors.New("nil params")
	}
	if params.Key == nil || params.Key.ckey == nil {
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

	ptr, err := j.Ptr()
	if err != nil {
		return nil, err
	}

	newSID, sigs, err := backend.ECDSA2PSignBatch(ptr, params.Key.ckey, params.SessionID, params.Messages)
	if err != nil {
		return nil, cbmpc.RemapError(err)
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
func SignWithGlobalAbort(_ context.Context, j *cbmpc.Job2P, params *SignParams) (*SignResult, error) {
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

	newSID, sig, err := backend.ECDSA2PSignWithGlobalAbort(ptr, params.Key.ckey, params.SessionID, params.Message)
	if err != nil {
		return nil, cbmpc.RemapError(err)
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
func SignWithGlobalAbortBatch(_ context.Context, j *cbmpc.Job2P, params *SignBatchParams) (*SignBatchResult, error) {
	if j == nil {
		return nil, errors.New("nil job")
	}
	if params == nil {
		return nil, errors.New("nil params")
	}
	if params.Key == nil || params.Key.ckey == nil {
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

	ptr, err := j.Ptr()
	if err != nil {
		return nil, err
	}

	newSID, sigs, err := backend.ECDSA2PSignWithGlobalAbortBatch(ptr, params.Key.ckey, params.SessionID, params.Messages)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	runtime.KeepAlive(j)
	runtime.KeepAlive(params.Key)

	return &SignBatchResult{
		SessionID:  newSID,
		Signatures: sigs,
	}, nil
}
