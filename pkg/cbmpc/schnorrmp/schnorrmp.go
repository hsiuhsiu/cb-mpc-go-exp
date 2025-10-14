package schnorrmp

import (
	"context"
	"errors"
	"runtime"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// Key represents a multi-party Schnorr key share.
//
// Implementation Note:
// Currently, this wraps the same C++ type as ECDSA MP (eckey::key_share_mp_t).
// By using a separate Go type, we insulate the Go API from potential future changes
// in the C++ library where Schnorr MP and ECDSA MP might use different key types.
//
// Memory Management:
// Keys must be explicitly freed by calling Close() when no longer needed.
// A finalizer is set as a safety net, but relying on it may cause resource leaks.
// Best practice: Always call Close() explicitly, preferably with defer.
//
// Example:
//
//	result, err := schnorrmp.DKG(ctx, job, &schnorrmp.DKGParams{Curve: cbmpc.CurveSecp256k1})
//	if err != nil {
//	    return err
//	}
//	defer result.Key.Close()
type Key struct {
	// ckey stores the C pointer as returned from bindings layer
	// Currently uses backend.ECDSAMPKey but treated as opaque
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

// Variant represents a Schnorr signature variant.
type Variant int

const (
	// VariantEdDSA represents EdDSA (Ed25519) variant.
	VariantEdDSA Variant = Variant(backend.SchnorrVariantEdDSA)
	// VariantBIP340 represents BIP340 (secp256k1) variant.
	VariantBIP340 Variant = Variant(backend.SchnorrVariantBIP340)
)

// String returns the string representation of the variant.
func (v Variant) String() string {
	switch v {
	case VariantEdDSA:
		return "EdDSA"
	case VariantBIP340:
		return "BIP340"
	default:
		return "Unknown"
	}
}

// DKGParams contains parameters for multi-party Schnorr distributed key generation.
type DKGParams struct {
	Curve cbmpc.Curve
}

// DKGResult contains the output of multi-party Schnorr distributed key generation.
type DKGResult struct {
	Key       *Key
	SessionID cbmpc.SessionID
}

// DKG performs multi-party Schnorr distributed key generation.
// The returned key must be freed with Close() when no longer needed.
//
// Context behavior: ctx is ignored; use cbmpc.NewJobMPWithContext to control cancellation.
//
// Note: Currently shares the same C++ DKG implementation as ECDSA MP,
// but this is an implementation detail hidden from the Go API.
//
// See cb-mpc/src/cbmpc/protocol/schnorr_mp.h for protocol details.
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

	// Currently uses ECDSA MP DKG since Schnorr MP uses the same key type
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

// RefreshParams contains parameters for multi-party Schnorr key refresh.
type RefreshParams struct {
	SessionID cbmpc.SessionID
	Key       *Key
}

// RefreshResult contains the output of multi-party Schnorr key refresh.
type RefreshResult struct {
	NewKey    *Key
	SessionID cbmpc.SessionID
}

// Refresh performs multi-party Schnorr key refresh.
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
// Note: Currently shares the same C++ refresh implementation as ECDSA MP,
// but this is an implementation detail hidden from the Go API.
//
// See cb-mpc/src/cbmpc/protocol/schnorr_mp.h for protocol details.
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

	// Currently uses ECDSA MP refresh since Schnorr MP uses the same key type
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

// SignParams contains parameters for multi-party Schnorr signing.
type SignParams struct {
	Key         *Key    // Key share to sign with
	Message     []byte  // Message to sign (not pre-hashed for EdDSA, pre-hashed for BIP340)
	SigReceiver int     // Party index that receives the final signature
	Variant     Variant // Signature variant (EdDSA or BIP340)
}

// SignResult contains the output of multi-party Schnorr signing.
type SignResult struct {
	Signature []byte // Schnorr signature (only populated for the designated receiver party)
}

// Sign performs multi-party Schnorr signing.
//
// Message handling varies by variant:
//   - EdDSA (Ed25519): Message is the raw message (not pre-hashed, any length)
//   - BIP340 (secp256k1): Message must be pre-hashed to exactly 32 bytes
//
// Only the party with party_idx == SigReceiver will receive the final signature.
// Other parties will receive an empty signature.
//
// Context behavior: ctx is ignored; use cbmpc.NewJobMPWithContext to control cancellation.
//
// See cb-mpc/src/cbmpc/protocol/schnorr_mp.h for protocol details.
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
		return nil, errors.New("empty message")
	}

	// Variant-specific message validation
	if params.Variant == VariantBIP340 && len(params.Message) != 32 {
		return nil, errors.New("BIP340 variant requires exactly 32-byte pre-hashed message")
	}

	ptr, err := j.Ptr()
	if err != nil {
		return nil, err
	}

	sig, err := backend.SchnorrMPSign(ptr, params.Key.ckey, params.Message, params.SigReceiver, backend.SchnorrVariant(params.Variant))
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	runtime.KeepAlive(j)
	runtime.KeepAlive(params.Key)

	return &SignResult{
		Signature: sig,
	}, nil
}

// SignBatchParams contains parameters for multi-party Schnorr batch signing.
type SignBatchParams struct {
	Key         *Key     // Key share to sign with
	Messages    [][]byte // Messages to sign
	SigReceiver int      // Party index that receives the final signatures
	Variant     Variant  // Signature variant (EdDSA or BIP340)
}

// SignBatchResult contains the output of multi-party Schnorr batch signing.
type SignBatchResult struct {
	Signatures [][]byte // Schnorr signatures (one per message, only populated for the designated receiver party)
}

// SignBatch performs multi-party Schnorr batch signing.
//
// Message handling varies by variant:
//   - EdDSA (Ed25519): Messages are raw messages (not pre-hashed, any length)
//   - BIP340 (secp256k1): Messages must be pre-hashed to exactly 32 bytes each
//
// Only the party with party_idx == SigReceiver will receive the final signatures.
// Other parties will receive empty signatures.
//
// Context behavior: ctx is ignored; use cbmpc.NewJobMPWithContext to control cancellation.
//
// See cb-mpc/src/cbmpc/protocol/schnorr_mp.h for protocol details.
func SignBatch(_ context.Context, j *cbmpc.JobMP, params *SignBatchParams) (*SignBatchResult, error) {
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

	// Variant-specific message validation
	if params.Variant == VariantBIP340 {
		for _, msg := range params.Messages {
			if len(msg) != 32 {
				return nil, errors.New("BIP340 variant requires all messages to be exactly 32 bytes (pre-hashed)")
			}
		}
	}

	ptr, err := j.Ptr()
	if err != nil {
		return nil, err
	}

	sigs, err := backend.SchnorrMPSignBatch(ptr, params.Key.ckey, params.Messages, params.SigReceiver, backend.SchnorrVariant(params.Variant))
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	runtime.KeepAlive(j)
	runtime.KeepAlive(params.Key)

	return &SignBatchResult{
		Signatures: sigs,
	}, nil
}
