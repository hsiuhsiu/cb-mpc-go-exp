package schnorr2p

import (
	"context"
	"errors"
	"runtime"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// Key represents a 2-party Schnorr key share (wraps eckey::key_share_2p_t).
//
// SECURITY WARNING: Keys contain sensitive cryptographic material.
// - Never log or print key contents
// - Zeroize serialized key bytes after use with cbmpc.ZeroizeBytes
// - Use Close() to securely free the key when done
type Key struct {
	ckey backend.Schnorr2PKey
}

// Close frees the underlying C++ key resources.
// The key cannot be used after calling Close.
func (k *Key) Close() error {
	if k == nil {
		return nil
	}
	if k.ckey != nil {
		backend.Schnorr2PKeyFree(k.ckey)
		k.ckey = nil
	}
	return nil
}

// Bytes serializes the key to bytes for persistent storage or network transmission.
// Returns a defensive copy to prevent external modification of internal key data.
//
// SECURITY WARNING: The returned bytes contain the private key share.
// - Zeroize with cbmpc.ZeroizeBytes immediately after use
// - Never log, print, or transmit over insecure channels
// - Encrypt before storing or transmitting
func (k *Key) Bytes() ([]byte, error) {
	if k == nil {
		return nil, errors.New("nil key")
	}
	if k.ckey == nil {
		return nil, errors.New("key is closed")
	}
	data, err := backend.Schnorr2PKeySerialize(k.ckey)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	// Return a defensive copy to prevent mutation of internal state
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

// PublicKey returns the public key point Q in compressed format.
func (k *Key) PublicKey() ([]byte, error) {
	if k == nil {
		return nil, errors.New("nil key")
	}
	if k.ckey == nil {
		return nil, errors.New("key is closed")
	}
	pubKey, err := backend.Schnorr2PKeyGetPublicKey(k.ckey)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	// Return a copy to prevent external modification
	result := make([]byte, len(pubKey))
	copy(result, pubKey)
	return result, nil
}

// Curve returns the elliptic curve used by this key.
func (k *Key) Curve() (cbmpc.Curve, error) {
	if k == nil {
		return cbmpc.CurveUnknown, errors.New("nil key")
	}
	if k.ckey == nil {
		return cbmpc.CurveUnknown, errors.New("key is closed")
	}
	curveNID, err := backend.Schnorr2PKeyGetCurve(k.ckey)
	if err != nil {
		return cbmpc.CurveUnknown, cbmpc.RemapError(err)
	}
	curve, err := backend.NIDToCurve(curveNID)
	if err != nil {
		return cbmpc.CurveUnknown, err
	}
	return cbmpc.Curve(curve), nil
}

// LoadKey deserializes a Schnorr 2P key from bytes.
//
// SECURITY WARNING: The input bytes contain the private key share.
// - Zeroize with cbmpc.ZeroizeBytes immediately after calling LoadKey
func LoadKey(serialized []byte) (*Key, error) {
	ckey, err := backend.Schnorr2PKeyDeserialize(serialized)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	key := &Key{ckey: ckey}
	runtime.SetFinalizer(key, (*Key).Close)
	return key, nil
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

// DKGParams contains parameters for 2-party Schnorr distributed key generation.
type DKGParams struct {
	Curve cbmpc.Curve
}

// DKGResult contains the output of 2-party Schnorr distributed key generation.
type DKGResult struct {
	Key *Key
}

// DKG performs 2-party Schnorr distributed key generation.
//
// See cb-mpc/src/cbmpc/protocol/ec_dkg.h for protocol details.
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

	nid, err := backend.CurveToNID(backend.Curve(params.Curve))
	if err != nil {
		return nil, err
	}

	ckey, err := backend.Schnorr2PDKG(ptr, nid)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	runtime.KeepAlive(j)

	key := &Key{ckey: ckey}
	runtime.SetFinalizer(key, (*Key).Close)

	return &DKGResult{
		Key: key,
	}, nil
}

// SignParams contains parameters for 2-party Schnorr signing.
type SignParams struct {
	Key     *Key    // Key share to sign with
	Message []byte  // Message to sign (not pre-hashed for EdDSA, pre-hashed for BIP340)
	Variant Variant // Signature variant (EdDSA or BIP340)
}

// SignResult contains the output of 2-party Schnorr signing.
type SignResult struct {
	Signature []byte // Schnorr signature
}

// Sign performs 2-party Schnorr signing.
//
// Message handling varies by variant:
//   - EdDSA (Ed25519): Message is the raw message (not pre-hashed, any length)
//   - BIP340 (secp256k1): Message must be pre-hashed to exactly 32 bytes
//
// See cb-mpc/src/cbmpc/protocol/schnorr_2p.h for protocol details.
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

	// Use the opaque C key pointer directly (no serialization/deserialization)
	sig, err := backend.Schnorr2PSign(ptr, params.Key.ckey, params.Message, backend.SchnorrVariant(params.Variant))
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	runtime.KeepAlive(j)
	runtime.KeepAlive(params.Key)

	return &SignResult{
		Signature: sig,
	}, nil
}

// SignBatchParams contains parameters for 2-party Schnorr batch signing.
type SignBatchParams struct {
	Key      *Key     // Key share to sign with
	Messages [][]byte // Messages to sign
	Variant  Variant  // Signature variant (EdDSA or BIP340)
}

// SignBatchResult contains the output of 2-party Schnorr batch signing.
type SignBatchResult struct {
	Signatures [][]byte // Schnorr signatures (one per message)
}

// SignBatch performs 2-party Schnorr batch signing.
//
// Message handling varies by variant:
//   - EdDSA (Ed25519): Messages are raw messages (not pre-hashed, any length)
//   - BIP340 (secp256k1): Messages must be pre-hashed to exactly 32 bytes each
//
// See cb-mpc/src/cbmpc/protocol/schnorr_2p.h for protocol details.
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

	// Use the opaque C key pointer directly (no serialization/deserialization)
	sigs, err := backend.Schnorr2PSignBatch(ptr, params.Key.ckey, params.Messages, backend.SchnorrVariant(params.Variant))
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	runtime.KeepAlive(j)
	runtime.KeepAlive(params.Key)

	return &SignBatchResult{
		Signatures: sigs,
	}, nil
}
