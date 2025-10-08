package cbmpc

import (
	"context"
	"errors"
	"runtime"

	"github.com/coinbase/cb-mpc-go/internal/bindings"
)

// ECDSA2PKey represents a 2-party ECDSA key share.
// The key is stored in serialized form and all operations are delegated to C++.
type ECDSA2PKey struct {
	serialized []byte
}

// Bytes returns the serialized key data.
func (k *ECDSA2PKey) Bytes() []byte {
	if k == nil {
		return nil
	}
	return k.serialized
}

// PublicKey extracts the public key point Q from the key share.
// Returns the compressed EC point encoding.
func (k *ECDSA2PKey) PublicKey() ([]byte, error) {
	if k == nil {
		return nil, errors.New("nil key")
	}
	pubKey, err := bindings.ECDSA2PKeyGetPublicKey(k.serialized)
	if err != nil {
		return nil, remapError(err)
	}
	return pubKey, nil
}

// Curve returns the elliptic curve used by this key.
func (k *ECDSA2PKey) Curve() (Curve, error) {
	if k == nil {
		return Curve{}, errors.New("nil key")
	}
	nid, err := bindings.ECDSA2PKeyGetCurveNID(k.serialized)
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

	keyData, err := bindings.ECDSA2PDKG(ptr, params.Curve.nid)
	if err != nil {
		return nil, remapError(err)
	}
	runtime.KeepAlive(j)

	return &DKGResult{
		Key: &ECDSA2PKey{serialized: keyData},
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
// See cb-mpc/src/cbmpc/protocol/ecdsa_2p.h for protocol details.
func Refresh(_ context.Context, j *Job2P, params *RefreshParams) (*RefreshResult, error) {
	if j == nil {
		return nil, errors.New("nil job")
	}
	if params == nil {
		return nil, errors.New("nil params")
	}
	if params.Key == nil {
		return nil, errors.New("nil key")
	}

	ptr, err := j.ptr()
	if err != nil {
		return nil, err
	}

	newKeyData, err := bindings.ECDSA2PRefresh(ptr, params.Key.serialized)
	if err != nil {
		return nil, remapError(err)
	}
	runtime.KeepAlive(j)

	return &RefreshResult{
		NewKey: &ECDSA2PKey{serialized: newKeyData},
	}, nil
}

// SignParams contains parameters for 2-party ECDSA signing.
type SignParams struct {
	SessionID []byte      // Session ID (in/out parameter)
	Key       *ECDSA2PKey // Key share to sign with
	Message   []byte      // Message hash to sign (must be pre-hashed)
}

// SignResult contains the output of 2-party ECDSA signing.
type SignResult struct {
	SessionID []byte // Updated session ID
	Signature []byte // ECDSA signature
}

// Sign performs 2-party ECDSA signing.
// The message must be the hash of the actual message to sign.
// See cb-mpc/src/cbmpc/protocol/ecdsa_2p.h for protocol details.
func Sign(_ context.Context, j *Job2P, params *SignParams) (*SignResult, error) {
	if j == nil {
		return nil, errors.New("nil job")
	}
	if params == nil {
		return nil, errors.New("nil params")
	}
	if params.Key == nil {
		return nil, errors.New("nil key")
	}
	if len(params.Message) == 0 {
		return nil, errors.New("empty message")
	}

	ptr, err := j.ptr()
	if err != nil {
		return nil, err
	}

	newSID, sig, err := bindings.ECDSA2PSign(ptr, params.SessionID, params.Key.serialized, params.Message)
	if err != nil {
		return nil, remapError(err)
	}
	runtime.KeepAlive(j)

	return &SignResult{
		SessionID: newSID,
		Signature: sig,
	}, nil
}
