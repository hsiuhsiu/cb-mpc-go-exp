//go:build cgo && !windows

package pve

import (
	"context"
	"errors"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	ac "github.com/coinbase/cb-mpc-go/pkg/cbmpc/accessstructure"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/internal/backend"
)

// ACCiphertext represents a PVE-AC ciphertext.
// Unlike single or batch ciphertexts, AC ciphertexts support flexible
// access control policies via secret sharing.
type ACCiphertext []byte

// ACEncryptParams contains parameters for PVE-AC encryption.
type ACEncryptParams struct {
	// AC is the compiled access control structure.
	AC ac.AccessStructure

	// PathToEK maps party path names to their encryption keys.
	// Path names must match those used in the AC structure.
	PathToEK map[string][]byte

	// Label is the encryption label.
	Label []byte

	// Curve is the elliptic curve to use.
	Curve cbmpc.Curve

	// Scalars are the secret values to encrypt (one per party in AC).
	Scalars [][]byte
}

// ACEncryptResult contains the result of PVE-AC encryption.
type ACEncryptResult struct {
	// Ciphertext is the encrypted result.
	Ciphertext ACCiphertext
}

// ACEncrypt performs PVE-AC encryption with access control.
// See cb-mpc/src/cbmpc/protocol/pve_ac.h for protocol details.
func (pve *PVE) ACEncrypt(ctx context.Context, p *ACEncryptParams) (*ACEncryptResult, error) {
	if pve == nil {
		return nil, errors.New("nil PVE")
	}
	if p == nil {
		return nil, errors.New("nil params")
	}
	if len(p.AC) == 0 {
		return nil, errors.New("empty AC")
	}
	if len(p.PathToEK) == 0 {
		return nil, errors.New("empty PathToEK map")
	}

	nid, err := backend.CurveToNID(backend.Curve(p.Curve))
	if err != nil {
		return nil, err
	}

	ctBytes, err := backend.PVEACEncrypt(
		pve.kem,
		p.AC,
		p.PathToEK,
		p.Label,
		nid,
		p.Scalars,
	)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	return &ACEncryptResult{
		Ciphertext: ACCiphertext(ctBytes),
	}, nil
}

// Bytes returns the serialized ciphertext bytes.
func (ct ACCiphertext) Bytes() []byte {
	return []byte(ct)
}

// ACVerifyParams contains parameters for PVE-AC verification.
type ACVerifyParams struct {
	// AC is the compiled access control structure.
	AC ac.AccessStructure

	// PathToEK maps party path names to their encryption keys.
	PathToEK map[string][]byte

	// Ciphertext is the PVE-AC ciphertext to verify.
	Ciphertext ACCiphertext

	// QPoints are the public key points (one per scalar).
	QPoints []*cbmpc.CurvePoint

	// Label is the encryption label.
	Label []byte
}

// ACVerify verifies a PVE-AC ciphertext.
// See cb-mpc/src/cbmpc/protocol/pve_ac.h for protocol details.
func (pve *PVE) ACVerify(ctx context.Context, p *ACVerifyParams) error {
	if pve == nil {
		return errors.New("nil PVE")
	}
	if p == nil {
		return errors.New("nil params")
	}
	if len(p.AC) == 0 {
		return errors.New("empty AC")
	}
	if len(p.PathToEK) == 0 {
		return errors.New("empty PathToEK map")
	}
	if len(p.Ciphertext) == 0 {
		return errors.New("empty ciphertext")
	}
	if len(p.QPoints) == 0 {
		return errors.New("empty Q points")
	}

	// Convert Q points to backend ECCPoints
	eccPoints := make([]backend.ECCPoint, len(p.QPoints))
	for i, pt := range p.QPoints {
		if pt == nil {
			return errors.New("nil Q point")
		}
		eccPoints[i] = pt.CPtr()
	}

	err := backend.PVEACVerify(
		pve.kem,
		p.AC,
		p.PathToEK,
		p.Ciphertext,
		eccPoints,
		p.Label,
	)
	if err != nil {
		return cbmpc.RemapError(err)
	}

	return nil
}

// ACPartyDecryptRowParams contains parameters for PVE-AC party decryption.
type ACPartyDecryptRowParams struct {
	// AC is the compiled access control structure.
	AC ac.AccessStructure

	// RowIndex specifies which row (scalar index) to decrypt.
	RowIndex int

	// Path is this party's path in the AC structure.
	Path string

	// DK is this party's decryption key handle.
	DK any

	// Ciphertext is the PVE-AC ciphertext.
	Ciphertext ACCiphertext

	// Label is the encryption label.
	Label []byte
}

// ACPartyDecryptRowResult contains the result of party decryption.
type ACPartyDecryptRowResult struct {
	// Share is this party's decryption share for the row.
	Share []byte
}

// ACPartyDecryptRow performs party decryption for a single row.
// Each authorized party calls this to produce their share.
// See cb-mpc/src/cbmpc/protocol/pve_ac.h for protocol details.
func (pve *PVE) ACPartyDecryptRow(ctx context.Context, p *ACPartyDecryptRowParams) (*ACPartyDecryptRowResult, error) {
	if pve == nil {
		return nil, errors.New("nil PVE")
	}
	if p == nil {
		return nil, errors.New("nil params")
	}
	if len(p.AC) == 0 {
		return nil, errors.New("empty AC")
	}
	if p.DK == nil {
		return nil, errors.New("nil DK")
	}
	if len(p.Ciphertext) == 0 {
		return nil, errors.New("empty ciphertext")
	}

	// Register the DK handle for C++ callback
	dkHandle := backend.RegisterHandle(p.DK)
	defer backend.FreeHandle(dkHandle)

	shareBytes, err := backend.PVEACPartyDecryptRow(
		pve.kem,
		p.AC,
		p.RowIndex,
		p.Path,
		dkHandle,
		p.Ciphertext,
		p.Label,
	)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	return &ACPartyDecryptRowResult{
		Share: shareBytes,
	}, nil
}

// ACAggregateToRestoreRowParams contains parameters for PVE-AC aggregation.
type ACAggregateToRestoreRowParams struct {
	// AC is the compiled access control structure.
	AC ac.AccessStructure

	// RowIndex specifies which row (scalar index) to restore.
	RowIndex int

	// Label is the encryption label.
	Label []byte

	// QuorumPathToShare maps party paths to their decryption shares.
	// Must satisfy the AC policy for the specified row.
	QuorumPathToShare map[string][]byte

	// Ciphertext is the PVE-AC ciphertext.
	Ciphertext ACCiphertext

	// AllPathToEK is optional: if provided, verification is performed during aggregation.
	// Maps all party paths to their encryption keys.
	AllPathToEK map[string][]byte
}

// ACAggregateToRestoreRowResult contains the result of aggregation.
type ACAggregateToRestoreRowResult struct {
	// Scalars are the restored secret values for the row.
	Scalars [][]byte
}

// ACAggregateToRestoreRow aggregates quorum shares to restore the original scalars.
// See cb-mpc/src/cbmpc/protocol/pve_ac.h for protocol details.
func (pve *PVE) ACAggregateToRestoreRow(ctx context.Context, p *ACAggregateToRestoreRowParams) (*ACAggregateToRestoreRowResult, error) {
	if pve == nil {
		return nil, errors.New("nil PVE")
	}
	if p == nil {
		return nil, errors.New("nil params")
	}
	if len(p.AC) == 0 {
		return nil, errors.New("empty AC")
	}
	if len(p.QuorumPathToShare) == 0 {
		return nil, errors.New("empty quorum shares")
	}
	if len(p.Ciphertext) == 0 {
		return nil, errors.New("empty ciphertext")
	}

	scalarsBytes, err := backend.PVEACAggregateToRestoreRow(
		pve.kem,
		p.AC,
		p.RowIndex,
		p.Label,
		p.QuorumPathToShare,
		p.Ciphertext,
		p.AllPathToEK,
	)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}

	return &ACAggregateToRestoreRowResult{
		Scalars: scalarsBytes,
	}, nil
}
