//go:build !cgo || windows

package cbmpc

import "errors"

// RSAKEM is not available in non-CGO builds.
type RSAKEM struct{}

func NewRSAKEM(keySize int) (*RSAKEM, error) {
	return nil, errors.New("RSAKEM requires CGO")
}

func (k *RSAKEM) Generate() (skRef []byte, ek []byte, err error) {
	return nil, nil, errors.New("RSAKEM requires CGO")
}

func (k *RSAKEM) Encapsulate(ek []byte, rho [32]byte) (ct, ss []byte, err error) {
	return nil, nil, errors.New("RSAKEM requires CGO")
}

func (k *RSAKEM) Decapsulate(skHandle any, ct []byte) (ss []byte, err error) {
	return nil, errors.New("RSAKEM requires CGO")
}

func (k *RSAKEM) DerivePub(skRef []byte) ([]byte, error) {
	return nil, errors.New("RSAKEM requires CGO")
}

func (k *RSAKEM) NewPrivateKeyHandle(skRef []byte) (any, error) {
	return nil, errors.New("RSAKEM requires CGO")
}

func (k *RSAKEM) FreePrivateKeyHandle(handle any) error {
	return errors.New("RSAKEM requires CGO")
}
