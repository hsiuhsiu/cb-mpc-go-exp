//go:build !cgo || windows

package rsa

import "errors"

// KEM stub implementation for non-CGO builds.
type KEM struct{}

func New(keySize int) (*KEM, error) {
	return nil, errors.New("RSA KEM requires CGO")
}

func (k *KEM) Generate() (skRef []byte, ek []byte, err error) {
	return nil, nil, errors.New("RSA KEM requires CGO")
}

func (k *KEM) Encapsulate(ek []byte, rho [32]byte) (ct, ss []byte, err error) {
	return nil, nil, errors.New("RSA KEM requires CGO")
}

func (k *KEM) Decapsulate(skHandle any, ct []byte) (ss []byte, err error) {
	return nil, errors.New("RSA KEM requires CGO")
}

func (k *KEM) DerivePub(skRef []byte) ([]byte, error) {
	return nil, errors.New("RSA KEM requires CGO")
}

func (k *KEM) NewPrivateKeyHandle(skRef []byte) (any, error) {
	return nil, errors.New("RSA KEM requires CGO")
}

func (k *KEM) FreePrivateKeyHandle(handle any) error {
	return errors.New("RSA KEM requires CGO")
}
