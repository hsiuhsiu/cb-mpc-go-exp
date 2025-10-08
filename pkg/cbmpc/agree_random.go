package cbmpc

import (
	"context"
	"errors"
	"runtime"

	"github.com/coinbase/cb-mpc-go/internal/bindings"
)

func AgreeRandom(_ context.Context, j *Job2P, bitlen int) ([]byte, error) {
	if bitlen < 8 || bitlen%8 != 0 {
		return nil, ErrInvalidBits
	}
	if j == nil {
		return nil, errors.New("nil job")
	}

	ptr, err := j.ptr()
	if err != nil {
		return nil, err
	}

	out, err := bindings.AgreeRandom2P(ptr, bitlen)
	if err != nil {
		return nil, remapError(err)
	}
	runtime.KeepAlive(j)
	return out, nil
}

func MultiAgreeRandom(_ context.Context, j *JobMP, bitlen int) ([]byte, error) {
	if bitlen < 8 || bitlen%8 != 0 {
		return nil, ErrInvalidBits
	}
	if j == nil {
		return nil, errors.New("nil job")
	}

	ptr, err := j.ptr()
	if err != nil {
		return nil, err
	}

	out, err := bindings.AgreeRandomMP(ptr, bitlen)
	if err != nil {
		return nil, remapError(err)
	}
	runtime.KeepAlive(j)
	return out, nil
}
