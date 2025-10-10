package agreerandom

import (
	"context"
	"errors"
	"runtime"

	"github.com/coinbase/cb-mpc-go/internal/bindings"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
)

// AgreeRandom is a Go wrapper for coinbase::mpc::agree_random.
// See cb-mpc/src/cbmpc/protocol/agree_random.h for protocol details.
func AgreeRandom(_ context.Context, j *cbmpc.Job2P, bitlen int) ([]byte, error) {
	if j == nil {
		return nil, errors.New("nil job")
	}

	ptr, err := j.Ptr()
	if err != nil {
		return nil, err
	}

	out, err := bindings.AgreeRandom2P(ptr, bitlen)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	runtime.KeepAlive(j)
	return out, nil
}

// MultiAgreeRandom is a Go wrapper for coinbase::mpc::multi_agree_random.
// See cb-mpc/src/cbmpc/protocol/agree_random.h for protocol details.
func MultiAgreeRandom(_ context.Context, j *cbmpc.JobMP, bitlen int) ([]byte, error) {
	if j == nil {
		return nil, errors.New("nil job")
	}

	ptr, err := j.Ptr()
	if err != nil {
		return nil, err
	}

	out, err := bindings.AgreeRandomMP(ptr, bitlen)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	runtime.KeepAlive(j)
	return out, nil
}

// WeakMultiAgreeRandom is a Go wrapper for coinbase::mpc::weak_multi_agree_random.
// See cb-mpc/src/cbmpc/protocol/agree_random.h for protocol details.
func WeakMultiAgreeRandom(_ context.Context, j *cbmpc.JobMP, bitlen int) ([]byte, error) {
	if j == nil {
		return nil, errors.New("nil job")
	}

	ptr, err := j.Ptr()
	if err != nil {
		return nil, err
	}

	out, err := bindings.WeakMultiAgreeRandom(ptr, bitlen)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	runtime.KeepAlive(j)
	return out, nil
}

// MultiPairwiseAgreeRandom is a Go wrapper for coinbase::mpc::multi_pairwise_agree_random.
// Returns a slice of []byte corresponding to the C++ std::vector<buf_t> output.
// See cb-mpc/src/cbmpc/protocol/agree_random.h for protocol details.
func MultiPairwiseAgreeRandom(_ context.Context, j *cbmpc.JobMP, bitlen int) ([][]byte, error) {
	if j == nil {
		return nil, errors.New("nil job")
	}

	ptr, err := j.Ptr()
	if err != nil {
		return nil, err
	}

	out, err := bindings.MultiPairwiseAgreeRandom(ptr, bitlen)
	if err != nil {
		return nil, cbmpc.RemapError(err)
	}
	runtime.KeepAlive(j)
	return out, nil
}
