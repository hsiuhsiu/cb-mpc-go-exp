//go:build cgo && !windows

package schnorrmp_test

import (
	"context"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/accessstructure"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/mocknet"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/schnorrmp"
)

// TestSchnorrMPThresholdDKG_ORNode mirrors ReconstructPubAdditiveShares_ORNode from test_ec_dkg.cpp
// Access structure: OR(p0, AND(p1, THRESHOLD[1](p2, p3)))
// DKG quorum: {p1, p3} (indices 1, 3)
func TestSchnorrMPThresholdDKG_ORNode(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	net := mocknet.New()
	curve := cbmpc.CurveSecp256k1
	nParties := 4

	// Build access structure: OR(p0, AND(p1, THRESHOLD[1](p2, p3)))
	ac, err := accessstructure.Compile(
		accessstructure.Or(
			accessstructure.Leaf("p0"),
			accessstructure.And(
				accessstructure.Leaf("p1"),
				accessstructure.Threshold(1,
					accessstructure.Leaf("p2"),
					accessstructure.Leaf("p3"),
				),
			),
		),
	)
	if err != nil {
		t.Fatalf("Failed to compile access structure: %v", err)
	}

	acStr, err := ac.String()
	if err != nil {
		t.Fatalf("Failed to get AC string: %v", err)
	}
	t.Logf("Access structure: %s", acStr)

	// DKG quorum: parties 1 and 3
	quorumIndices := []int{1, 3}

	// Set up roles and names
	roles := make([]cbmpc.RoleID, nParties)
	names := make([]string, nParties)
	for i := 0; i < nParties; i++ {
		roles[i] = cbmpc.RoleID(i)
		names[i] = "p" + string(rune('0'+i))
	}

	var wg sync.WaitGroup
	results := make([]*schnorrmp.ThresholdDKGResult, nParties)
	errors := make([]error, nParties)

	// All parties participate, but only quorum members actively generate keys
	for i := 0; i < nParties; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(roles[partyID], roles)

			job, err := cbmpc.NewJobMP(transport, roles[partyID], names)
			if err != nil {
				errors[partyID] = err
				return
			}
			defer func() {
				_ = job.Close()
			}()

			result, err := schnorrmp.ThresholdDKG(ctx, job, &schnorrmp.ThresholdDKGParams{
				Curve:              curve,
				AccessStructure:    ac,
				QuorumPartyIndices: quorumIndices,
			})
			results[partyID] = result
			errors[partyID] = err
		}(i)
	}

	wg.Wait()

	// Check for errors
	for i, err := range errors {
		if err != nil {
			t.Fatalf("Party %d threshold DKG failed: %v", i, err)
		}
	}

	// Verify all parties got keys
	for i, result := range results {
		if result == nil {
			t.Fatalf("Party %d got nil result", i)
		}
		if result.Key == nil {
			t.Fatalf("Party %d got nil key", i)
		}
		keyBytes, err := result.Key.Bytes()
		if err != nil {
			t.Fatalf("Party %d failed to get key bytes: %v", i, err)
		}
		if len(keyBytes) == 0 {
			t.Fatalf("Party %d got empty key", i)
		}
		if len(result.SessionID.Bytes()) == 0 {
			t.Fatalf("Party %d got empty session ID", i)
		}
	}

	// Verify all parties have the same public key
	pubKey0, err := results[0].Key.PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key from party 0: %v", err)
	}

	for i := 1; i < nParties; i++ {
		pubKey, err := results[i].Key.PublicKey()
		if err != nil {
			t.Fatalf("Failed to get public key from party %d: %v", i, err)
		}
		if string(pubKey) != string(pubKey0) {
			t.Fatalf("Public keys don't match:\nParty 0: %x\nParty %d: %x", pubKey0, i, pubKey)
		}
	}

	t.Logf("Threshold DKG (OR node) successful for %d parties, quorum: %v, public key: %s",
		nParties, quorumIndices, abbrevHex(pubKey0))

	// Clean up keys
	for _, result := range results {
		if result != nil && result.Key != nil {
			_ = result.Key.Close()
		}
	}
}

// TestSchnorrMPThresholdDKG_Threshold2of3 mirrors ReconstructPubAdditiveShares_Threshold2of3 from test_ec_dkg.cpp
// Access structure: THRESHOLD[2](p0, p1, p2)
// DKG quorum: {p0, p2} (indices 0, 2)
func TestSchnorrMPThresholdDKG_Threshold2of3(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	net := mocknet.New()
	curve := cbmpc.CurveSecp256k1
	nParties := 3

	// Build access structure: THRESHOLD[2](p0, p1, p2)
	ac, err := accessstructure.Compile(
		accessstructure.Threshold(2,
			accessstructure.Leaf("p0"),
			accessstructure.Leaf("p1"),
			accessstructure.Leaf("p2"),
		),
	)
	if err != nil {
		t.Fatalf("Failed to compile access structure: %v", err)
	}

	acStr, err := ac.String()
	if err != nil {
		t.Fatalf("Failed to get AC string: %v", err)
	}
	t.Logf("Access structure: %s", acStr)

	// DKG quorum: parties 0 and 2
	quorumIndices := []int{0, 2}

	// Set up roles and names
	roles := make([]cbmpc.RoleID, nParties)
	names := make([]string, nParties)
	for i := 0; i < nParties; i++ {
		roles[i] = cbmpc.RoleID(i)
		names[i] = "p" + string(rune('0'+i))
	}

	var wg sync.WaitGroup
	results := make([]*schnorrmp.ThresholdDKGResult, nParties)
	errors := make([]error, nParties)

	for i := 0; i < nParties; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(roles[partyID], roles)

			job, err := cbmpc.NewJobMP(transport, roles[partyID], names)
			if err != nil {
				errors[partyID] = err
				return
			}
			defer func() {
				_ = job.Close()
			}()

			result, err := schnorrmp.ThresholdDKG(ctx, job, &schnorrmp.ThresholdDKGParams{
				Curve:              curve,
				AccessStructure:    ac,
				QuorumPartyIndices: quorumIndices,
			})
			results[partyID] = result
			errors[partyID] = err
		}(i)
	}

	wg.Wait()

	// Check for errors
	for i, err := range errors {
		if err != nil {
			t.Fatalf("Party %d threshold DKG failed: %v", i, err)
		}
	}

	// Verify all parties have the same public key
	pubKey0, err := results[0].Key.PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key from party 0: %v", err)
	}

	for i := 1; i < nParties; i++ {
		pubKey, err := results[i].Key.PublicKey()
		if err != nil {
			t.Fatalf("Failed to get public key from party %d: %v", i, err)
		}
		if string(pubKey) != string(pubKey0) {
			t.Fatalf("Public keys don't match:\nParty 0: %x\nParty %d: %x", pubKey0, i, pubKey)
		}
	}

	t.Logf("Threshold DKG (2-of-3) successful for %d parties, quorum: %v, public key: %s",
		nParties, quorumIndices, abbrevHex(pubKey0))

	// Clean up keys
	for _, result := range results {
		if result != nil && result.Key != nil {
			_ = result.Key.Close()
		}
	}
}

// TestSchnorrMPThresholdDKG_ThresholdNofN_ANDEquivalent mirrors ReconstructPubAdditiveShares_ThresholdNofN_ANDEquivalent
// Access structure: THRESHOLD[3](p0, p1, p2) - equivalent to AND since all parties required
// DKG quorum: {p0, p1, p2} (indices 0, 1, 2)
func TestSchnorrMPThresholdDKG_ThresholdNofN_ANDEquivalent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	net := mocknet.New()
	curve := cbmpc.CurveP384
	nParties := 3

	// Build access structure: THRESHOLD[3](p0, p1, p2) - all parties required
	ac, err := accessstructure.Compile(
		accessstructure.Threshold(3,
			accessstructure.Leaf("p0"),
			accessstructure.Leaf("p1"),
			accessstructure.Leaf("p2"),
		),
	)
	if err != nil {
		t.Fatalf("Failed to compile access structure: %v", err)
	}

	acStr, err := ac.String()
	if err != nil {
		t.Fatalf("Failed to get AC string: %v", err)
	}
	t.Logf("Access structure: %s", acStr)

	// DKG quorum: all parties
	quorumIndices := []int{0, 1, 2}

	// Set up roles and names
	roles := make([]cbmpc.RoleID, nParties)
	names := make([]string, nParties)
	for i := 0; i < nParties; i++ {
		roles[i] = cbmpc.RoleID(i)
		names[i] = "p" + string(rune('0'+i))
	}

	var wg sync.WaitGroup
	results := make([]*schnorrmp.ThresholdDKGResult, nParties)
	errors := make([]error, nParties)

	for i := 0; i < nParties; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(roles[partyID], roles)

			job, err := cbmpc.NewJobMP(transport, roles[partyID], names)
			if err != nil {
				errors[partyID] = err
				return
			}
			defer func() {
				_ = job.Close()
			}()

			result, err := schnorrmp.ThresholdDKG(ctx, job, &schnorrmp.ThresholdDKGParams{
				Curve:              curve,
				AccessStructure:    ac,
				QuorumPartyIndices: quorumIndices,
			})
			results[partyID] = result
			errors[partyID] = err
		}(i)
	}

	wg.Wait()

	// Check for errors
	for i, err := range errors {
		if err != nil {
			t.Fatalf("Party %d threshold DKG failed: %v", i, err)
		}
	}

	// Verify all parties have the same public key
	pubKey0, err := results[0].Key.PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key from party 0: %v", err)
	}

	for i := 1; i < nParties; i++ {
		pubKey, err := results[i].Key.PublicKey()
		if err != nil {
			t.Fatalf("Failed to get public key from party %d: %v", i, err)
		}
		if string(pubKey) != string(pubKey0) {
			t.Fatalf("Public keys don't match:\nParty 0: %x\nParty %d: %x", pubKey0, i, pubKey)
		}
	}

	t.Logf("Threshold DKG (N-of-N/AND-equivalent) successful for %d parties, quorum: %v, public key: %s",
		nParties, quorumIndices, abbrevHex(pubKey0))

	// Clean up keys
	for _, result := range results {
		if result != nil && result.Key != nil {
			_ = result.Key.Close()
		}
	}
}

// TestSchnorrMPThresholdDKG_Threshold3of4_LargerLeaves mirrors ReconstructPubAdditiveShares_Threshold3of4_LargerLeaves
// Access structure: THRESHOLD[3](p0, p1, p2, p3)
// DKG quorum: {p0, p1, p2} (indices 0, 1, 2)
func TestSchnorrMPThresholdDKG_Threshold3of4_LargerLeaves(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	net := mocknet.New()
	curve := cbmpc.CurveP521
	nParties := 4

	// Build access structure: THRESHOLD[3](p0, p1, p2, p3)
	ac, err := accessstructure.Compile(
		accessstructure.Threshold(3,
			accessstructure.Leaf("p0"),
			accessstructure.Leaf("p1"),
			accessstructure.Leaf("p2"),
			accessstructure.Leaf("p3"),
		),
	)
	if err != nil {
		t.Fatalf("Failed to compile access structure: %v", err)
	}

	acStr, err := ac.String()
	if err != nil {
		t.Fatalf("Failed to get AC string: %v", err)
	}
	t.Logf("Access structure: %s", acStr)

	// DKG quorum: parties 0, 1, 2 (note: test in C++ uses {3, 1, 2} but order shouldn't matter)
	quorumIndices := []int{0, 1, 2}

	// Set up roles and names
	roles := make([]cbmpc.RoleID, nParties)
	names := make([]string, nParties)
	for i := 0; i < nParties; i++ {
		roles[i] = cbmpc.RoleID(i)
		names[i] = "p" + string(rune('0'+i))
	}

	var wg sync.WaitGroup
	results := make([]*schnorrmp.ThresholdDKGResult, nParties)
	errors := make([]error, nParties)

	for i := 0; i < nParties; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(roles[partyID], roles)

			job, err := cbmpc.NewJobMP(transport, roles[partyID], names)
			if err != nil {
				errors[partyID] = err
				return
			}
			defer func() {
				_ = job.Close()
			}()

			result, err := schnorrmp.ThresholdDKG(ctx, job, &schnorrmp.ThresholdDKGParams{
				Curve:              curve,
				AccessStructure:    ac,
				QuorumPartyIndices: quorumIndices,
			})
			results[partyID] = result
			errors[partyID] = err
		}(i)
	}

	wg.Wait()

	// Check for errors
	for i, err := range errors {
		if err != nil {
			t.Fatalf("Party %d threshold DKG failed: %v", i, err)
		}
	}

	// Verify all parties have the same public key
	pubKey0, err := results[0].Key.PublicKey()
	if err != nil {
		t.Fatalf("Failed to get public key from party 0: %v", err)
	}

	for i := 1; i < nParties; i++ {
		pubKey, err := results[i].Key.PublicKey()
		if err != nil {
			t.Fatalf("Failed to get public key from party %d: %v", i, err)
		}
		if string(pubKey) != string(pubKey0) {
			t.Fatalf("Public keys don't match:\nParty 0: %x\nParty %d: %x", pubKey0, i, pubKey)
		}
	}

	t.Logf("Threshold DKG (3-of-4) successful for %d parties, quorum: %v, public key: %s",
		nParties, quorumIndices, abbrevHex(pubKey0))

	// Clean up keys
	for _, result := range results {
		if result != nil && result.Key != nil {
			_ = result.Key.Close()
		}
	}
}

// TestSchnorrMPThresholdRefresh tests threshold refresh following DKG
func TestSchnorrMPThresholdRefresh(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	net := mocknet.New()
	curve := cbmpc.CurveSecp256k1
	nParties := 3

	// Build access structure: THRESHOLD[2](p0, p1, p2)
	ac, err := accessstructure.Compile(
		accessstructure.Threshold(2,
			accessstructure.Leaf("p0"),
			accessstructure.Leaf("p1"),
			accessstructure.Leaf("p2"),
		),
	)
	if err != nil {
		t.Fatalf("Failed to compile access structure: %v", err)
	}

	// DKG quorum: parties 0 and 2
	quorumIndices := []int{0, 2}

	// Set up roles and names
	roles := make([]cbmpc.RoleID, nParties)
	names := make([]string, nParties)
	for i := 0; i < nParties; i++ {
		roles[i] = cbmpc.RoleID(i)
		names[i] = "p" + string(rune('0'+i))
	}

	// First, perform threshold DKG
	var wg sync.WaitGroup
	keys := make([]*schnorrmp.Key, nParties)
	sessionIDs := make([]cbmpc.SessionID, nParties)
	errors := make([]error, nParties)

	for i := 0; i < nParties; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(roles[partyID], roles)

			job, err := cbmpc.NewJobMP(transport, roles[partyID], names)
			if err != nil {
				errors[partyID] = err
				return
			}
			defer func() {
				_ = job.Close()
			}()

			result, err := schnorrmp.ThresholdDKG(ctx, job, &schnorrmp.ThresholdDKGParams{
				Curve:              curve,
				AccessStructure:    ac,
				QuorumPartyIndices: quorumIndices,
			})
			if err != nil {
				errors[partyID] = err
				return
			}
			keys[partyID] = result.Key
			sessionIDs[partyID] = result.SessionID
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("Party %d threshold DKG failed: %v", i, err)
		}
	}

	oldPubKey, err := keys[0].PublicKey()
	if err != nil {
		t.Fatalf("Failed to get old public key: %v", err)
	}
	t.Logf("Threshold DKG complete, public key: %s", abbrevHex(oldPubKey))

	// Now perform threshold refresh with same quorum
	newKeys := make([]*schnorrmp.Key, nParties)
	errors = make([]error, nParties)

	for i := 0; i < nParties; i++ {
		wg.Add(1)
		go func(partyID int) {
			defer wg.Done()

			transport := net.EpMP(roles[partyID], roles)

			job, err := cbmpc.NewJobMP(transport, roles[partyID], names)
			if err != nil {
				errors[partyID] = err
				return
			}
			defer func() {
				_ = job.Close()
			}()

			result, err := schnorrmp.ThresholdRefresh(ctx, job, &schnorrmp.ThresholdRefreshParams{
				SessionID:          sessionIDs[partyID],
				Key:                keys[partyID],
				AccessStructure:    ac,
				QuorumPartyIndices: quorumIndices,
			})
			if err != nil {
				errors[partyID] = err
				return
			}
			newKeys[partyID] = result.NewKey
		}(i)
	}

	wg.Wait()

	for i, err := range errors {
		if err != nil {
			t.Fatalf("Party %d threshold refresh failed: %v", i, err)
		}
	}

	// Verify public keys are the same after refresh
	for i, newKey := range newKeys {
		newPubKey, err := newKey.PublicKey()
		if err != nil {
			t.Fatalf("Failed to get new public key from party %d: %v", i, err)
		}

		if string(oldPubKey) != string(newPubKey) {
			t.Fatalf("Public key changed after refresh for party %d:\nOld: %s\nNew: %s",
				i, abbrevHex(oldPubKey), abbrevHex(newPubKey))
		}
	}

	t.Logf("Threshold refresh successful, public key preserved: %s", abbrevHex(oldPubKey))

	// Clean up keys
	for _, key := range keys {
		if key != nil {
			_ = key.Close()
		}
	}
	for _, key := range newKeys {
		if key != nil {
			_ = key.Close()
		}
	}
}

// abbrevHex returns an abbreviated hex string showing first 2 and last 2 bytes.
// Example: []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff} -> "aabb...eeff"
func abbrevHex(data []byte) string {
	if len(data) <= 4 {
		return hex.EncodeToString(data)
	}
	return hex.EncodeToString(data[:2]) + "..." + hex.EncodeToString(data[len(data)-2:])
}
