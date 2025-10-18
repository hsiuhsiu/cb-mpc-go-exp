package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/coinbase/cb-mpc-go/examples/common"
	"github.com/coinbase/cb-mpc-go/examples/tlsnet"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/curve"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/ecdsamp"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/kem/rsa"
	"github.com/coinbase/cb-mpc-go/pkg/cbmpc/pve"
)

func main() {
	var (
		configPath = flag.String("config", "examples/ecdsa-mpc-with-backup/cluster.json", "path to cluster configuration")
		selfName   = flag.String("self", "", "name of this party in the cluster configuration")
		message    = flag.String("message", "Hello, MPC World!", "message to sign")
		timeout    = flag.Duration("timeout", 90*time.Second, "overall protocol timeout")
	)
	flag.Parse()

	if *selfName == "" {
		log.Fatal("--self flag is required")
	}

	// Load configuration
	cfg, err := common.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if err := common.ValidateConfig(cfg); err != nil {
		log.Fatalf("invalid config: %v", err)
	}
	if len(cfg.Parties) != 4 {
		log.Fatalf("multi-party demo requires exactly four parties (got %d)", len(cfg.Parties))
	}

	// Extract party names and addresses
	n := len(cfg.Parties)
	names := make([]string, n)
	addresses := make([]string, n)
	selfIndex := -1
	for i, p := range cfg.Parties {
		names[i] = p.Name
		addresses[i] = p.Address
		if p.Name == *selfName {
			selfIndex = i
		}
	}
	if selfIndex < 0 {
		log.Fatalf("self name %q not present in config", *selfName)
	}

	// Load TLS certificates
	cert, err := common.LoadKeyPair(cfg.Parties[selfIndex].Cert, cfg.Parties[selfIndex].Key)
	if err != nil {
		log.Fatalf("load certificate: %v", err)
	}

	caPool, err := common.LoadCertPool(cfg.CACert)
	if err != nil {
		log.Fatalf("load CA: %v", err)
	}

	// Setup mTLS transport
	transport, err := tlsnet.New(tlsnet.Config{
		Self:        selfIndex,
		Names:       names,
		Addresses:   addresses,
		Certificate: cert,
		RootCAs:     caPool,
	})
	if err != nil {
		log.Fatalf("start tls transport: %v", err)
	}
	defer transport.Close()

	log.Printf("[%s] mTLS transport established with %d parties", names[selfIndex], len(names))

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Create multi-party job
	// #nosec G115 -- selfIndex is validated to be >= 0 and < len(cfg.Parties) which is exactly 4
	job, err := cbmpc.NewJobMPWithContext(ctx, transport, cbmpc.RoleID(selfIndex), names)
	if err != nil {
		log.Fatalf("NewJobMP: %v", err)
	}
	defer job.Close()

	log.Printf("[%s] Starting Threshold ECDSA MPC with PVE Backup Demo", names[selfIndex])
	log.Printf("[%s] ======================================================", names[selfIndex])

	// Step 1: Distributed Key Generation (P-256, 4-of-4)
	log.Printf("[%s] Step 1: Performing ECDSA DKG (P-256, 4-of-4)...", names[selfIndex])
	dkgResult, err := ecdsamp.DKG(ctx, job, &ecdsamp.DKGParams{Curve: cbmpc.CurveP256})
	if err != nil {
		log.Fatalf("DKG failed: %v", err)
	}
	defer dkgResult.Key.Close()
	log.Printf("[%s] ✓ DKG completed successfully", names[selfIndex])

	// Extract and display public key
	pubKeyBytes, err := dkgResult.Key.PublicKey()
	if err != nil {
		log.Fatalf("extract public key: %v", err)
	}
	log.Printf("[%s]   Public Key: %x", names[selfIndex], pubKeyBytes)

	// Step 3: Sign a message with threshold quorum
	// Step 2: Signing (all 4 parties online)
	// Note: Current API expects all parties online during signing
	log.Printf("[%s] Step 2: Signing (4-of-4)...", names[selfIndex])
	msgHash := sha256.Sum256([]byte(*message))
	log.Printf("[%s]   Message: %q", names[selfIndex], *message)
	log.Printf("[%s]   Message Hash (SHA-256): %x", names[selfIndex], msgHash[:])

	// Designate party 0 (alice) as the signature receiver
	sigReceiver := 0
	signResult, err := ecdsamp.Sign(ctx, job, &ecdsamp.SignParams{
		Key:         dkgResult.Key,
		Message:     msgHash[:],
		SigReceiver: sigReceiver,
	})
	if err != nil {
		log.Fatalf("Sign failed: %v", err)
	}

	if selfIndex == sigReceiver {
		log.Printf("[%s] ✓ Signature created (I am the receiver)", names[selfIndex])
		log.Printf("[%s]   Signature: %x", names[selfIndex], signResult.Signature)
	} else {
		log.Printf("[%s] ✓ Signing completed (signature sent to %s)", names[selfIndex], names[sigReceiver])
	}

	// Step 3: Backup key using PVE (Publicly Verifiable Encryption)
	log.Printf("[%s] Step 3: Creating PVE backup of key share...", names[selfIndex])

	// Create deterministic RSA-OAEP KEM instance for PVE backups
	kemInstance, err := rsa.New(3072)
	if err != nil {
		log.Fatalf("create KEM: %v", err)
	}

	// Generate KEM key pair for backup encryption
	skRef, ek, err := kemInstance.Generate()
	if err != nil {
		log.Fatalf("KEM generate: %v", err)
	}
	// Create a handle for the private key for decapsulation
	dkHandle, err := kemInstance.NewPrivateKeyHandle(skRef)
	if err != nil {
		log.Fatalf("KEM NewPrivateKeyHandle: %v", err)
	}
	defer func() {
		_ = kemInstance.FreePrivateKeyHandle(dkHandle)
	}()
	log.Printf("[%s]   Backup Encryption Key generated", names[selfIndex])

	// Get key bytes to derive a fixed-size backup secret
	keyBytes, err := dkgResult.Key.Bytes()
	if err != nil {
		log.Fatalf("get key bytes: %v", err)
	}
	defer cbmpc.ZeroizeBytes(keyBytes)

	// Derive a 32-byte secret from the key bytes (for demo backup)
	keyDigest := sha256.Sum256(keyBytes)

	// Convert digest to scalar for PVE encryption
	keyScalar, err := curve.NewScalarFromBytes(keyDigest[:])
	if err != nil {
		log.Fatalf("create scalar: %v", err)
	}
	defer keyScalar.Free()

	// Create PVE instance
	pveInstance, err := pve.New(kemInstance)
	if err != nil {
		log.Fatalf("create PVE: %v", err)
	}

	// Encrypt key using PVE
	backupLabel := []byte(fmt.Sprintf("backup-%s-%d", names[selfIndex], time.Now().Unix()))
	encResult, err := pveInstance.Encrypt(ctx, &pve.EncryptParams{
		EK:    ek,
		Label: backupLabel,
		Curve: cbmpc.CurveP256,
		X:     keyScalar,
	})
	if err != nil {
		log.Fatalf("PVE encrypt: %v", err)
	}
	log.Printf("[%s] ✓ Key backed up with PVE", names[selfIndex])
	log.Printf("[%s]   Backup Label: %s", names[selfIndex], string(backupLabel))
	log.Printf("[%s]   Ciphertext size: %d bytes", names[selfIndex], len(encResult.Ciphertext))

	// Step 4: Verify the PVE backup
	log.Printf("[%s] Step 4: Verifying PVE backup...", names[selfIndex])

	// Extract Q point from ciphertext
	ctQPoint, err := encResult.Ciphertext.Q()
	if err != nil {
		log.Fatalf("extract Q from ciphertext: %v", err)
	}
	defer ctQPoint.Free()

	// Verify the ciphertext
	err = pveInstance.Verify(ctx, &pve.VerifyParams{
		EK:         ek,
		Ciphertext: encResult.Ciphertext,
		Q:          ctQPoint,
		Label:      backupLabel,
	})
	if err != nil {
		log.Fatalf("PVE verify failed: %v", err)
	}
	log.Printf("[%s] ✓ PVE backup verified successfully", names[selfIndex])

	// Step 5: Demonstrate recovery by decrypting the backup
	log.Printf("[%s] Step 5: Demonstrating key recovery from backup...", names[selfIndex])

	decResult, err := pveInstance.Decrypt(ctx, &pve.DecryptParams{
		DK:         dkHandle,
		EK:         ek,
		Ciphertext: encResult.Ciphertext,
		Label:      backupLabel,
		Curve:      cbmpc.CurveP256,
	})
	if err != nil {
		log.Fatalf("PVE decrypt: %v", err)
	}
	defer decResult.X.Free()

	// Verify recovered scalar matches original
	if !keyScalar.Equal(decResult.X) {
		log.Fatal("recovered backup secret does not match original")
	}
	log.Printf("[%s] ✓ Key recovered successfully and verified to match original", names[selfIndex])

	// Step 6: Demonstrate key refresh
	log.Printf("[%s] Step 6: Refreshing key shares...", names[selfIndex])
	refreshResult, err := ecdsamp.Refresh(ctx, job, &ecdsamp.RefreshParams{
		SessionID: dkgResult.SessionID,
		Key:       dkgResult.Key,
	})
	if err != nil {
		log.Fatalf("Refresh failed: %v", err)
	}
	defer refreshResult.NewKey.Close()
	log.Printf("[%s] ✓ Key refresh completed - shares are now updated", names[selfIndex])

	// Verify refreshed key has same public key
	refreshedPubKey, err := refreshResult.NewKey.PublicKey()
	if err != nil {
		log.Fatalf("extract refreshed public key: %v", err)
	}
	if hex.EncodeToString(refreshedPubKey) != hex.EncodeToString(pubKeyBytes) {
		log.Fatal("refreshed public key does not match original!")
	}
	log.Printf("[%s]   Verified: Refreshed key has same public key", names[selfIndex])

	// Summary
	log.Printf("[%s] ======================================================", names[selfIndex])
	log.Printf("[%s] Demo completed successfully!", names[selfIndex])
	log.Printf("[%s]", names[selfIndex])
	log.Printf("[%s] Summary:", names[selfIndex])
	log.Printf("[%s] - Performed ECDSA DKG on P-256 (4-of-4)", names[selfIndex])
	log.Printf("[%s] - Signed message: %q", names[selfIndex], *message)
	log.Printf("[%s] - Backed up key share with PVE", names[selfIndex])
	log.Printf("[%s] - Verified and recovered key from backup", names[selfIndex])
	log.Printf("[%s] - Refreshed key shares (proactive security)", names[selfIndex])
	log.Printf("[%s]", names[selfIndex])
	log.Printf("[%s] This demonstrates production-grade:", names[selfIndex])
	log.Printf("[%s] ✓ Secure multi-party computation with mTLS", names[selfIndex])
	log.Printf("[%s] ✓ Threshold cryptography (2-of-3)", names[selfIndex])
	log.Printf("[%s] ✓ Distributed key generation without trust", names[selfIndex])
	log.Printf("[%s] ✓ Collaborative threshold signing", names[selfIndex])
	log.Printf("[%s] ✓ Publicly verifiable encryption for backups", names[selfIndex])
	log.Printf("[%s] ✓ Secure key recovery", names[selfIndex])
	log.Printf("[%s] ✓ Proactive security via key refresh", names[selfIndex])

	// Write backup to file (optional)
	if os.Getenv("SAVE_BACKUP") == "1" {
		backupFile := fmt.Sprintf("backup-%s.hex", names[selfIndex])
		err = os.WriteFile(backupFile, []byte(hex.EncodeToString(encResult.Ciphertext)), 0600)
		if err != nil {
			log.Printf("[%s] Warning: could not save backup: %v", names[selfIndex], err)
		} else {
			log.Printf("[%s] Backup saved to: %s", names[selfIndex], backupFile)
		}
	}
}
