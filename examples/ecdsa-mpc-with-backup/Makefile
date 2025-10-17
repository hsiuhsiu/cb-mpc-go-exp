.PHONY: certs clean run-alice run-bob run-charlie run-dave run help

# Default target
help:
	@echo "Threshold ECDSA MPC with Backup Example"
	@echo "========================================"
	@echo ""
	@echo "Available targets:"
	@echo "  make certs        - Generate TLS certificates for mTLS"
	@echo "  make run          - Show instructions for running parties"
	@echo "  make run-alice    - Run Alice's party"
	@echo "  make run-bob      - Run Bob's party"
	@echo "  make run-charlie  - Run Charlie's party"
	@echo "  make run-dave     - Run Dave's party"
	@echo "  make clean        - Remove certificates and backups"
	@echo ""
	@echo "Quick start:"
	@echo "  1. Run 'make certs' to generate certificates"
	@echo "  2. In terminal 1: make run-alice"
	@echo "  3. In terminal 2: make run-bob"
	@echo "  4. In terminal 3: make run-charlie"
	@echo "  5. In terminal 4: make run-dave"
	@echo ""

# Generate TLS certificates
certs:
	@if [ -f certs/rootCA.pem ]; then \
	  echo "Certificates already exist in certs/ (skipping)."; \
	  echo ""; \
	  echo "Existing files:"; \
	  ls -lh certs/; \
	  echo ""; \
	else \
	  echo "Generating TLS certificates for mTLS (4 parties)..."; \
	  mkdir -p certs; \
	  cd ../.. && scripts/run_with_go.sh run ./examples/tlsnet/cmd/gen-certs \
	    -names alice,bob,charlie,dave \
	    -output examples/ecdsa-mpc-with-backup/certs \
	    -localhost=true; \
	  echo "✓ Certificates generated in certs/"; \
	  echo ""; \
	  echo "Generated files:"; \
	  ls -lh certs/; \
	  echo ""; \
	fi

# Clean certificates and backups
clean:
	@echo "Cleaning certificates and backups..."
	@rm -rf certs/
	@rm -f backup-*.hex
	@echo "✓ Cleaned"

# Run Alice's party
run-alice: certs
	@echo "Starting Alice's party..."
	@cd ../.. && scripts/run_with_go.sh run ./examples/ecdsa-mpc-with-backup --self=alice --config=examples/ecdsa-mpc-with-backup/cluster.json

# Run Bob's party
run-bob: certs
	@echo "Starting Bob's party..."
	@cd ../.. && scripts/run_with_go.sh run ./examples/ecdsa-mpc-with-backup --self=bob --config=examples/ecdsa-mpc-with-backup/cluster.json

# Run Charlie's party
run-charlie: certs
	@echo "Starting Charlie's party..."
	@cd ../.. && scripts/run_with_go.sh run ./examples/ecdsa-mpc-with-backup --self=charlie --config=examples/ecdsa-mpc-with-backup/cluster.json

# Run Dave's party
run-dave: certs
	@echo "Starting Dave's party..."
	@cd ../.. && scripts/run_with_go.sh run ./examples/ecdsa-mpc-with-backup --self=dave --config=examples/ecdsa-mpc-with-backup/cluster.json


# Run all parties (requires terminal multiplexer or four terminals)
run: certs
	@echo "Run the following commands in separate terminals:"
	@echo ""
	@echo "  Terminal 1: make run-alice"
	@echo "  Terminal 2: make run-bob"
	@echo "  Terminal 3: make run-charlie"
	@echo "  Terminal 4: make run-dave"
	@echo ""

# Run with custom message
run-alice-custom: certs
	@echo "Starting Alice with custom message..."
	@cd ../.. && scripts/run_with_go.sh run ./examples/ecdsa-mpc-with-backup --self=alice --config=examples/ecdsa-mpc-with-backup/cluster.json --message="Custom test message"

run-bob-custom: certs
	@echo "Starting Bob with custom message..."
	@cd ../.. && scripts/run_with_go.sh run ./examples/ecdsa-mpc-with-backup --self=bob --config=examples/ecdsa-mpc-with-backup/cluster.json --message="Custom test message"

run-charlie-custom: certs
	@echo "Starting Charlie with custom message..."
	@cd ../.. && scripts/run_with_go.sh run ./examples/ecdsa-mpc-with-backup --self=charlie --config=examples/ecdsa-mpc-with-backup/cluster.json --message="Custom test message"

# Run with backup save enabled
run-alice-save: certs
	@echo "Starting Alice with backup save..."
	@cd ../.. && SAVE_BACKUP=1 scripts/run_with_go.sh run ./examples/ecdsa-mpc-with-backup --self=alice --config=examples/ecdsa-mpc-with-backup/cluster.json

run-bob-save: certs
	@echo "Starting Bob with backup save..."
	@cd ../.. && SAVE_BACKUP=1 scripts/run_with_go.sh run ./examples/ecdsa-mpc-with-backup --self=bob --config=examples/ecdsa-mpc-with-backup/cluster.json

run-charlie-save: certs
	@echo "Starting Charlie with backup save..."
	@cd ../.. && SAVE_BACKUP=1 scripts/run_with_go.sh run ./examples/ecdsa-mpc-with-backup --self=charlie --config=examples/ecdsa-mpc-with-backup/cluster.json
