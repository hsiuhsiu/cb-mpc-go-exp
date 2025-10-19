# 2-Party Agree Random over mTLS

Generate certificates once:

```bash
# From repository root
scripts/run_with_go.sh run examples/tlsnet/cmd/gen-certs/main.go \
  --output examples/agree-random-2p/certs \
  --names p0,p1 \
  --localhost
```

Then launch each party in its own terminal (start within 10 seconds of each other):

**Terminal 1:**
```bash
# From repository root
scripts/run_with_go.sh run examples/agree-random-2p/main.go \
  --self p0 \
  --config examples/agree-random-2p/cluster.json
```

**Terminal 2:**
```bash
# From repository root
scripts/run_with_go.sh run examples/agree-random-2p/main.go \
  --self p1 \
  --config examples/agree-random-2p/cluster.json
```

Each process prints the shared random output.
