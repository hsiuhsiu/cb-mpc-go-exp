# Multi-Party Agree Random over mTLS

Generate certificates once (creates material for `p0`, `p1`, `p2`):

```bash
# From repository root
scripts/run_with_go.sh run examples/tlsnet/cmd/gen-certs/main.go \
  --output examples/agree-random-mp/certs \
  --names p0,p1,p2 \
  --localhost
```

Launch each party in a separate terminal (start within 10 seconds of each other):

**Terminal 1:**
```bash
# From repository root
scripts/run_with_go.sh run examples/agree-random-mp/main.go \
  --self p0 \
  --config examples/agree-random-mp/cluster.json
```

**Terminal 2:**
```bash
# From repository root
scripts/run_with_go.sh run examples/agree-random-mp/main.go \
  --self p1 \
  --config examples/agree-random-mp/cluster.json
```

**Terminal 3:**
```bash
# From repository root
scripts/run_with_go.sh run examples/agree-random-mp/main.go \
  --self p2 \
  --config examples/agree-random-mp/cluster.json
```

All parties will print the identical random output produced by the protocol.
