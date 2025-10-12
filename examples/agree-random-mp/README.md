# Multi-Party Agree Random over mTLS

Generate certificates once (creates material for `p0`, `p1`, `p2`):

```
scripts/run_example.sh run ./examples/tlsnet/cmd/gen-certs --output examples/agree-random-mp/certs --names p0,p1,p2
```

Launch each party in a separate terminal (add --timeout if desired):

```
scripts/run_example.sh run ./examples/agree-random-mp --self p0 --config examples/agree-random-mp/cluster.json --timeout 30s
scripts/run_example.sh run ./examples/agree-random-mp --self p1 --config examples/agree-random-mp/cluster.json --timeout 30s
scripts/run_example.sh run ./examples/agree-random-mp --self p2 --config examples/agree-random-mp/cluster.json --timeout 30s
```

All parties will print the identical random output produced by the protocol.
