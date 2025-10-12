# 2-Party Agree Random over mTLS

Generate certificates once:

```
scripts/run_example.sh run ./examples/tlsnet/cmd/gen-certs --output examples/agree-random-2p/certs --names p0,p1
```

Then launch each party in its own terminal (add --timeout if desired):

```
scripts/run_example.sh run ./examples/agree-random-2p --self p0 --config examples/agree-random-2p/cluster.json --timeout 30s
scripts/run_example.sh run ./examples/agree-random-2p --self p1 --config examples/agree-random-2p/cluster.json --timeout 30s
```

Each process prints the shared random output.
