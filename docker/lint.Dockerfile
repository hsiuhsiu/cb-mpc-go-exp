FROM golangci/golangci-lint:v1.58.1

WORKDIR /workspace

CMD ["golangci-lint", "run", "./..."]
