FROM golang:1.23-bullseye@sha256:161b8513c09cbfa4c174fd32e46eddc5eddf487a43958b9cf8b07d628e9e0f85

ARG GOLANGCI_LINT_VERSION=v1.64.8

RUN GOBIN=/usr/local/bin GOFLAGS=-mod=mod go install github.com/golangci/golangci-lint/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}

WORKDIR /workspace

CMD ["golangci-lint", "run", "./..."]
