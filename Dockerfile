FROM golang:1.25

ARG GOLANGCI_LINT_VERSION=v1.64.8

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        clang \
        ninja-build \
        pkg-config \
        python3 \
        perl \
        git \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN GOBIN=/usr/local/bin GOFLAGS=-mod=mod go install github.com/golangci/golangci-lint/cmd/golangci-lint@${GOLANGCI_LINT_VERSION}

WORKDIR /workspace

ENV GOCACHE=/workspace/build/.cache/go-build \
    GOMODCACHE=/workspace/build/.cache/go-mod \
    GOLANGCI_LINT_CACHE=/workspace/build/.cache/golangci

CMD ["bash"]
