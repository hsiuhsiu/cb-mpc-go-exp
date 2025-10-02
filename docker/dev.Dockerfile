FROM golang:1.22-bullseye

ARG GOLANGCI_LINT_VERSION=v1.58.1

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

RUN curl -sSfL https://github.com/golangci/golangci-lint/releases/download/${GOLANGCI_LINT_VERSION}/golangci-lint-${GOLANGCI_LINT_VERSION#v}-linux-amd64.tar.gz \
        -o /tmp/golangci.tar.gz \
    && tar -xzf /tmp/golangci.tar.gz -C /tmp \
    && mv /tmp/golangci-lint-${GOLANGCI_LINT_VERSION#v}-linux-amd64/golangci-lint /usr/local/bin/golangci-lint \
    && chmod +x /usr/local/bin/golangci-lint \
    && rm -rf /tmp/golangci.tar.gz /tmp/golangci-lint-${GOLANGCI_LINT_VERSION#v}-linux-amd64

WORKDIR /workspace

ENV GOCACHE=/workspace/build/.cache/go-build \
    GOMODCACHE=/workspace/build/.cache/go-mod \
    GOLANGCI_LINT_CACHE=/workspace/build/.cache/golangci

CMD ["bash"]
