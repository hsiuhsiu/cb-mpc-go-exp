# Supported Platforms

| Operating System | Architectures        | Status            |
| ---------------- | -------------------- | ----------------- |
| Linux            | amd64                | Supported         |
| macOS (Darwin)   | amd64, arm64 (Apple) | Supported         |
| Windows          | n/a                  | Unsupported (TBD) |

Linux/amd64 underpins our CI runs and the published Docker images. macOS (both Intel and Apple Silicon) is supported for native development; the scripts auto-detect the host CPU and build matching artifacts.

Windows is currently unsupported. We welcome issue reports describing blocking gaps, but there is no official tooling or CI coverage yet.
