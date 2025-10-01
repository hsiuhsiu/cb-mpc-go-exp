.PHONY: help build test test-short clean deps examples force-build-cpp

# Marker file to track if C++ library is built
CPP_LIB := cb-mpc/lib/Release/libcbmpc.a
SUBMODULE_INIT := cb-mpc/.git

help:
	@echo "Available targets:"
	@echo "  deps         - Initialize git submodules"
	@echo "  build-cpp    - Build cb-mpc C++ library (only if needed)"
	@echo "  force-build-cpp - Force rebuild of C++ library"
	@echo "  build        - Build Go wrapper (builds C++ if needed)"
	@echo "  test         - Run Go tests (builds C++ if needed)"
	@echo "  test-short   - Run Go tests without checking C++ build"
	@echo "  examples     - Run example programs"
	@echo "  clean        - Clean Go build artifacts"
	@echo "  clean-all    - Clean everything including cb-mpc build"

# Initialize submodules if not already done
$(SUBMODULE_INIT):
	git submodule update --init --recursive

# Build C++ library only if it doesn't exist or is outdated
$(CPP_LIB): $(SUBMODULE_INIT)
	@echo "Building C++ library (this may take a few minutes)..."
	bash scripts/build_cpp.sh Release

# Convenience target that checks if rebuild is needed
build-cpp: $(CPP_LIB)
	@echo "✅ C++ library is up to date"

# Force rebuild of C++ library
force-build-cpp: $(SUBMODULE_INIT)
	@echo "Force rebuilding C++ library..."
	bash scripts/build_cpp.sh Release

# Build Go code (will build C++ if needed)
build: $(CPP_LIB)
	bash scripts/go_with_cpp.sh go build ./...

# Run tests (will build C++ if needed)
test: $(CPP_LIB)
	bash scripts/go_with_cpp.sh go test -v ./...

# Run tests without checking C++ build (fast)
test-short:
	bash scripts/go_with_cpp.sh go test -v -short ./...

examples: $(CPP_LIB)
	@echo "Running agree_random example..."
	bash scripts/go_with_cpp.sh go run examples/agree_random/main.go

clean:
	go clean ./...

clean-all: clean
	cd cb-mpc && make clean || true
	rm -rf cb-mpc/build cb-mpc/lib
