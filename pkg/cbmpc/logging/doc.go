// Package logging provides a minimal logging facade for the cb-mpc wrapper.
//
// This package defines a Logger interface that wraps a subset of the standard
// library's log/slog functionality. The interface is intentionally small to
// allow applications to provide custom implementations for testing, redaction,
// or integration with existing logging systems.
//
// # Logger Interface
//
// The Logger interface provides context-aware logging methods:
//
//	type Logger interface {
//	    Debug(ctx context.Context, msg string, args ...any)
//	    Info(ctx context.Context, msg string, args ...any)
//	    Warn(ctx context.Context, msg string, args ...any)
//	    Error(ctx context.Context, msg string, args ...any)
//	    With(args ...any) Logger
//	}
//
// # Default Implementation
//
// The package provides a default slog-backed implementation:
//
//	import (
//	    "log/slog"
//	    "github.com/coinbase/cb-mpc-go/pkg/cbmpc/logging"
//	)
//
//	// Use default logger (slog.Default())
//	logger := logging.New(nil)
//
//	// Use custom slog.Logger
//	handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
//	    Level: slog.LevelDebug,
//	})
//	customLogger := logging.New(slog.New(handler))
//
// # Redaction Support
//
// The package provides utilities for redacting sensitive information:
//
//	// Mark an attribute as redacted
//	logger.Info(ctx, "key loaded", logging.Redacted("key_bytes"))
//	// Logs: key_bytes="[redacted]"
//
//	// Get the redaction placeholder
//	placeholder := logging.Placeholder() // Returns "[redacted]"
//
// # Usage in MPC Code
//
// Loggers can be passed to MPC protocol implementations for debugging
// and observability:
//
//	logger := logging.New(nil)
//	logger.Info(ctx, "starting DKG", "curve", "P256", "parties", 2)
//
//	// Log with redaction for sensitive data
//	logger.Debug(ctx, "generated scalar",
//	    logging.Redacted("scalar"),
//	    "curve", "P256",
//	)
//
// # Custom Implementations
//
// Applications can provide custom Logger implementations:
//
//	type customLogger struct {
//	    // ... your fields
//	}
//
//	func (l *customLogger) Debug(ctx context.Context, msg string, args ...any) {
//	    // Custom debug logic
//	}
//	// ... implement other methods
//
//	logger := &customLogger{}
//	// Use logger with MPC protocols
//
// # Security Considerations
//
//   - Never log private keys, key shares, or other sensitive cryptographic material
//   - Use logging.Redacted() to mark sensitive attributes
//   - Be cautious with message hashes and signatures (may leak information)
//   - Consider using structured logging for better auditability
//   - Ensure log storage is secure and access-controlled
package logging
