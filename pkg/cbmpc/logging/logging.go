package logging

import (
	"context"
	"log/slog"
)

const redactedPlaceholder = "[redacted]"

// Logger defines the subset of slog functionality used by the cb-mpc wrapper.
// The interface is intentionally small so applications can provide their own
// implementation for testing or redaction policies.
type Logger interface {
	Debug(ctx context.Context, msg string, args ...any)
	Info(ctx context.Context, msg string, args ...any)
	Warn(ctx context.Context, msg string, args ...any)
	Error(ctx context.Context, msg string, args ...any)
	With(args ...any) Logger
}

// New returns a Logger backed by the provided slog.Logger. Passing nil binds to
// slog.Default().
func New(logger *slog.Logger) Logger {
	if logger == nil {
		logger = slog.Default()
	}
	return &slogLogger{logger: logger}
}

type slogLogger struct {
	logger *slog.Logger
}

func (l *slogLogger) Debug(ctx context.Context, msg string, args ...any) {
	l.logger.DebugContext(ctx, msg, args...)
}

func (l *slogLogger) Info(ctx context.Context, msg string, args ...any) {
	l.logger.InfoContext(ctx, msg, args...)
}

func (l *slogLogger) Warn(ctx context.Context, msg string, args ...any) {
	l.logger.WarnContext(ctx, msg, args...)
}

func (l *slogLogger) Error(ctx context.Context, msg string, args ...any) {
	l.logger.ErrorContext(ctx, msg, args...)
}

func (l *slogLogger) With(args ...any) Logger {
	return &slogLogger{logger: l.logger.With(args...)}
}

// Redacted marks attributes that contain sensitive information. Callers must
// avoid logging raw secrets; instead, include this attribute as a reminder that
// the value was intentionally removed.
func Redacted(key string) slog.Attr {
	return slog.String(key, redactedPlaceholder)
}

// Placeholder returns the canonical string that represents a redacted value.
func Placeholder() string {
	return redactedPlaceholder
}
