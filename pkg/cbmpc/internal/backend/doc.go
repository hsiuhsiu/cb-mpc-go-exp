//go:build !windows

// Package backend hosts the thin cgo layer that links the Go API to the
// native cb-mpc library. The real implementation lives behind build tags so
// that the rest of the repository can compile without cgo.
package backend
