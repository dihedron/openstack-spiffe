//go:build !linux

package hardening

import "errors"

var errUnsupported = errors.New("only supported on Linux")

// SetNonDumpable is only supported on Linux.
func SetNonDumpable() error { return errUnsupported }

// LockMemory is only supported on Linux.
func LockMemory() error { return errUnsupported }
