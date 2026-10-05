//go:build linux

// Package hardening protects the signer's private keys in process memory
// (I-4, I-5): the process is made non-dumpable, and its memory is locked so
// that no page holding a key, or a temporary of a signature, is ever
// written to swap. See "Memory protection" in the issuer spec.
package hardening

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// SetNonDumpable marks the process non-dumpable: no core dump, and no
// ptrace or /proc/<pid>/mem access by other processes of the same user.
func SetNonDumpable() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("marking the process non-dumpable: %w", err)
	}
	return nil
}

// LockMemory locks every page the process maps, now and later, into RAM:
// keys, but also the copies Go's crypto makes of them while signing, which
// the program cannot place itself. Pages are locked as they are first
// touched (MCL_ONFAULT), so the process uses only the memory it needs. The
// kernel counts the locked virtual size, which the Go runtime makes large
// (about 1.3 GB): RLIMIT_MEMLOCK must be unlimited (LimitMEMLOCK=infinity
// in the systemd unit, which needs no capability).
func LockMemory() error {
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE | unix.MCL_ONFAULT); err != nil {
		return lockError(err)
	}
	return nil
}

func lockError(err error) error {
	hint := ""
	if errors.Is(err, unix.ENOMEM) || errors.Is(err, unix.EPERM) {
		hint = ": raise the locked-memory limit (LimitMEMLOCK=infinity in the systemd unit, as the package's has), or set key_store.lock_memory to false on a host without swap"
	}
	return fmt.Errorf("locking the process memory: %w%s", err, hint)
}
