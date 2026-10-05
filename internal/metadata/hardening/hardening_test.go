//go:build linux

package hardening

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The checks run in a child process (this test binary, re-executed), so
// that the test process itself stays dumpable and unlocked.
const childEnv = "HARDENING_TEST_CHILD"

func TestMain(m *testing.M) {
	switch os.Getenv(childEnv) {
	case "":
		os.Exit(m.Run())
	case "non-dumpable":
		if err := SetNonDumpable(); err != nil {
			fmt.Println("error:", err)
			os.Exit(1)
		}
		dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		fmt.Println("dumpable:", dumpable, err)
	case "lock-low-limit":
		// lowering a limit needs no privilege
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: 8 << 20, Max: 8 << 20}); err != nil {
			fmt.Println("setrlimit:", err)
			os.Exit(1)
		}
		fmt.Println("lock:", LockMemory())
	case "lock-unlimited":
		fmt.Println("lock:", LockMemory())
		fmt.Println("locked kB:", lockedKB())
	}
	os.Exit(0)
}

func child(t *testing.T, mode string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), childEnv+"="+mode)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child %s: %v\n%s", mode, err, out)
	}
	return string(out)
}

func lockedKB() string {
	data, _ := os.ReadFile("/proc/self/status")
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmLck:") {
			return strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "VmLck:"), "kB"))
		}
	}
	return ""
}

func TestSetNonDumpable(t *testing.T) {
	if out := child(t, "non-dumpable"); !strings.Contains(out, "dumpable: 0 <nil>") {
		t.Fatalf("the process is still dumpable:\n%s", out)
	}
}

func TestLockMemoryFailsUnderALowLimit(t *testing.T) {
	out := child(t, "lock-low-limit")
	if !strings.Contains(out, "LimitMEMLOCK") || strings.Contains(out, "lock: <nil>") {
		t.Fatalf("locking under an 8 MiB limit: %s, want an error naming LimitMEMLOCK", out)
	}
}

func TestLockMemory(t *testing.T) {
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
		t.Fatal(err)
	}
	// the Go runtime's locked virtual size is about 1.3 GB
	if limit.Cur != unix.RLIM_INFINITY && limit.Cur < 4<<30 {
		t.Skipf("RLIMIT_MEMLOCK is %d bytes here; the lab checks locking under the packaged unit (MEM-1)", limit.Cur)
	}
	out := child(t, "lock-unlimited")
	if !strings.Contains(out, "lock: <nil>") || strings.Contains(out, "locked kB: 0\n") {
		t.Fatalf("locking with no limit:\n%s", out)
	}
}

func TestLockMemoryErrorIsWrapped(t *testing.T) {
	err := lockError(unix.ENOMEM)
	if !errors.Is(err, unix.ENOMEM) || !strings.Contains(err.Error(), "LimitMEMLOCK") {
		t.Fatalf("lockError = %v", err)
	}
}
