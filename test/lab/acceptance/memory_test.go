//go:build lab

package acceptance

import (
	"strconv"
	"strings"
	"testing"
)

// TestMemoryProtection is MEM-1: the running signer is non-dumpable and its
// memory is locked into RAM; the units disable core dumps and lift the
// locked-memory limit for the signer (I-4).
func TestMemoryProtection(t *testing.T) {
	l := theLab
	for _, vm := range []string{"issuer-a", "issuer-b"} {
		t.Run(vm, func(t *testing.T) {
			pid := strings.TrimSpace(l.must(t, vm, "systemctl show -p MainPID --value openstack-spire-issuer"))
			if pid == "" || pid == "0" {
				t.Fatal("the signer is not running")
			}
			// a non-dumpable process's /proc files belong to root, although
			// it runs as openstack-spire-issuer
			if owner := strings.TrimSpace(l.must(t, vm, "sudo stat -c %U /proc/"+pid+"/environ")); owner != "root" {
				t.Errorf("/proc/%s/environ belongs to %s: the signer is dumpable", pid, owner)
			}
			locked := strings.Fields(l.must(t, vm, "sudo grep VmLck /proc/"+pid+"/status"))
			if len(locked) < 2 {
				t.Fatalf("no VmLck in the signer's status")
			}
			if kb, _ := strconv.Atoi(locked[1]); kb == 0 {
				t.Error("the signer's memory is not locked (VmLck 0 kB)")
			}
			for unit, want := range map[string]string{
				"openstack-spire-issuer":            "LimitCORE=0\nLimitMEMLOCK=infinity",
				"openstack-spire-issuer-aggregator": "LimitCORE=0",
			} {
				props := "LimitCORE"
				if strings.Contains(want, "MEMLOCK") {
					props += ",LimitMEMLOCK"
				}
				if got := strings.TrimSpace(l.must(t, vm, "systemctl show -p "+props+" "+unit)); got != want {
					t.Errorf("%s: %q, want %q", unit, got, want)
				}
			}
		})
	}
}
