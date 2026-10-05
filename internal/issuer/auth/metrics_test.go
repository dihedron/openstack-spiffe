package auth

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/issuer/metrics"
	"github.com/dihedron/openstack-spiffe/internal/issuer/metrics/metricstest"
)

const validations = "openstack_spire.keystone.validations"

func TestValidationMetrics(t *testing.T) {
	m, r := metricstest.New(t, metrics.Config{})
	v := newValidator()
	a := newAuthenticator(t, v, &testClock{now: testNow}, WithMetrics(m))
	ctx := context.Background()

	_, _ = a.Authenticate(ctx, serviceToken)   // validated by Keystone
	_, _ = a.Authenticate(ctx, serviceToken)   // from the cache
	_, _ = a.Authenticate(ctx, arbitraryToken) // valid, but not allowlisted
	_, _ = a.Authenticate(ctx, "unknown")      // invalid
	_, _ = a.Authenticate(ctx, "")             // missing: no validation at all
	v.err = ErrUnavailable
	_, _ = a.Authenticate(ctx, "another") // Keystone failing

	for _, tt := range []struct {
		attrs []string
		want  int64
	}{
		{[]string{"result", metrics.ResultValid, "source", "backend"}, 1},
		{[]string{"result", metrics.ResultValid, "source", "cache"}, 1},
		{[]string{"result", metrics.ResultNotAllowed}, 1},
		{[]string{"result", metrics.ResultInvalid}, 1},
		{[]string{"result", metrics.ResultError}, 1},
		{nil, 5},
	} {
		if got := r.Value(t, validations, tt.attrs...); got != tt.want {
			t.Errorf("%v: %d, want %d", tt.attrs, got, tt.want)
		}
	}
	// the cache hit made no call to Keystone
	if got := r.Value(t, "openstack_spire.keystone.validation.duration"); got != 4 {
		t.Errorf("%d Keystone calls recorded, want 4", got)
	}
	if got := r.Value(t, "openstack_spire.keystone.validations.in_flight"); got != 0 {
		t.Errorf("%d validations still in flight", got)
	}
}

func TestMergedAndBusyMetrics(t *testing.T) {
	m, r := metricstest.New(t, metrics.Config{})
	v := newValidator()
	v.gate = make(chan struct{})
	v.identities["second"] = novaIdentity(time.Hour)
	a := newAuthenticator(t, v, &testClock{now: testNow}, WithMetrics(m), WithMaxConcurrentValidations(1))
	ctx := context.Background()

	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() { _, _ = a.Authenticate(ctx, serviceToken) })
	}
	for v.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	if got := r.Value(t, "openstack_spire.keystone.validations.in_flight"); got != 1 {
		t.Errorf("%d validations in flight, want 1", got)
	}
	_, _ = a.Authenticate(ctx, "second") // the only slot is taken
	time.Sleep(20 * time.Millisecond)
	close(v.gate)
	wg.Wait()

	if got := r.Value(t, validations, "source", "merged"); got != 2 {
		t.Errorf("%d merged validations, want 2", got)
	}
	if got := r.Value(t, validations, "result", metrics.ResultBusy); got != 1 {
		t.Errorf("%d busy validations, want 1", got)
	}
}

func TestMiddlewareReasons(t *testing.T) {
	m, r := metricstest.New(t, metrics.Config{})
	v := newValidator()
	a := newAuthenticator(t, v, &testClock{now: testNow})
	h, _ := protected(a)
	wrapped := m.AttestMiddleware(h)
	post(wrapped, "")
	post(wrapped, "unknown")
	post(wrapped, arbitraryToken)
	v.err = ErrUnavailable
	post(wrapped, "another")
	for reason, status := range map[string]string{
		metrics.ReasonUnauthenticated:     "401",
		metrics.ReasonCallerNotAllowed:    "403",
		metrics.ReasonKeystoneUnavailable: "503",
	} {
		if r.Value(t, "openstack_spire.attest.requests", "reason", reason, "http.response.status_code", status) == 0 {
			t.Errorf("no %s rejection with status %s", reason, status)
		}
	}
	if got := r.Value(t, "openstack_spire.attest.requests", "reason", metrics.ReasonUnauthenticated); got != 2 {
		t.Errorf("%d unauthenticated, want 2", got)
	}
}

func TestMiddlewareBusyReason(t *testing.T) {
	m, r := metricstest.New(t, metrics.Config{})
	v := newValidator()
	v.gate = make(chan struct{})
	v.identities["second"] = novaIdentity(time.Hour)
	a := newAuthenticator(t, v, &testClock{now: testNow}, WithMaxConcurrentValidations(1))
	h, _ := protected(a)
	wrapped := m.AttestMiddleware(h)
	done := make(chan struct{})
	go func() { post(wrapped, serviceToken); close(done) }()
	for v.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	if resp := post(wrapped, "second"); resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status %d with the slot taken, want 503", resp.StatusCode)
	}
	close(v.gate)
	<-done
	if r.Value(t, "openstack_spire.attest.requests", "reason", metrics.ReasonKeystoneBusy, "http.response.status_code", "503") != 1 {
		t.Error("no keystone_busy rejection")
	}
}
