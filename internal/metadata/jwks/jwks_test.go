package jwks

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"io"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/metadata/keystore"
)

// fakeSource is a KeySource whose keys and failure are set by the test.
type fakeSource struct {
	mu   sync.Mutex
	keys []keystore.PublicKey
	err  error
}

func (f *fakeSource) PublicKeys(ctx context.Context) ([]keystore.PublicKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.keys), f.err
}

func (f *fakeSource) set(keys ...keystore.PublicKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys = keys
}

func rsaKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	return k
}

func ecKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generating EC key: %v", err)
	}
	return k
}

func get(t *testing.T, h http.Handler, method string) *http.Response {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, "/.well-known/jwks.json", nil))
	return rec.Result()
}

func decodeSet(t *testing.T, resp *http.Response) (Set, []map[string]any) {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	var set Set
	if err := json.Unmarshal(body, &set); err != nil {
		t.Fatalf("decoding set %s: %v", body, err)
	}
	var generic struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &generic); err != nil {
		t.Fatalf("decoding set: %v", err)
	}
	return set, generic.Keys
}

func TestServesEveryKeyAsRFC7517Set(t *testing.T) {
	rsaPriv, ecPriv := rsaKey(t, 2048), ecKey(t, elliptic.P256())
	source := &fakeSource{}
	source.set(
		keystore.PublicKey{ID: "2026-09-29-signer-a-key-100", Algorithm: "RS256", Key: rsaPriv.Public()},
		keystore.PublicKey{ID: "2026-09-29-signer-a-key-200", Algorithm: "ES256", Key: ecPriv.Public()},
	)
	h, err := NewHandler(source)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	resp := get(t, h, http.MethodGet)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type %q, want application/json", ct)
	}
	if nosniff := resp.Header.Get("X-Content-Type-Options"); nosniff != "nosniff" {
		t.Fatalf("X-Content-Type-Options %q, want nosniff", nosniff)
	}
	set, generic := decodeSet(t, resp)
	if len(set.Keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(set.Keys))
	}

	// exactly the public members, nothing else
	wantMembers := map[string][]string{
		"RSA": {"alg", "e", "kid", "kty", "n", "use"},
		"EC":  {"alg", "crv", "kid", "kty", "use", "x", "y"},
	}
	for _, m := range generic {
		kty, _ := m["kty"].(string)
		if got := slices.Sorted(maps.Keys(m)); !slices.Equal(got, wantMembers[kty]) {
			t.Fatalf("%s key has members %v, want %v", kty, got, wantMembers[kty])
		}
		if m["use"] != "sig" {
			t.Fatalf("use = %v, want sig", m["use"])
		}
	}

	r, e := set.Keys[0], set.Keys[1]
	if r.KeyID != "2026-09-29-signer-a-key-100" || r.KeyType != "RSA" || r.Algorithm != "RS256" {
		t.Fatalf("unexpected RSA key: %+v", r)
	}
	if e.KeyID != "2026-09-29-signer-a-key-200" || e.KeyType != "EC" || e.Algorithm != "ES256" || e.Curve != "P-256" {
		t.Fatalf("unexpected EC key: %+v", e)
	}
	if r.Exponent != "AQAB" {
		t.Fatalf("e = %q, want AQAB (65537)", r.Exponent)
	}
	for _, s := range []string{r.Modulus, r.Exponent, e.X, e.Y} {
		if strings.ContainsAny(s, "=+/") {
			t.Fatalf("%q is not unpadded base64url", s)
		}
	}
	if x, _ := base64.RawURLEncoding.DecodeString(e.X); len(x) != 32 {
		t.Fatalf("x is %d bytes, want 32", len(x))
	}
}

func TestEmptySetIsAnEmptyArray(t *testing.T) {
	h, err := NewHandler(&fakeSource{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	body, _ := io.ReadAll(get(t, h, http.MethodGet).Body)
	if got := strings.TrimSpace(string(body)); got != `{"keys":[]}` {
		t.Fatalf("body %s, want {\"keys\":[]}", got)
	}
}

func TestContentIsReadLive(t *testing.T) {
	source := &fakeSource{}
	source.set(keystore.PublicKey{ID: "old", Algorithm: "ES256", Key: ecKey(t, elliptic.P256()).Public()})
	h, err := NewHandler(source)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	if set, _ := decodeSet(t, get(t, h, http.MethodGet)); len(set.Keys) != 1 || set.Keys[0].KeyID != "old" {
		t.Fatalf("unexpected set: %+v", set)
	}

	source.set(keystore.PublicKey{ID: "new", Algorithm: "ES256", Key: ecKey(t, elliptic.P256()).Public()})
	if set, _ := decodeSet(t, get(t, h, http.MethodGet)); len(set.Keys) != 1 || set.Keys[0].KeyID != "new" {
		t.Fatalf("rotation not reflected: %+v", set)
	}
}

func TestCacheControl(t *testing.T) {
	source := &fakeSource{}
	replica, err := NewHandler(source)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	if cc := get(t, replica, http.MethodGet).Header.Get("Cache-Control"); cc != "no-cache" {
		t.Fatalf("default Cache-Control %q, want no-cache", cc)
	}

	aggregator, err := NewHandler(source, WithMaxAge(30*time.Second))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	if cc := get(t, aggregator, http.MethodGet).Header.Get("Cache-Control"); cc != "public, max-age=30" {
		t.Fatalf("Cache-Control %q, want public, max-age=30", cc)
	}

	zero, err := NewHandler(source, WithMaxAge(0))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	if cc := get(t, zero, http.MethodGet).Header.Get("Cache-Control"); cc != "no-cache" {
		t.Fatalf("zero max-age Cache-Control %q, want no-cache", cc)
	}

	if _, err := NewHandler(source, WithMaxAge(-time.Second)); err == nil {
		t.Fatal("accepted a negative max-age")
	}
	if _, err := NewHandler(source, WithMaxAge(1500*time.Millisecond)); err == nil {
		t.Fatal("accepted a max-age that is not a whole number of seconds")
	}
}

func TestHeadHasHeadersButNoBody(t *testing.T) {
	source := &fakeSource{}
	source.set(keystore.PublicKey{ID: "k", Algorithm: "ES256", Key: ecKey(t, elliptic.P256()).Public()})
	h, _ := NewHandler(source)
	resp := get(t, h, http.MethodHead)
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || len(body) != 0 || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("HEAD: status %d, %d body bytes, headers %v", resp.StatusCode, len(body), resp.Header)
	}
}

func TestOtherMethodsNotAllowed(t *testing.T) {
	h, _ := NewHandler(&fakeSource{})
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		resp := get(t, h, method)
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("%s: status %d, want 405", method, resp.StatusCode)
		}
		if allow := resp.Header.Get("Allow"); allow != "GET, HEAD" {
			t.Fatalf("%s: Allow %q, want GET, HEAD", method, allow)
		}
	}
}

func TestSourceFailureIs503(t *testing.T) {
	source := &fakeSource{err: errors.New("vault proxy 10.0.0.7 unreachable")}
	h, _ := NewHandler(source, WithMaxAge(30*time.Second))
	resp := get(t, h, http.MethodGet)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("error response Cache-Control %q, want no-store", cc)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "10.0.0.7") {
		t.Fatalf("error details leaked to the client: %s", body)
	}
}

func TestUnencodableKeyIs500(t *testing.T) {
	source := &fakeSource{}
	source.set(keystore.PublicKey{ID: "k", Algorithm: "RS256", Key: ecKey(t, elliptic.P256()).Public()})
	h, _ := NewHandler(source)
	if resp := get(t, h, http.MethodGet); resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", resp.StatusCode)
	}
}

func TestNewHandlerRequiresSource(t *testing.T) {
	if _, err := NewHandler(nil); err == nil {
		t.Fatal("accepted a nil key source")
	}
}

func TestRoundTrip(t *testing.T) {
	keys := []keystore.PublicKey{
		{ID: "r", Algorithm: "RS256", Key: rsaKey(t, 2048).Public()},
		{ID: "e", Algorithm: "ES256", Key: ecKey(t, elliptic.P256()).Public()},
	}
	for _, want := range keys {
		k, err := FromPublicKey(want)
		if err != nil {
			t.Fatalf("FromPublicKey(%s): %v", want.ID, err)
		}
		got, err := k.PublicKey()
		if err != nil {
			t.Fatalf("PublicKey(%s): %v", want.ID, err)
		}
		type equaler interface{ Equal(crypto.PublicKey) bool }
		if got.ID != want.ID || got.Algorithm != want.Algorithm || !want.Key.(equaler).Equal(got.Key) {
			t.Fatalf("round trip of %s changed the key", want.ID)
		}
	}
}

func TestFromPublicKeyRejectsMismatches(t *testing.T) {
	rsaPub, ecPub := rsaKey(t, 2048).Public(), ecKey(t, elliptic.P256()).Public()
	tests := []struct {
		name string
		key  keystore.PublicKey
	}{
		{"empty kid", keystore.PublicKey{Algorithm: "RS256", Key: rsaPub}},
		{"RS256 with EC key", keystore.PublicKey{ID: "k", Algorithm: "RS256", Key: ecPub}},
		{"ES256 with RSA key", keystore.PublicKey{ID: "k", Algorithm: "ES256", Key: rsaPub}},
		{"unknown algorithm", keystore.PublicKey{ID: "k", Algorithm: "PS256", Key: rsaPub}},
		{"small RSA key", keystore.PublicKey{ID: "k", Algorithm: "RS256", Key: rsaKey(t, 1024).Public()}},
		{"P-384 key", keystore.PublicKey{ID: "k", Algorithm: "ES256", Key: ecKey(t, elliptic.P384()).Public()}},
		{"private key", keystore.PublicKey{ID: "k", Algorithm: "ES256", Key: ecKey(t, elliptic.P256())}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := FromPublicKey(tt.key); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestPublicKeyValidation(t *testing.T) {
	validRSA, err := FromPublicKey(keystore.PublicKey{ID: "r", Algorithm: "RS256", Key: rsaKey(t, 2048).Public()})
	if err != nil {
		t.Fatal(err)
	}
	validEC, err := FromPublicKey(keystore.PublicKey{ID: "e", Algorithm: "ES256", Key: ecKey(t, elliptic.P256()).Public()})
	if err != nil {
		t.Fatal(err)
	}
	small, _ := FromPublicKey(keystore.PublicKey{ID: "s", Algorithm: "RS256", Key: rsaKey(t, 2048).Public()})
	small.Modulus = base64.RawURLEncoding.EncodeToString(rsaKey(t, 1024).N.Bytes())
	p384 := ecKey(t, elliptic.P384()).PublicKey
	p384Bytes, _ := p384.Bytes()

	tests := []struct {
		name   string
		mutate func(*Key)
		base   Key
	}{
		{"empty kid", func(k *Key) { k.KeyID = "" }, validRSA},
		{"use enc", func(k *Key) { k.Use = "enc" }, validRSA},
		{"missing use", func(k *Key) { k.Use = "" }, validRSA},
		{"alg mismatch", func(k *Key) { k.Algorithm = "ES256" }, validRSA},
		{"unknown alg", func(k *Key) { k.Algorithm = "none" }, validRSA},
		{"unknown kty", func(k *Key) { k.KeyType = "oct" }, validRSA},
		{"small modulus", func(k *Key) {}, small},
		{"bad modulus encoding", func(k *Key) { k.Modulus = "not base64!" }, validRSA},
		{"even exponent", func(k *Key) { k.Exponent = base64.RawURLEncoding.EncodeToString([]byte{2}) }, validRSA},
		{"exponent 1", func(k *Key) { k.Exponent = "AQ" }, validRSA},
		{"huge exponent", func(k *Key) { k.Exponent = base64.RawURLEncoding.EncodeToString(big.NewInt(1<<40 + 1).Bytes()) }, validRSA},
		{"wrong curve name", func(k *Key) { k.Curve = "P-384" }, validEC},
		{"point on another curve", func(k *Key) {
			k.X = base64.RawURLEncoding.EncodeToString(p384Bytes[1:49])
			k.Y = base64.RawURLEncoding.EncodeToString(p384Bytes[49:])
		}, validEC},
		{"point not on curve", func(k *Key) { k.Y = k.X }, validEC},
		{"short coordinate", func(k *Key) { k.X = base64.RawURLEncoding.EncodeToString(make([]byte, 31)) }, validEC},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := tt.base
			tt.mutate(&k)
			if _, err := k.PublicKey(); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// TestEphemeralSignatureVerifiesWithServedKey is the replica's end-to-end
// check: a signature from the key store verifies with the key a client reads
// from the handler, selected by kid.
func TestEphemeralSignatureVerifiesWithServedKey(t *testing.T) {
	for _, alg := range []string{"RS256", "ES256"} {
		t.Run(alg, func(t *testing.T) {
			now := time.Date(2026, 9, 29, 14, 32, 11, 0, time.UTC)
			ks, err := keystore.NewEphemeral(context.Background(), "signer-a", alg,
				keystore.WithClock(func() time.Time { return now }))
			if err != nil {
				t.Fatalf("NewEphemeral: %v", err)
			}
			now = now.Add(2 * time.Minute)
			h, err := NewHandler(ks)
			if err != nil {
				t.Fatalf("NewHandler: %v", err)
			}

			active, err := ks.Active(context.Background())
			if err != nil {
				t.Fatalf("Active: %v", err)
			}
			digest := sha256.Sum256([]byte("header.payload"))
			signature, err := ks.Sign(context.Background(), active.ID, digest[:])
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			set, _ := decodeSet(t, get(t, h, http.MethodGet))
			i := slices.IndexFunc(set.Keys, func(k Key) bool { return k.KeyID == active.ID })
			if i < 0 {
				t.Fatalf("active kid %q not served", active.ID)
			}
			pub, err := set.Keys[i].PublicKey()
			if err != nil {
				t.Fatalf("PublicKey: %v", err)
			}
			switch k := pub.Key.(type) {
			case *rsa.PublicKey:
				if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], signature); err != nil {
					t.Fatalf("signature does not verify: %v", err)
				}
			case *ecdsa.PublicKey:
				r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
				if !ecdsa.Verify(k, digest[:], r, s) {
					t.Fatal("signature does not verify")
				}
			}
		})
	}
}
