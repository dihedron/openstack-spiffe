package token

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
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/metadata/claims"
	"github.com/dihedron/openstack-spiffe/internal/metadata/keystore"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

const (
	testProjectID  = "f3c9a1d2b4e54a6b8c7d9e0f1a2b3c4d"
	testInstanceID = "8f7c1b6e-6a0e-4d4b-9a51-3f0e8b1d2c3a"
)

var testNow = time.Date(2026, 9, 29, 14, 32, 11, 0, time.UTC)

func validRequest() claims.NovaRequest {
	return claims.NovaRequest{
		ProjectID:  testProjectID,
		InstanceID: testInstanceID,
		Hostname:   "vm-01",
		Metadata:   map[string]any{"role": "web"},
	}
}

func newBuilder(t *testing.T, options ...claims.Option) *claims.Builder {
	t.Helper()
	options = append([]claims.Option{claims.WithClock(func() time.Time { return testNow })}, options...)
	b, err := claims.NewBuilder(options...)
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	return b
}

// fakeStore is a KeyStore whose active key and failures are set by the test.
type fakeStore struct {
	mu        sync.Mutex
	keys      map[string]crypto.Signer
	algorithm map[string]string
	active    string
	activeErr error
	signErr   error
	// onSign, if set, runs before every signature and may return an error
	// to fail it (e.g. to simulate a rotation between Active and Sign).
	onSign   func(kid string) error
	signs    int
	actives  int
	checkErr error
}

func newFakeStore() *fakeStore {
	return &fakeStore{keys: map[string]crypto.Signer{}, algorithm: map[string]string{}}
}

func (f *fakeStore) add(t *testing.T, kid, algorithm string) {
	t.Helper()
	var (
		signer crypto.Signer
		err    error
	)
	switch algorithm {
	case "ES256":
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[kid], f.algorithm[kid] = signer, algorithm
}

func (f *fakeStore) activate(kid string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.active = kid
}

func (f *fakeStore) Active(ctx context.Context) (keystore.KeyInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actives++
	if f.activeErr != nil {
		return keystore.KeyInfo{}, f.activeErr
	}
	return keystore.KeyInfo{ID: f.active, Algorithm: f.algorithm[f.active]}, nil
}

func (f *fakeStore) Sign(ctx context.Context, kid string, digest []byte) ([]byte, error) {
	f.mu.Lock()
	f.signs++
	onSign, signErr := f.onSign, f.signErr
	f.mu.Unlock()
	if onSign != nil {
		if err := onSign(kid); err != nil {
			return nil, err
		}
	}
	if signErr != nil {
		return nil, signErr
	}
	f.mu.Lock()
	signer, active := f.keys[kid], f.active
	f.mu.Unlock()
	if kid != active {
		return nil, fmt.Errorf("signing with key %q: %w", kid, keystore.ErrKeyNotActive)
	}
	switch k := signer.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(nil, k, crypto.SHA256, digest)
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, k, digest)
		if err != nil {
			return nil, err
		}
		signature := make([]byte, 64)
		r.FillBytes(signature[:32])
		s.FillBytes(signature[32:])
		return signature, nil
	}
	return nil, fmt.Errorf("unknown key %q", kid)
}

func (f *fakeStore) PublicKeys(ctx context.Context) ([]keystore.PublicKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var keys []keystore.PublicKey
	for kid, signer := range f.keys {
		keys = append(keys, keystore.PublicKey{ID: kid, Algorithm: f.algorithm[kid], Key: signer.Public()})
	}
	return keys, nil
}

func (f *fakeStore) Check(ctx context.Context) error { return f.checkErr }

// verify checks a compact JWS against the key store's published keys, the
// way a verifier selecting the key by kid would, and returns its header and
// claims.
func verify(t *testing.T, ks keystore.KeyStore, token string) (iid.Header, iid.Claims) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3", len(parts))
	}
	decode := func(s string) []byte {
		t.Helper()
		if strings.ContainsAny(s, "=+/") {
			t.Fatalf("segment %q is not unpadded base64url", s)
		}
		data, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("decoding segment: %v", err)
		}
		return data
	}

	var header iid.Header
	if err := json.Unmarshal(decode(parts[0]), &header); err != nil {
		t.Fatalf("decoding header: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(decode(parts[0]), &generic); err != nil {
		t.Fatalf("decoding header: %v", err)
	}
	if len(generic) != 3 {
		t.Fatalf("header has fields %v, want exactly alg, kid, typ", generic)
	}
	if header.Type != "JWT" {
		t.Fatalf("typ = %q, want JWT", header.Type)
	}

	keys, err := ks.PublicKeys(context.Background())
	if err != nil {
		t.Fatalf("PublicKeys: %v", err)
	}
	var key *keystore.PublicKey
	for i := range keys {
		if keys[i].ID == header.KeyID {
			key = &keys[i]
		}
	}
	if key == nil {
		t.Fatalf("kid %q is not published", header.KeyID)
	}
	if key.Algorithm != header.Algorithm {
		t.Fatalf("header alg %q, published key alg %q", header.Algorithm, key.Algorithm)
	}

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	signature := decode(parts[2])
	switch pub := key.Key.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature); err != nil {
			t.Fatalf("signature does not verify: %v", err)
		}
	case *ecdsa.PublicKey:
		r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
		if len(signature) != 64 || !ecdsa.Verify(pub, digest[:], r, s) {
			t.Fatal("signature does not verify")
		}
	default:
		t.Fatalf("unexpected key type %T", pub)
	}

	var c iid.Claims
	if err := json.Unmarshal(decode(parts[1]), &c); err != nil {
		t.Fatalf("decoding claims: %v", err)
	}
	return header, c
}

func TestMintedTokenVerifiesAgainstEphemeralStore(t *testing.T) {
	for _, alg := range []string{"RS256", "ES256"} {
		t.Run(alg, func(t *testing.T) {
			now := testNow
			ks, err := keystore.NewEphemeral(context.Background(), "signer-a", alg,
				keystore.WithClock(func() time.Time { return now }))
			if err != nil {
				t.Fatalf("NewEphemeral: %v", err)
			}
			now = now.Add(2 * time.Minute) // first key is active
			m, err := NewMinter(ks, newBuilder(t, claims.WithCustomClaims(map[string]string{"region": "eu-1"})))
			if err != nil {
				t.Fatalf("NewMinter: %v", err)
			}

			token, err := m.Mint(context.Background(), validRequest(), claims.Enrichment{})
			if err != nil {
				t.Fatalf("Mint: %v", err)
			}
			header, c := verify(t, ks, token)

			active, _ := ks.Active(context.Background())
			if header.KeyID != active.ID || header.Algorithm != alg {
				t.Fatalf("header = %+v, want kid %q, alg %q", header, active.ID, alg)
			}
			if c.Issuer != iid.Issuer || c.Audience != iid.Audience || c.Subject != testInstanceID ||
				c.ProjectID != testProjectID || c.InstanceID != testInstanceID || c.Hostname != "vm-01" ||
				c.Tags["role"] != "web" || c.Custom["region"] != "eu-1" {
				t.Fatalf("unexpected claims: %+v", c)
			}
			if c.IssuedAt != testNow.Unix() || c.Expiry-c.IssuedAt != int64(iid.TTL/time.Second) {
				t.Fatalf("unexpected validity: iat %d, exp %d", c.IssuedAt, c.Expiry)
			}
		})
	}
}

func TestKidFollowsActiveKeyAcrossRotation(t *testing.T) {
	ks := newFakeStore()
	ks.add(t, "2026-09-29-signer-a-key-100", "RS256")
	ks.add(t, "2026-09-30-signer-a-key-100", "ES256")
	ks.activate("2026-09-29-signer-a-key-100")
	m, err := NewMinter(ks, newBuilder(t))
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}

	before, err := m.Mint(context.Background(), validRequest(), claims.Enrichment{})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	ks.activate("2026-09-30-signer-a-key-100")
	after, err := m.Mint(context.Background(), validRequest(), claims.Enrichment{})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	if h, _ := verify(t, ks, before); h.KeyID != "2026-09-29-signer-a-key-100" || h.Algorithm != "RS256" {
		t.Fatalf("pre-rotation header = %+v", h)
	}
	if h, _ := verify(t, ks, after); h.KeyID != "2026-09-30-signer-a-key-100" || h.Algorithm != "ES256" {
		t.Fatalf("post-rotation header = %+v", h)
	}
}

func TestRotationBetweenActiveAndSignIsRetried(t *testing.T) {
	ks := newFakeStore()
	ks.add(t, "old", "RS256")
	ks.add(t, "new", "RS256")
	ks.activate("old")
	var once sync.Once
	ks.onSign = func(kid string) error {
		once.Do(func() { ks.activate("new") }) // rotation lands right after Active
		return nil
	}
	m, err := NewMinter(ks, newBuilder(t))
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}

	token, err := m.Mint(context.Background(), validRequest(), claims.Enrichment{})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if h, _ := verify(t, ks, token); h.KeyID != "new" {
		t.Fatalf("kid = %q, want the key active after the rotation", h.KeyID)
	}
	if ks.actives != 2 || ks.signs != 2 {
		t.Fatalf("Active called %d times, Sign %d times; want 2 each", ks.actives, ks.signs)
	}
}

func TestPersistentlyInactiveKeyGivesUp(t *testing.T) {
	ks := newFakeStore()
	ks.add(t, "k", "RS256")
	ks.activate("k")
	ks.signErr = fmt.Errorf("signing: %w", keystore.ErrKeyNotActive)
	m, err := NewMinter(ks, newBuilder(t))
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}

	token, err := m.Mint(context.Background(), validRequest(), claims.Enrichment{})
	if !errors.Is(err, ErrKeyStoreUnavailable) || token != "" {
		t.Fatalf("Mint = %q, %v; want no token and ErrKeyStoreUnavailable", token, err)
	}
	if ks.signs != 2 {
		t.Fatalf("Sign called %d times, want 2 (one retry)", ks.signs)
	}
}

func TestKeyStoreFailures(t *testing.T) {
	boom := errors.New("vault proxy unreachable")
	tests := []struct {
		name  string
		setup func(*fakeStore)
		cause error
	}{
		{"active fails", func(f *fakeStore) { f.activeErr = boom }, boom},
		{"no active key yet", func(f *fakeStore) { f.activeErr = fmt.Errorf("wait: %w", keystore.ErrNoActiveKey) }, keystore.ErrNoActiveKey},
		{"sign fails", func(f *fakeStore) { f.signErr = boom }, boom},
		{"sign cancelled", func(f *fakeStore) { f.signErr = context.Canceled }, context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks := newFakeStore()
			ks.add(t, "k", "RS256")
			ks.activate("k")
			tt.setup(ks)
			m, err := NewMinter(ks, newBuilder(t))
			if err != nil {
				t.Fatalf("NewMinter: %v", err)
			}

			token, err := m.Mint(context.Background(), validRequest(), claims.Enrichment{})
			if token != "" {
				t.Fatalf("got a token despite the failure: %q", token)
			}
			if !errors.Is(err, ErrKeyStoreUnavailable) || !errors.Is(err, tt.cause) {
				t.Fatalf("error %v should wrap both ErrKeyStoreUnavailable and %v", err, tt.cause)
			}
		})
	}
}

func TestUnsupportedAlgorithmRejected(t *testing.T) {
	ks := newFakeStore()
	ks.add(t, "k", "HS256")
	ks.activate("k")
	m, err := NewMinter(ks, newBuilder(t))
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	if token, err := m.Mint(context.Background(), validRequest(), claims.Enrichment{}); err == nil || token != "" {
		t.Fatalf("Mint = %q, %v; want an error", token, err)
	}
	if ks.signs != 0 {
		t.Fatal("Sign called for an unsupported algorithm")
	}
}

func TestInvalidRequestNeverReachesKeyStore(t *testing.T) {
	ks := newFakeStore()
	ks.add(t, "k", "RS256")
	ks.activate("k")
	m, err := NewMinter(ks, newBuilder(t))
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	req := validRequest()
	req.InstanceID = "not-a-uuid"

	token, err := m.Mint(context.Background(), req, claims.Enrichment{})
	if !errors.Is(err, claims.ErrInvalidRequest) || errors.Is(err, ErrKeyStoreUnavailable) || token != "" {
		t.Fatalf("Mint = %q, %v; want no token and ErrInvalidRequest only", token, err)
	}
	if ks.actives != 0 || ks.signs != 0 {
		t.Fatal("key store used for an invalid request")
	}
}

// reservedBuilder returns claims whose custom claims shadow a reserved name,
// which claims.Builder itself refuses to produce.
type reservedBuilder struct{ name string }

func (b reservedBuilder) Build(ctx context.Context, req claims.NovaRequest, enrichment claims.Enrichment) (iid.Claims, error) {
	return iid.Claims{
		Issuer: iid.Issuer, Audience: iid.Audience, Subject: req.InstanceID,
		ProjectID: req.ProjectID, InstanceID: req.InstanceID, Hostname: req.Hostname,
		Custom: map[string]string{b.name: "forged"},
	}, nil
}

func TestReservedCustomClaimsRejectedBeforeSigning(t *testing.T) {
	for _, name := range []string{"sub", iid.ClaimAvailabilityZone, ""} {
		t.Run(name, func(t *testing.T) {
			ks := newFakeStore()
			ks.add(t, "k", "RS256")
			ks.activate("k")
			m, err := NewMinter(ks, reservedBuilder{name: name})
			if err != nil {
				t.Fatalf("NewMinter: %v", err)
			}
			token, err := m.Mint(context.Background(), validRequest(), claims.Enrichment{})
			if !errors.Is(err, iid.ErrInvalidCustomClaim) || token != "" {
				t.Fatalf("Mint = %q, %v; want no token and ErrInvalidCustomClaim", token, err)
			}
			if ks.signs != 0 {
				t.Fatal("Sign called with reserved custom claims")
			}
		})
	}
}

// hugeBuilder returns claims whose tags push the token past
// iid.MaxTokenBytes, which claims.Builder itself never produces.
type hugeBuilder struct{}

func (hugeBuilder) Build(ctx context.Context, req claims.NovaRequest, enrichment claims.Enrichment) (iid.Claims, error) {
	return iid.Claims{
		Issuer: iid.Issuer, Audience: iid.Audience, Subject: req.InstanceID,
		ProjectID: req.ProjectID, InstanceID: req.InstanceID, Hostname: req.Hostname,
		Tags: map[string]string{"blob": strings.Repeat("x", iid.MaxTokenBytes)},
	}, nil
}

func TestOversizedTokenNotIssued(t *testing.T) {
	ks := newFakeStore()
	ks.add(t, "k", "RS256")
	ks.activate("k")
	m, err := NewMinter(ks, hugeBuilder{})
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	token, err := m.Mint(context.Background(), validRequest(), claims.Enrichment{})
	if !errors.Is(err, ErrTokenTooLarge) || errors.Is(err, ErrKeyStoreUnavailable) || token != "" {
		t.Fatalf("Mint = %d-byte token, %v; want no token and ErrTokenTooLarge", len(token), err)
	}
}

func TestTokenAtMaximumClaimSizesFitsTheLimit(t *testing.T) {
	// the largest claims the builder can produce: full tags and custom
	// claims caps, the longest hostname and every enrichment claim
	tags := map[string]any{}
	for i := 0; len(tags) < 200; i++ {
		tags[fmt.Sprintf("key-%03d", i)] = strings.Repeat(`"`, 40)
	}
	custom := map[string]string{}
	for i := 0; ; i++ {
		custom[fmt.Sprintf("c%02d", i)] = strings.Repeat("x", 100)
		if err := iid.ValidateCustomClaims(custom); err != nil {
			delete(custom, fmt.Sprintf("c%02d", i))
			break
		}
	}
	ks := newFakeStore()
	ks.add(t, "k", "RS256")
	ks.activate("k")
	m, err := NewMinter(ks, newBuilder(t, claims.WithCustomClaims(custom)))
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	req := validRequest()
	req.ProjectID = strings.Repeat("p", 64)
	req.Hostname = strings.Repeat("h", 255)
	req.Metadata = tags
	enrichment := claims.Enrichment{
		AvailabilityZone: strings.Repeat("z", 255), Flavor: strings.Repeat("f", 255), UserID: strings.Repeat("u", 64),
		ProjectName: strings.Repeat("n", 64), DomainID: strings.Repeat("d", 64),
	}
	token, err := m.Mint(context.Background(), req, enrichment)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if len(token) > iid.MaxTokenBytes/2 {
		t.Fatalf("largest token is %d bytes, want well below %d", len(token), iid.MaxTokenBytes)
	}
}

func TestDistinctTokensPerCall(t *testing.T) {
	ks := newFakeStore()
	ks.add(t, "k", "ES256")
	ks.activate("k")
	m, err := NewMinter(ks, newBuilder(t))
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	a, _ := m.Mint(context.Background(), validRequest(), claims.Enrichment{})
	b, _ := m.Mint(context.Background(), validRequest(), claims.Enrichment{})
	_, ca := verify(t, ks, a)
	_, cb := verify(t, ks, b)
	if ca.ID == cb.ID {
		t.Fatalf("two tokens share jti %q", ca.ID)
	}
}

func TestNewMinterRequiresDependencies(t *testing.T) {
	if _, err := NewMinter(nil, newBuilder(t)); err == nil {
		t.Fatal("accepted a nil key store")
	}
	if _, err := NewMinter(newFakeStore(), nil); err == nil {
		t.Fatal("accepted a nil claims builder")
	}
}

func TestEnrichmentClaimsAreSigned(t *testing.T) {
	ks := newFakeStore()
	ks.add(t, "k", "ES256")
	ks.activate("k")
	m, err := NewMinter(ks, newBuilder(t))
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	enrichment := claims.Enrichment{AvailabilityZone: "az-1", Flavor: "m1.small", UserID: "u1", ProjectName: "web", DomainID: "default"}
	token, err := m.Mint(context.Background(), validRequest(), enrichment)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	_, c := verify(t, ks, token)
	if c.AvailabilityZone != "az-1" || c.Flavor != "m1.small" || c.UserID != "u1" || c.ProjectName != "web" || c.DomainID != "default" {
		t.Fatalf("enrichment claims not in the token: %+v", c)
	}
	if len(c.Custom) != 0 {
		t.Fatalf("enrichment claims decoded as custom claims: %v", c.Custom)
	}
}
