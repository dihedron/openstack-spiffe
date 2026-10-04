package openstackiid

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/metadata/keystore"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

const (
	testProjectID  = "f3c9a1d2b4e54a6b8c7d9e0f1a2b3c4d"
	testInstanceID = "8f7c1b6e-6a0e-4d4b-9a51-3f0e8b1d2c3a"
	testSkew       = 30 * time.Second
)

var testNow = time.Date(2026, 9, 29, 14, 32, 11, 0, time.UTC)

// signingKey is a test signing key with its kid.
type signingKey struct {
	kid    string
	alg    string
	signer crypto.Signer
}

var (
	keysOnce                sync.Once
	rsaKey, ecKey, otherKey *signingKey
)

// testKeys returns RSA and EC keys, generated once: RSA key generation is
// slow.
func testKeys(t *testing.T) (rs, es, other *signingKey) {
	t.Helper()
	keysOnce.Do(func() {
		r, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		e, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		o, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		rsaKey = &signingKey{"2026-09-29-signer-a-key-1", "RS256", r}
		ecKey = &signingKey{"2026-09-29-signer-b-key-1", "ES256", e}
		otherKey = &signingKey{"2026-09-29-rogue-key-1", "ES256", o}
	})
	return rsaKey, ecKey, otherKey
}

func (k *signingKey) public() keystore.PublicKey {
	return keystore.PublicKey{ID: k.kid, Algorithm: k.alg, Key: k.signer.Public()}
}

// lookupOf returns a KeyLookup holding the public halves of keys.
func lookupOf(keys ...*signingKey) KeyLookup {
	set := map[string]keystore.PublicKey{}
	for _, k := range keys {
		set[k.kid] = k.public()
	}
	return func(kid string) (keystore.PublicKey, bool) {
		k, ok := set[kid]
		return k, ok
	}
}

func validClaims() map[string]any {
	iat := testNow.Add(-10 * time.Second).Unix()
	return map[string]any{
		"iss": iid.Issuer, "aud": iid.Audience, "sub": testInstanceID,
		"iat": iat, "nbf": iat, "exp": iat + int64(iid.TTL/time.Second),
		"jti":        "5b1f0f3e-2f7a-4c1e-8d0a-6c2f9b7e4a11",
		"project_id": testProjectID, "instance_id": testInstanceID, "hostname": "vm-01",
		"tags": map[string]any{"role": "web", "url": "https://example.org:8443/"},
	}
}

func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// sign returns a compact JWS of claims signed with key, with the given
// header (alg, kid and typ default to the key's and "JWT").
func sign(t *testing.T, key *signingKey, header map[string]any, claims map[string]any) string {
	t.Helper()
	h := map[string]any{"alg": key.alg, "kid": key.kid, "typ": "JWT"}
	maps.Copy(h, header)
	input := b64(mustJSON(t, h)) + "." + b64(mustJSON(t, claims))
	digest := sha256.Sum256([]byte(input))
	var sig []byte
	var err error
	switch signer := key.signer.(type) {
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, signer, crypto.SHA256, digest[:])
	case *ecdsa.PrivateKey:
		return resign(t, key, input)
	}
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64(sig)
}

func with(claims map[string]any, changes map[string]any) map[string]any {
	c := maps.Clone(claims)
	for k, v := range changes {
		if v == nil {
			delete(c, k)
			continue
		}
		c[k] = v
	}
	return c
}

func TestVerifyAccepts(t *testing.T) {
	rs, es, _ := testKeys(t)
	for _, key := range []*signingKey{rs, es} {
		t.Run(key.alg, func(t *testing.T) {
			token := sign(t, key, nil, validClaims())
			header, c, err := Verify(token, lookupOf(rs, es), testNow, testSkew)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if header.KeyID != key.kid || c.InstanceID != testInstanceID || c.ProjectID != testProjectID || c.Tags["role"] != "web" {
				t.Fatalf("header %+v, claims %+v", header, c)
			}
		})
	}
}

func TestVerifyAcceptsUnknownClaims(t *testing.T) {
	_, es, _ := testKeys(t)
	token := sign(t, es, nil, with(validClaims(), map[string]any{
		"country": "italy", "future_number": 5, "future_object": map[string]any{"a": 1},
		"flavor": "m1.small",
	}))
	_, c, err := Verify(token, lookupOf(es), testNow, testSkew)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if c.Flavor != "m1.small" || c.Custom["country"] != "italy" {
		t.Fatalf("claims %+v", c)
	}
}

func TestVerifyAcceptsTokenWithoutTyp(t *testing.T) {
	_, es, _ := testKeys(t)
	h := map[string]any{"alg": es.alg, "kid": es.kid}
	input := b64(mustJSON(t, h)) + "." + b64(mustJSON(t, validClaims()))
	// re-sign without typ by building the token by hand
	token := resign(t, es, input)
	if _, _, err := Verify(token, lookupOf(es), testNow, testSkew); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// resign signs an arbitrary signing input with an EC key.
func resign(t *testing.T, key *signingKey, input string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key.signer.(*ecdsa.PrivateKey), digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}

func TestVerifyRejects(t *testing.T) {
	rs, es, other := testKeys(t)
	lookup := lookupOf(rs, es)
	valid := validClaims()
	iat := valid["iat"].(int64)
	ttl := int64(iid.TTL / time.Second)

	tamperedPayload := func() string {
		token := sign(t, es, nil, valid)
		parts := strings.Split(token, ".")
		parts[1] = b64(mustJSON(t, with(valid, map[string]any{"project_id": "someone-else"})))
		return strings.Join(parts, ".")
	}
	hmacToken := func() string {
		h := b64(mustJSON(t, map[string]any{"alg": "HS256", "kid": es.kid, "typ": "JWT"}))
		input := h + "." + b64(mustJSON(t, valid))
		// keyed with the public key's bytes: the classic algorithm confusion
		mac := hmac.New(sha256.New, []byte(es.kid))
		mac.Write([]byte(input))
		return input + "." + b64(mac.Sum(nil))
	}
	noneToken := func() string {
		h := b64(mustJSON(t, map[string]any{"alg": "none", "kid": es.kid, "typ": "JWT"}))
		return h + "." + b64(mustJSON(t, valid)) + "."
	}
	// a token signed by the EC key but claiming RS256 under the RSA kid
	algMismatch := func() string {
		h := b64(mustJSON(t, map[string]any{"alg": "ES256", "kid": rs.kid, "typ": "JWT"}))
		return resign(t, es, h+"."+b64(mustJSON(t, valid)))
	}

	tests := []struct {
		name  string
		token func() string
		want  error
	}{
		{"not compact", func() string { return "abc.def" }, ErrInvalidToken},
		{"too large", func() string { return strings.Repeat("a", iid.MaxTokenBytes+1) }, ErrInvalidToken},
		{"alg none", noneToken, ErrInvalidToken},
		{"alg HS256", hmacToken, ErrInvalidToken},
		{"alg differs from the JWK's", algMismatch, ErrInvalidToken},
		{"typ not JWT", func() string { return sign(t, es, map[string]any{"typ": "at+jwt"}, valid) }, ErrInvalidToken},
		{"crit header", func() string { return sign(t, es, map[string]any{"crit": []string{"exp"}}, valid) }, ErrInvalidToken},
		{"no kid", func() string { return sign(t, es, map[string]any{"kid": ""}, valid) }, ErrInvalidToken},
		{"unknown kid", func() string { return sign(t, other, nil, valid) }, ErrUnknownKID},
		{"key not in the set under a known kid", func() string { return sign(t, &signingKey{es.kid, "ES256", other.signer}, nil, valid) }, ErrInvalidToken},
		{"tampered payload", tamperedPayload, ErrInvalidToken},
		{"truncated signature", func() string { tok := sign(t, es, nil, valid); return tok[:len(tok)-4] }, ErrInvalidToken},
		{"wrong iss", func() string { return sign(t, es, nil, with(valid, map[string]any{"iss": "nova-vendordata-plugin"})) }, ErrInvalidToken},
		{"missing iss", func() string { return sign(t, es, nil, with(valid, map[string]any{"iss": nil})) }, ErrInvalidToken},
		{"wrong aud", func() string { return sign(t, es, nil, with(valid, map[string]any{"aud": "other-consumer"})) }, ErrInvalidToken},
		{"expired", func() string {
			return sign(t, es, nil, with(valid, map[string]any{"iat": iat - 600, "nbf": iat - 600, "exp": iat - 600 + ttl}))
		}, ErrInvalidToken},
		{"not yet valid", func() string {
			return sign(t, es, nil, with(valid, map[string]any{"iat": iat + 120, "nbf": iat + 120, "exp": iat + 120 + ttl}))
		}, ErrInvalidToken},
		{"lifetime over TTL", func() string { return sign(t, es, nil, with(valid, map[string]any{"exp": iat + ttl + 1})) }, ErrInvalidToken},
		{"nbf after iat", func() string { return sign(t, es, nil, with(valid, map[string]any{"nbf": iat + 1})) }, ErrInvalidToken},
		{"exp not after iat", func() string { return sign(t, es, nil, with(valid, map[string]any{"exp": iat})) }, ErrInvalidToken},
		{"sub differs from instance_id", func() string {
			return sign(t, es, nil, with(valid, map[string]any{"sub": "1f7c1b6e-6a0e-4d4b-9a51-3f0e8b1d2c3a"}))
		}, ErrInvalidToken},
		{"no jti", func() string { return sign(t, es, nil, with(valid, map[string]any{"jti": nil})) }, ErrInvalidToken},
		{"bad instance_id", func() string {
			up := strings.ToUpper(testInstanceID)
			return sign(t, es, nil, with(valid, map[string]any{"sub": up, "instance_id": up}))
		}, ErrInvalidToken},
		{"bad project_id", func() string { return sign(t, es, nil, with(valid, map[string]any{"project_id": "../other"})) }, ErrInvalidToken},
		{"bad hostname", func() string { return sign(t, es, nil, with(valid, map[string]any{"hostname": "vm\x00"})) }, ErrInvalidToken},
		{"non-string tag", func() string { return sign(t, es, nil, with(valid, map[string]any{"tags": map[string]any{"n": 1}})) }, ErrInvalidToken},
		{"tag key with ':'", func() string {
			return sign(t, es, nil, with(valid, map[string]any{"tags": map[string]any{"a:b": "c"}}))
		}, ErrInvalidToken},
		{"tags too large", func() string {
			return sign(t, es, nil, with(valid, map[string]any{"tags": map[string]any{"big": strings.Repeat("x", iid.MaxTagsBytes)}}))
		}, ErrInvalidToken},
		{"empty enrichment claim", func() string { return sign(t, es, nil, with(valid, map[string]any{"flavor": ""})) }, ErrInvalidToken},
		{"malformed kid", func() string { return sign(t, es, map[string]any{"kid": "../../jwks"}, valid) }, iid.ErrInvalidKeyID},
		{"kid with control characters", func() string { return sign(t, es, map[string]any{"kid": es.kid + "\n"}, valid) }, iid.ErrInvalidKeyID},
		{"kid over 128 bytes", func() string {
			return sign(t, es, map[string]any{"kid": "2026-09-29-signer-b-key-" + strings.Repeat("1", 105)}, valid)
		}, iid.ErrInvalidKeyID},
		{"tag key with a format character", func() string {
			return sign(t, es, nil, with(valid, map[string]any{"tags": map[string]any{"ro\u202ele": "web"}}))
		}, ErrInvalidToken},
		{"tag value with a format character", func() string {
			return sign(t, es, nil, with(valid, map[string]any{"tags": map[string]any{"role": "we\u200bb"}}))
		}, ErrInvalidToken},
		{"tag value with a control character", func() string {
			return sign(t, es, nil, with(valid, map[string]any{"tags": map[string]any{"role": "web\nlevel=ERROR"}}))
		}, ErrInvalidToken},
		{"enrichment claim with a format character", func() string {
			return sign(t, es, nil, with(valid, map[string]any{"availability_zone": "az\u202e-1"}))
		}, ErrInvalidToken},
		{"enrichment claim over 255 bytes", func() string {
			return sign(t, es, nil, with(valid, map[string]any{"project_name": strings.Repeat("p", 256)}))
		}, ErrInvalidToken},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Verify(tt.token(), lookup, testNow, testSkew)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Verify error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestVerifyMalformedKIDNeverLookedUp(t *testing.T) {
	_, es, _ := testKeys(t)
	looked := false
	lookup := func(kid string) (keystore.PublicKey, bool) {
		looked = true
		return keystore.PublicKey{}, false
	}
	const kid = "attacker\x1b[31m-controlled"
	_, _, err := Verify(sign(t, es, map[string]any{"kid": kid}, validClaims()), lookup, testNow, testSkew)
	switch {
	case !errors.Is(err, iid.ErrInvalidKeyID) || !errors.Is(err, ErrInvalidToken):
		t.Fatalf("Verify error = %v, want ErrInvalidToken and iid.ErrInvalidKeyID", err)
	case errors.Is(err, ErrUnknownKID):
		t.Fatal("a malformed kid is reported as unknown, which triggers a JWK Set re-fetch")
	case looked:
		t.Fatal("a malformed kid was looked up")
	case strings.Contains(err.Error(), "attacker"):
		t.Fatalf("error %q contains the kid", err)
	}
}

func TestVerifyAcceptsValidCharacters(t *testing.T) {
	rs, _, _ := testKeys(t)
	claims := with(validClaims(), map[string]any{
		"tags":         map[string]any{"rôle": "wéb server", "empty": ""},
		"project_name": "prøject",
	})
	if _, _, err := Verify(sign(t, rs, nil, claims), lookupOf(rs), testNow, testSkew); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyClockSkew(t *testing.T) {
	_, es, _ := testKeys(t)
	ttl := int64(iid.TTL / time.Second)
	skew := int64(testSkew / time.Second)
	now := testNow.Unix()
	tests := []struct {
		name string
		iat  int64
		ok   bool
	}{
		{"issued at the future edge of the tolerance", now + skew, true},
		{"issued just beyond the tolerance", now + skew + 1, false},
		{"expiring at the past edge of the tolerance", now - ttl - skew + 1, true},
		{"expired beyond the tolerance", now - ttl - skew, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := sign(t, es, nil, with(validClaims(), map[string]any{"iat": tt.iat, "nbf": tt.iat, "exp": tt.iat + ttl}))
			_, _, err := Verify(token, lookupOf(es), testNow, testSkew)
			if tt.ok != (err == nil) {
				t.Fatalf("Verify error = %v, want ok=%v", err, tt.ok)
			}
		})
	}
	// the tolerance never stretches the lifetime itself
	token := sign(t, es, nil, with(validClaims(), map[string]any{"iat": now, "nbf": now, "exp": now + ttl + 1}))
	if _, _, err := Verify(token, lookupOf(es), testNow, time.Minute); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("lifetime over TTL accepted with a tolerance: %v", err)
	}
}

func TestSPIFFEIDAndSelectors(t *testing.T) {
	c := iid.Claims{
		ProjectID: testProjectID, InstanceID: testInstanceID, Hostname: "web-03",
		Tags: map[string]string{"role": "jboss", "url": "https://example.org:8443/x", "env": "prod"},
	}
	if got, want := SPIFFEID("example.org", c), "spiffe://example.org/spire/agent/openstack_iid/"+testProjectID+"/"+testInstanceID; got != want {
		t.Fatalf("SPIFFEID = %q, want %q", got, want)
	}
	want := []string{
		"project_id:" + testProjectID,
		"instance_id:" + testInstanceID,
		"hostname:web-03",
		"tag:env:prod",
		"tag:role:jboss",
		"tag:url:https://example.org:8443/x",
	}
	if got := Selectors(c); !slices.Equal(got, want) {
		t.Fatalf("Selectors = %v, want %v", got, want)
	}

	c.AvailabilityZone, c.Flavor, c.UserID, c.ProjectName, c.DomainID = "az-1", "m1.large", "9f8e", "billing", "default"
	c.Custom = map[string]string{"country": "italy"}
	want = append(want,
		"availability_zone:az-1", "flavor:m1.large", "user_id:9f8e", "project_name:billing", "domain_id:default")
	if got := Selectors(c); !slices.Equal(got, want) {
		t.Fatalf("Selectors with enrichment = %v, want %v (custom claims never become selectors)", got, want)
	}
}
