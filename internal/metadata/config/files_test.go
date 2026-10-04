package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

var fileCheckNow = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

// writeKeyPair writes a self-signed certificate valid until notAfter and its
// key (with the given permissions) into dir.
func writeKeyPair(t *testing.T, dir, name string, notAfter time.Time, keyPerm os.FileMode) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    fileCheckNow.Add(-24 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{name},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), keyPerm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, keyPerm); err != nil { // umask may have narrowed it
		t.Fatal(err)
	}
	return certPath, keyPath
}

func fileCheckOptions() CheckOptions {
	return CheckOptions{
		Hostname: func() (string, error) { return "ci-runner", nil },
		Now:      func() time.Time { return fileCheckNow },
	}
}

func signerDoc(certPath, keyPath, caPath string) string {
	doc := "tls_cert_path: " + certPath + "\ntls_key_path: " + keyPath + "\nreplica_id: a\n" +
		"tags:\n  allowlist: [role]\nkeystone:\n  allowed_users: [nova@Default]\n"
	if caPath != "" {
		doc += "  ca_cert_path: " + caPath + "\n"
	}
	return doc
}

func fileFindings(findings []Finding) []findingKey {
	var keys []findingKey
	for _, f := range findings {
		if f.Kind == KindFile {
			keys = append(keys, findingKey{f.Line, f.Path, f.Severity, f.Kind})
		}
	}
	return keys
}

func TestFileChecksValid(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeKeyPair(t, dir, "server", fileCheckNow.Add(365*24*time.Hour), 0o600)
	result := CheckSigner("signer.yaml", []byte(signerDoc(cert, key, cert)+auditSyslogEnabled), fileCheckOptions())
	if len(result.Findings) != 0 {
		t.Fatalf("unexpected findings:\n%s", dump(result.Findings))
	}
}

func TestFileChecksSkipped(t *testing.T) {
	opts := fileCheckOptions()
	opts.SkipFiles = true
	result := CheckSigner("signer.yaml", []byte(signerDoc("/missing.crt", "/missing.key", "/missing.pem")+auditSyslogEnabled), opts)
	if len(result.Findings) != 0 {
		t.Fatalf("unexpected findings with SkipFiles:\n%s", dump(result.Findings))
	}
}

func TestFileChecksProblems(t *testing.T) {
	dir := t.TempDir()
	valid := fileCheckNow.Add(365 * 24 * time.Hour)
	goodCert, goodKey := writeKeyPair(t, dir, "good", valid, 0o600)
	_, otherKey := writeKeyPair(t, dir, "other", valid, 0o600)
	expiredCert, expiredKey := writeKeyPair(t, dir, "expired", fileCheckNow.Add(-time.Hour), 0o600)
	soonCert, soonKey := writeKeyPair(t, dir, "soon", fileCheckNow.Add(10*24*time.Hour), 0o600)
	openCert, openKey := writeKeyPair(t, dir, "open", valid, 0o644)
	garbage := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name          string
		cert, key, ca string
		want          []findingKey
	}{
		{"missing files", filepath.Join(dir, "none.crt"), filepath.Join(dir, "none.key"), "", []findingKey{
			{1, "tls_cert_path", SeverityError, KindFile},
			{2, "tls_key_path", SeverityError, KindFile},
		}},
		{"certificate is not PEM", garbage, goodKey, "", []findingKey{
			{1, "tls_cert_path", SeverityError, KindFile},
		}},
		{"key does not match", goodCert, otherKey, "", []findingKey{
			{2, "tls_key_path", SeverityError, KindFile},
		}},
		{"expired", expiredCert, expiredKey, "", []findingKey{
			{1, "tls_cert_path", SeverityError, KindFile},
		}},
		{"expiring soon", soonCert, soonKey, "", []findingKey{
			{1, "tls_cert_path", SeverityWarning, KindFile},
		}},
		{"key readable by others", openCert, openKey, "", []findingKey{
			{2, "tls_key_path", SeverityWarning, KindFile},
		}},
		{"invalid CA bundle", goodCert, goodKey, garbage, []findingKey{
			{8, "keystone.ca_cert_path", SeverityError, KindFile},
		}},
		{"missing CA bundle", goodCert, goodKey, filepath.Join(dir, "none.pem"), []findingKey{
			{8, "keystone.ca_cert_path", SeverityError, KindFile},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckSigner("signer.yaml", []byte(signerDoc(tt.cert, tt.key, tt.ca)), fileCheckOptions())
			got := fileFindings(result.Findings)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("file findings = %+v, want %+v\n%s", got, tt.want, dump(result.Findings))
			}
		})
	}
}

func TestFileChecksAggregator(t *testing.T) {
	dir := t.TempDir()
	cert, key := writeKeyPair(t, dir, "agg", fileCheckNow.Add(365*24*time.Hour), 0o600)
	garbage := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(garbage, []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	doc := "tls_cert_path: " + cert + "\ntls_key_path: " + key + "\nreplicas: [https://a/jwks]\nreplica_ca_cert_path: " + garbage + "\n"
	result := CheckAggregator("aggregator.yaml", []byte(doc), fileCheckOptions())
	want := []findingKey{{4, "replica_ca_cert_path", SeverityError, KindFile}}
	if got := fileFindings(result.Findings); !slices.Equal(got, want) {
		t.Fatalf("file findings = %+v, want %+v", got, want)
	}
}
