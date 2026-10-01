package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// certificateRenewalWarning is how early an upcoming certificate expiry is
// flagged.
const certificateRenewalWarning = 30 * 24 * time.Hour

// checkKeyPair checks the TLS certificate and key files referenced at the
// given YAML paths: both must be readable, the certificate must be currently
// valid and match the key, and the key should not be readable by others.
// Neither file's content is ever included in a finding.
func checkKeyPair[T any](r *Result[T], certKey, certPath, keyKey, keyPath string, now time.Time) {
	if certPath == "" || keyPath == "" {
		return // already reported as missing
	}
	certPEM, certErr := os.ReadFile(filepath.Clean(certPath))
	if certErr != nil {
		r.errorf(KindFile, certKey, "cannot read certificate: %v", certErr)
	}
	keyPEM, keyErr := os.ReadFile(filepath.Clean(keyPath))
	if keyErr != nil {
		r.errorf(KindFile, keyKey, "cannot read private key: %v", keyErr)
	} else if info, err := os.Stat(filepath.Clean(keyPath)); err == nil && info.Mode().Perm()&0o077 != 0 {
		r.add(Finding{
			Path:     keyKey,
			Severity: SeverityWarning,
			Kind:     KindFile,
			Message:  fmt.Sprintf("private key %s is accessible by group or others (mode %04o); restrict it to the service user", keyPath, info.Mode().Perm()),
		})
	}
	if certErr != nil {
		return
	}

	block, _ := pem.Decode(certPEM)
	for block != nil && block.Type != "CERTIFICATE" {
		block, _ = pem.Decode(nil)
	}
	if block == nil {
		r.errorf(KindFile, certKey, "no PEM certificate found in %s", certPath)
		return
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		r.errorf(KindFile, certKey, "cannot parse certificate in %s: %v", certPath, err)
		return
	}
	switch {
	case now.After(leaf.NotAfter):
		r.errorf(KindFile, certKey, "certificate expired on %s", leaf.NotAfter.Format(time.DateOnly))
	case now.Before(leaf.NotBefore):
		r.errorf(KindFile, certKey, "certificate is not valid before %s", leaf.NotBefore.Format(time.DateTime))
	case leaf.NotAfter.Sub(now) < certificateRenewalWarning:
		r.add(Finding{
			Path:     certKey,
			Severity: SeverityWarning,
			Kind:     KindFile,
			Message:  "certificate expires on " + leaf.NotAfter.Format(time.DateOnly) + ", renew it",
		})
	}

	if keyErr == nil {
		if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
			r.errorf(KindFile, keyKey, "private key cannot be parsed or does not match the certificate: %v", err)
		}
	}
}

// checkCABundle checks that the optional CA bundle at the given YAML path
// holds at least one PEM certificate.
func checkCABundle[T any](r *Result[T], key, path string) {
	if path == "" {
		return
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		r.errorf(KindFile, key, "cannot read CA bundle: %v", err)
		return
	}
	if !x509.NewCertPool().AppendCertsFromPEM(data) {
		r.errorf(KindFile, key, "no PEM certificates found in %s", path)
	}
}
