package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
)

// maxLoggedPayload bounds the part of a rejected payload that is logged.
const maxLoggedPayload = 512

const redacted = "[redacted]"

// redact returns the log attributes describing a rejected payload (I-2).
// A payload that parses as a JSON object is logged, truncated to
// maxLoggedPayload bytes, with its user-data value and every metadata value
// redacted: tenants commonly keep secrets in either. The metadata keys are
// kept, since they help diagnose a rejected request. Duplicate names are
// accepted here, so that a payload rejected for having them is still
// logged; the parser resolves escaped names, so an escaped "user-data" is
// redacted too.
//
// Any other payload is logged with its size and SHA-256 only, never its
// content, since the sensitive values cannot be located reliably in it.
func redact(body []byte) []any {
	var object map[string]any
	if err := json.Unmarshal(body, &object, jsontext.AllowDuplicateNames(true)); err == nil && object != nil {
		if _, ok := object["user-data"]; ok {
			object["user-data"] = redacted
		}
		if value, ok := object["metadata"]; ok {
			if metadata, ok := value.(map[string]any); ok {
				for key := range metadata {
					metadata[key] = redacted
				}
			} else {
				object["metadata"] = redacted
			}
		}
		if clean, err := json.Marshal(object, json.Deterministic(true)); err == nil {
			return []any{"payload", truncate(clean)}
		}
	}
	sum := sha256.Sum256(body)
	return []any{"payload_bytes", len(body), "payload_sha256", hex.EncodeToString(sum[:])}
}

func truncate(b []byte) string {
	if len(b) <= maxLoggedPayload {
		return string(b)
	}
	return string(b[:maxLoggedPayload]) + "...(truncated)"
}
