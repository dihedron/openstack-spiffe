package attest

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
)

// maxLoggedPayload bounds the part of a rejected payload that is logged.
const maxLoggedPayload = 512

const redacted = "[redacted]"

// redact returns a rejected payload for logging, truncated to
// maxLoggedPayload bytes and with user-data redacted. A JSON object has its
// user-data member replaced (duplicate names are accepted here, so that a
// payload rejected for having them is still logged); any other payload is
// cut at the first mention of user-data, since its value cannot be located
// reliably.
func redact(body []byte) string {
	var object map[string]any
	if err := json.Unmarshal(body, &object, jsontext.AllowDuplicateNames(true)); err == nil {
		if _, ok := object["user-data"]; ok {
			object["user-data"] = redacted
		}
		if clean, err := json.Marshal(object, json.Deterministic(true)); err == nil {
			return truncate(clean)
		}
	}
	if i := bytes.Index(body, []byte(`"user-data`)); i >= 0 {
		body = append(bytes.Clone(body[:i]), redacted...)
	}
	return truncate(body)
}

func truncate(b []byte) string {
	if len(b) <= maxLoggedPayload {
		return string(b)
	}
	return string(b[:maxLoggedPayload]) + "...(truncated)"
}
