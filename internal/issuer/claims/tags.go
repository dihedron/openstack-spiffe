package claims

import (
	"encoding/json/v2"
	"fmt"
	"maps"
	"slices"
	"unicode/utf8"

	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

// Reason tells why a metadata entry is left out of the "tags" claim.
type Reason int8

// Reasons for which a metadata entry is left out of the "tags" claim; the zero
// value is deliberately not a valid reason.
const (
	// ReasonNotString marks a metadata entry whose value is not a string.
	ReasonNotString Reason = iota + 1
	// ReasonNotAllowed marks a metadata key that is not in the allowlist.
	ReasonNotAllowed
	// ReasonTooLarge marks an entry that would push the serialized tags over
	// the size cap.
	ReasonTooLarge
	// ReasonNotEncodable marks an entry that cannot be serialized to JSON.
	ReasonNotEncodable
	// ReasonInvalidKey marks a key failing iid.ValidateTagKey: empty, or
	// containing ':', which would make the "tag:<key>:<value>" selector of
	// the SPIRE plugins ambiguous, or not valid UTF-8, or containing control
	// or format characters.
	ReasonInvalidKey
	// ReasonInvalidValue marks a value failing iid.ValidateTagValue: not
	// valid UTF-8, or containing control or format characters.
	ReasonInvalidValue
)

// maxLoggedKeyBytes bounds the part of a dropped key that is logged.
const maxLoggedKeyBytes = 64

// Name returns the reason's stable name, as the metrics record it.
func (r Reason) Name() string {
	switch r {
	case ReasonNotString:
		return "not_string"
	case ReasonNotAllowed:
		return "not_allowed"
	case ReasonTooLarge:
		return "too_large"
	case ReasonNotEncodable:
		return "not_encodable"
	case ReasonInvalidKey:
		return "invalid_key"
	case ReasonInvalidValue:
		return "invalid_value"
	default:
		return "unknown"
	}
}

// String returns a human-readable description of the reason.
func (r Reason) String() string {
	switch r {
	case ReasonNotString:
		return "non-string value"
	case ReasonNotAllowed:
		return "key not in allowlist"
	case ReasonTooLarge:
		return "tags size cap exceeded"
	case ReasonNotEncodable:
		return "not encodable"
	case ReasonInvalidKey:
		return "invalid key (empty, containing ':', or invalid characters)"
	case ReasonInvalidValue:
		return "invalid value (invalid characters)"
	default:
		return fmt.Sprintf("unknown reason (%d)", int8(r))
	}
}

// DroppedTag describes a metadata entry left out of the "tags" claim. It
// deliberately carries the key only: values are user-supplied and must not be
// logged.
type DroppedTag struct {
	Key    string
	Reason Reason
}

// FilterTags derives the "tags" claim from the instance metadata. Keys
// failing iid.ValidateTagKey are dropped, even when allowlisted; if allowlist
// is not empty, only the listed keys are kept; only string values passing
// iid.ValidateTagValue are kept.
// The JSON serialization of the result never exceeds maxBytes: entries are
// considered in sorted key order and any entry that would not fit is dropped,
// so the outcome is deterministic for a given input. The returned map is never
// nil; dropped entries are returned in sorted key order.
func FilterTags(metadata map[string]any, allowlist []string, maxBytes int) (map[string]string, []DroppedTag) {
	tags := map[string]string{}
	var dropped []DroppedTag

	size := len("{}")
	for _, key := range slices.Sorted(maps.Keys(metadata)) {
		if iid.ValidateTagKey(key) != nil {
			dropped = append(dropped, DroppedTag{Key: key, Reason: ReasonInvalidKey})
			continue
		}
		if len(allowlist) > 0 && !slices.Contains(allowlist, key) {
			dropped = append(dropped, DroppedTag{Key: key, Reason: ReasonNotAllowed})
			continue
		}
		value, ok := metadata[key].(string)
		if !ok {
			dropped = append(dropped, DroppedTag{Key: key, Reason: ReasonNotString})
			continue
		}
		if iid.ValidateTagValue(value) != nil {
			dropped = append(dropped, DroppedTag{Key: key, Reason: ReasonInvalidValue})
			continue
		}
		entry, err := entrySize(key, value)
		if err != nil {
			dropped = append(dropped, DroppedTag{Key: key, Reason: ReasonNotEncodable})
			continue
		}
		if len(tags) > 0 {
			entry++ // separating comma
		}
		if size+entry > maxBytes {
			dropped = append(dropped, DroppedTag{Key: key, Reason: ReasonTooLarge})
			continue
		}
		size += entry
		tags[key] = value
	}
	return tags, dropped
}

// LoggedKey returns a metadata key as it may be logged: at most 64 bytes,
// cut on a character boundary when the key is valid UTF-8, and marked with
// "..." when cut. Escaping is left to the log handler.
func LoggedKey(key string) string {
	if len(key) <= maxLoggedKeyBytes {
		return key
	}
	n := maxLoggedKeyBytes
	if utf8.ValidString(key) {
		for !utf8.RuneStart(key[n]) {
			n--
		}
	}
	return key[:n] + "..."
}

// entrySize returns the size of `"key":"value"` once JSON-encoded, escaping
// included.
func entrySize(key, value string) (int, error) {
	k, err := json.Marshal(key)
	if err != nil {
		return 0, err
	}
	v, err := json.Marshal(value)
	if err != nil {
		return 0, err
	}
	return len(k) + len(":") + len(v), nil
}
