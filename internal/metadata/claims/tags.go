package claims

import (
	"encoding/json/v2"
	"fmt"
	"maps"
	"slices"
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
)

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

// FilterTags derives the "tags" claim from the instance metadata. Only string
// values are kept; if allowlist is not empty, only the listed keys are kept.
// The JSON serialization of the result never exceeds maxBytes: entries are
// considered in sorted key order and any entry that would not fit is dropped,
// so the outcome is deterministic for a given input. The returned map is never
// nil; dropped entries are returned in sorted key order.
func FilterTags(metadata map[string]any, allowlist []string, maxBytes int) (map[string]string, []DroppedTag) {
	tags := map[string]string{}
	var dropped []DroppedTag

	size := len("{}")
	for _, key := range slices.Sorted(maps.Keys(metadata)) {
		if len(allowlist) > 0 && !slices.Contains(allowlist, key) {
			dropped = append(dropped, DroppedTag{Key: key, Reason: ReasonNotAllowed})
			continue
		}
		value, ok := metadata[key].(string)
		if !ok {
			dropped = append(dropped, DroppedTag{Key: key, Reason: ReasonNotString})
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
