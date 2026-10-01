package config

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

var (
	durationType    = reflect.TypeFor[time.Duration]()
	unmarshalerType = reflect.TypeFor[yaml.Unmarshaler]()
	linePrefix      = regexp.MustCompile(`^(?:yaml: )?line (\d+): (.*)$`)
)

// decodeDocument parses data and decodes it into cfg (which already holds the
// defaults), recording findings for syntax errors, unknown keys and invalid
// values; decoding goes on past invalid values, which keep their defaults. It
// reports whether cfg could be decoded at all.
func decodeDocument[T any](r *Result[T], data []byte, cfg *T) bool {
	r.lines = map[string]int{}
	r.linePaths = map[int]string{}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		line, message := splitLine(err.Error())
		r.add(Finding{Line: line, Severity: SeverityError, Kind: KindSyntax, Message: message})
		return false
	}
	if len(root.Content) == 0 {
		return true // empty document: defaults only
	}
	document := root.Content[0]
	r.walk(document, reflect.TypeFor[T](), "")

	if err := document.Decode(cfg); err != nil {
		var typeErr *yaml.TypeError
		if !errors.As(err, &typeErr) {
			r.errorf(KindInvalidValue, "", "%v", err)
			return true
		}
		for _, entry := range typeErr.Errors {
			line, message := splitLine(entry)
			r.add(Finding{Line: line, Path: r.linePaths[line], Severity: SeverityError, Kind: KindInvalidValue, Message: message})
		}
	}
	return true
}

// splitLine separates the "line N: " prefix of YAML error messages.
func splitLine(message string) (int, string) {
	if m := linePrefix.FindStringSubmatch(message); m != nil {
		line, _ := strconv.Atoi(m[1])
		return line, m[2]
	}
	return 0, strings.TrimPrefix(message, "yaml: ")
}

// record remembers where the key at path is.
func (r *Result[T]) record(path string, line int) {
	r.lines[path] = line
	if _, ok := r.linePaths[line]; !ok {
		r.linePaths[line] = path
	}
}

// walk visits node against the Go type t it will be decoded into, recording
// the line of every key and flagging keys unknown to the schema.
func (r *Result[T]) walk(node *yaml.Node, t reflect.Type, path string) {
	if node.Kind == yaml.AliasNode && node.Alias != nil {
		node = node.Alias
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == durationType || reflect.PointerTo(t).Implements(unmarshalerType) {
		return // leaf value
	}
	switch t.Kind() {
	case reflect.Struct:
		if node.Kind != yaml.MappingNode {
			return // reported by the decoder
		}
		fields, names := yamlFields(t)
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			child := join(path, key.Value)
			r.record(child, key.Line)
			field, ok := fields[key.Value]
			if !ok {
				r.add(Finding{
					Line:       key.Line,
					Path:       child,
					Severity:   SeverityError,
					Kind:       KindUnknownKey,
					Message:    "unknown key",
					Suggestion: suggest(key.Value, names),
				})
				continue
			}
			r.walk(value, field, child)
		}
	case reflect.Map:
		if node.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			child := join(path, key.Value)
			r.record(child, key.Line)
			r.walk(value, t.Elem(), child)
		}
	case reflect.Slice:
		if node.Kind != yaml.SequenceNode {
			return
		}
		for i, item := range node.Content {
			child := fmt.Sprintf("%s[%d]", path, i)
			r.record(child, item.Line)
			r.walk(item, t.Elem(), child)
		}
	}
}

// yamlFields returns the fields of struct type t by YAML name, and the names
// in declaration order.
func yamlFields(t reflect.Type) (map[string]reflect.Type, []string) {
	fields := map[string]reflect.Type{}
	var names []string
	for field := range t.Fields() {
		if !field.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
		switch name {
		case "-":
			continue
		case "":
			name = strings.ToLower(field.Name)
		}
		fields[name] = field.Type
		names = append(names, name)
	}
	return fields, names
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// suggest returns the candidate closest to name, if it is close enough to be
// a plausible typo (edit distance of at most 2).
func suggest(name string, candidates []string) string {
	best, bestDistance := "", 3
	for _, candidate := range candidates {
		if d := editDistance(name, candidate); d < bestDistance && d < len(name) {
			best, bestDistance = candidate, d
		}
	}
	return best
}

// editDistance is the Levenshtein distance between a and b.
func editDistance(a, b string) int {
	previous := make([]int, len(b)+1)
	current := make([]int, len(b)+1)
	for j := range previous {
		previous[j] = j
	}
	for i := 1; i <= len(a); i++ {
		current[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			current[j] = min(previous[j]+1, current[j-1]+1, previous[j-1]+cost)
		}
		previous, current = current, previous
	}
	return previous[len(b)]
}
