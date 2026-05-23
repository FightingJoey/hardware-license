package license

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"
)

// CanonicalJSON produces a deterministic byte representation that is
// stable across Go, Node and any other implementation that follows
// RFC 8785 (JSON Canonicalization Scheme). We implement a subset:
//
//   - object keys sorted by UTF-16 code units
//   - no insignificant whitespace
//   - numbers formatted per ECMA-262 7.1.12.1 for integers (we never
//     serialize floats in this codebase, so this is sufficient)
//   - strings emitted with the JSON escape rules required by RFC 8785
//
// The input is what json.Unmarshal produced, i.e. only the following
// types may appear: map[string]any, []any, string, float64, bool, nil.
// Time values must be pre-converted to RFC 3339 strings by the caller.
func CanonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// CanonicalJSONOf is a convenience wrapper that first round-trips the
// value through encoding/json so callers can pass structs directly.
// time.Time fields get their default RFC 3339 representation, which is
// exactly what we want.
func CanonicalJSONOf(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonical: pre-marshal: %w", err)
	}
	var generic any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("canonical: re-decode: %w", err)
	}
	return CanonicalJSON(generic)
}

func encodeCanonical(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeCanonicalString(buf, x)
	case json.Number:
		// We only ever produce integers in the wire format; reject
		// anything that has a decimal point so we don't accidentally
		// canonicalize floats with platform-specific precision.
		s := x.String()
		for _, c := range s {
			if c == '.' || c == 'e' || c == 'E' {
				return fmt.Errorf("canonical: non-integer numbers are not supported (%q)", s)
			}
		}
		// Normalise leading zeros / signs the way json.Number doesn't
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			u, uerr := strconv.ParseUint(s, 10, 64)
			if uerr != nil {
				return fmt.Errorf("canonical: invalid number %q: %v", s, err)
			}
			buf.WriteString(strconv.FormatUint(u, 10))
			return nil
		}
		buf.WriteString(strconv.FormatInt(n, 10))
	case float64:
		// Only allow integral floats; anything else is a bug.
		if x != float64(int64(x)) {
			return fmt.Errorf("canonical: fractional floats are not supported (%v)", x)
		}
		buf.WriteString(strconv.FormatInt(int64(x), 10))
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sortByUTF16(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, k)
			buf.WriteByte(':')
			if err := encodeCanonical(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonical: unsupported type %T", v)
	}
	return nil
}

func sortByUTF16(keys []string) {
	sort.Slice(keys, func(i, j int) bool {
		a := utf16.Encode([]rune(keys[i]))
		b := utf16.Encode([]rune(keys[j]))
		for k := 0; k < len(a) && k < len(b); k++ {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return len(a) < len(b)
	})
}

// writeCanonicalString applies the RFC 8785 string escaping rules:
// only the mandatory escapes for control characters (\b \t \n \f \r,
// otherwise \u00XX), plus " and \. All other code points are written
// as raw UTF-8.
func writeCanonicalString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\t':
			buf.WriteString(`\t`)
		case '\n':
			buf.WriteString(`\n`)
		case '\f':
			buf.WriteString(`\f`)
		case '\r':
			buf.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}
