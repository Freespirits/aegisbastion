package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// JCS (JSON Canonicalization Scheme, RFC 8785) — the platform's canonical
// JSON form (doc 01 §10.2: RoE/token/scope-manifest canonicalization and the
// audit hash chain are all JCS).
//
// Canonical serializes a decoded JSON value (map[string]any, []any, string,
// json.Number/float64/int, bool, nil) to its RFC 8785 form:
//   - object keys sorted by UTF-16 code units
//   - strings escaped per ECMAScript JSON.stringify
//   - numbers serialized per ECMAScript Number::toString (shortest round-trip)
//   - no insignificant whitespace
func Canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := writeCanonical(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// CanonicalizeJSON parses raw JSON and re-serializes it canonically (JCS).
// Gatekeeper canonicalizes scope manifests with JCS before hashing, so this
// is the helper that reproduces "scope:sha256:<hash>" values from a scope
// document (Ruling A.3).
func CanonicalizeJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("audit: JCS input does not decode: %w", err)
	}
	if dec.More() {
		return nil, errors.New("audit: JCS input has trailing data")
	}
	return Canonical(v)
}

func writeCanonical(b *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeJCSString(b, t)
	case json.Number:
		s, err := canonicalNumber(t.String())
		if err != nil {
			return err
		}
		b.WriteString(s)
	case float64:
		s, err := es6Number(t)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case int:
		b.WriteString(strconv.Itoa(t))
	case int64:
		b.WriteString(strconv.FormatInt(t, 10))
	case uint64:
		b.WriteString(strconv.FormatUint(t, 10))
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJCSString(b, k)
			b.WriteByte(':')
			if err := writeCanonical(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("audit: JCS unsupported value of type %T", v)
	}
	return nil
}

// utf16Less compares strings by UTF-16 code units (RFC 8785 §3.2.3): Go's
// byte-wise string order diverges from UTF-16 order for characters outside
// the BMP, so compare via UTF-16 encoding.
func utf16Less(a, b string) bool {
	ra := utf16.Encode([]rune(a))
	rb := utf16.Encode([]rune(b))
	for i := 0; i < len(ra) && i < len(rb); i++ {
		if ra[i] != rb[i] {
			return ra[i] < rb[i]
		}
	}
	return len(ra) < len(rb)
}

// writeJCSString writes a string escaped per ECMAScript JSON.stringify: the
// C0 controls use short escapes where defined (\b \t \n \f \r) and \u00xx
// otherwise; only '"' and '\\' are escaped above that; everything else is
// raw UTF-8.
func writeJCSString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else if r == utf8.RuneError {
				// Invalid UTF-8 in input — ECMAScript would carry the lone
				// surrogates; Go strings cannot. Escape deterministically.
				b.WriteString(`�`)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// canonicalNumber renders a JSON number literal in ECMAScript Number::toString
// form. Integer literals within the safe range pass through; everything else
// goes through float64 shortest round-trip formatting.
func canonicalNumber(lit string) (string, error) {
	if isIntegerLiteral(lit) {
		if lit == "-0" {
			return "0", nil
		}
		// Strip leading zeros is unnecessary for json.Number (the decoder
		// already validated the literal).
		if i, err := strconv.ParseInt(lit, 10, 64); err == nil {
			return strconv.FormatInt(i, 10), nil
		}
		if u, err := strconv.ParseUint(lit, 10, 64); err == nil && u < 1<<53 {
			return strconv.FormatUint(u, 10), nil
		}
		// Fall through: beyond int64/2^53 — ECMAScript would round to double.
	}
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		return "", fmt.Errorf("audit: JCS invalid number %q", lit)
	}
	return es6Number(f)
}

func isIntegerLiteral(lit string) bool {
	return !strings.ContainsAny(lit, ".eE")
}

// es6Number formats f per ECMAScript Number::toString (the JCS/RFC 8785
// number rule): shortest round-trip decimal; plain notation for
// 1e-6 <= |f| < 1e21, exponential notation outside.
func es6Number(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("audit: JCS cannot serialize non-finite number %v", f)
	}
	if f == 0 {
		return "0", nil // covers -0
	}
	neg := math.Signbit(f)
	if neg {
		f = -f
	}
	// Shortest round-trip scientific form: "d.dddde±xx" or "de±xx".
	sci := strconv.FormatFloat(f, 'e', -1, 64)
	ePos := strings.IndexByte(sci, 'e')
	mant := sci[:ePos]
	exp, err := strconv.Atoi(sci[ePos+1:])
	if err != nil {
		return "", fmt.Errorf("audit: JCS number format: %w", err)
	}
	digits := strings.Replace(mant, ".", "", 1)
	k := len(digits)
	n := exp + 1 // digits before the decimal point in scientific normalization

	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		var m string
		if k > 1 {
			m = digits[:1] + "." + digits[1:]
		} else {
			m = digits
		}
		e := n - 1
		if e >= 0 {
			out = fmt.Sprintf("%se+%d", m, e)
		} else {
			out = fmt.Sprintf("%se-%d", m, -e)
		}
	}
	if neg {
		out = "-" + out
	}
	return out, nil
}
