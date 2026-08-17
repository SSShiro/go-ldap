package ldap

import (
	"strconv"
	"unicode/utf8"

	"testing"

	ber "github.com/nmcclain/asn1-ber"
)

// A binary assertion value (raw high/meta bytes) must come out of DecompileFilter
// as a valid RFC 4515 escaped, UTF-8 string that a downstream compiler accepts —
// not as raw bytes.
func TestDecompileFilterEscapesBinaryValue(t *testing.T) {
	guid := []byte{0xba, 0x97, 0xf7, 0x0b, 0x11, 0xfb, 0x78, 0x4e,
		0xa9, 0xc8, 0xfd, 0xe4, 0x43, 0x04, 0xde, 0xc7}

	eq := ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterEqualityMatch, nil, "eq")
	eq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "objectGUID", "attr"))
	eq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(guid), "val"))

	got, err := DecompileFilter(eq)
	if err != nil {
		t.Fatalf("DecompileFilter err: %v", err)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("result is not valid UTF-8: %q", got)
	}
	// Decoding the escaped value back to bytes must reproduce the original GUID:
	// printable ASCII bytes stay literal, everything else is \XX.
	inner := got[len("(objectGUID=") : len(got)-1]
	if decoded := decodeFilterValue(t, inner); !equalBytes(decoded, guid) {
		t.Fatalf("round-trip mismatch: decoded %v, want %v (from %q)", decoded, guid, got)
	}
}

func decodeFilterValue(t *testing.T, s string) []byte {
	t.Helper()
	var out []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil {
				t.Fatalf("bad escape at %d in %q: %v", i, s, err)
			}
			out = append(out, byte(v))
			i += 2
		} else {
			out = append(out, s[i])
		}
	}
	return out
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The four filter metacharacters and NUL must be escaped even though they are
// printable ASCII, or the recompiled filter would be structurally different.
func TestDecompileFilterEscapesMetacharacters(t *testing.T) {
	val := []byte{'(', ')', '*', '\\', 0x00}
	eq := ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterEqualityMatch, nil, "eq")
	eq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "attr"))
	eq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(val), "val"))

	got, err := DecompileFilter(eq)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	want := `(cn=\28\29\2a\5c\00)`
	if got != want {
		t.Fatalf("got=%q want=%q", got, want)
	}
}

// Plain ASCII and multi-byte UTF-8 values must pass through unescaped.
func TestDecompileFilterKeepsPrintable(t *testing.T) {
	eq := ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterEqualityMatch, nil, "eq")
	eq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "attr"))
	eq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "Smith", "val"))
	got, _ := DecompileFilter(eq)
	if got != "(cn=Smith)" {
		t.Fatalf("printable value changed: %q", got)
	}
}

// An extensible match (filter [9], e.g. LDAP_MATCHING_RULE_IN_CHAIN) must be
// rendered as "type:matchingRule:=value", not dropped as an empty "()".
func TestDecompileFilterExtensibleMatch(t *testing.T) {
	em := ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterExtensibleMatch, nil, "em")
	em.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, MatchingRuleAssertionMatchingRule, "1.2.840.113556.1.4.1941", "rule"))
	em.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, MatchingRuleAssertionType, "member", "type"))
	em.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, MatchingRuleAssertionMatchValue, "CN=Ivan Ivanov,OU=IT operation,OU=Example,DC=com", "value"))

	got, err := DecompileFilter(em)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	want := `(member:1.2.840.113556.1.4.1941:=CN=Ivan Ivanov,OU=IT operation,OU=Example,DC=com)`
	if got != want {
		t.Fatalf("extensible match mismatch:\n got=%q\nwant=%q", got, want)
	}
}
