package ldap

// This file adds read-only accessors for the unexported fields of the
// server-side request types (AddRequest, CompareRequest, ModifyDNRequest and
// Attribute). Upstream decodes these requests into structs whose fields are
// unexported and exposes no getters, which makes it impossible for a handler
// to forward the request payload to another server. The accessors below close
// that gap without changing the wire decoding or the public struct layout, so
// existing code keeps compiling unchanged.

// DN returns the distinguished name of the entry to be added.
func (a AddRequest) DN() string { return a.dn }

// Attributes returns the attributes of the entry to be added.
func (a AddRequest) Attributes() []Attribute { return a.attributes }

// Type returns the attribute description (name).
func (a Attribute) Type() string { return a.attrType }

// Values returns the attribute values.
func (a Attribute) Values() []string { return a.attrVals }

// DN returns the distinguished name of the entry being compared.
func (c CompareRequest) DN() string { return c.dn }

// AVAs returns the attribute/value assertions of the compare request.
// A compare request always carries exactly one assertion.
func (c CompareRequest) AVAs() []AttributeValueAssertion { return c.ava }

// Attribute returns the attribute description of the (first) assertion, or "".
func (c CompareRequest) Attribute() string {
	if len(c.ava) == 0 {
		return ""
	}
	return c.ava[0].attributeDesc
}

// Value returns the asserted value of the (first) assertion, or "".
func (c CompareRequest) Value() string {
	if len(c.ava) == 0 {
		return ""
	}
	return c.ava[0].assertionValue
}

// AttributeDesc returns the attribute description of the assertion.
func (a AttributeValueAssertion) AttributeDesc() string { return a.attributeDesc }

// AssertionValue returns the asserted value.
func (a AttributeValueAssertion) AssertionValue() string { return a.assertionValue }

// DN returns the distinguished name of the entry whose DN is being modified.
func (m ModifyDNRequest) DN() string { return m.dn }

// NewRDN returns the new relative distinguished name.
func (m ModifyDNRequest) NewRDN() string { return m.newrdn }

// DeleteOldRDN reports whether the old RDN attribute should be removed.
func (m ModifyDNRequest) DeleteOldRDN() bool { return m.deleteoldrdn }

// NewSuperior returns the new parent DN for a move operation, or "" when the
// entry is only being renamed in place.
func (m ModifyDNRequest) NewSuperior() string { return m.newSuperior }
