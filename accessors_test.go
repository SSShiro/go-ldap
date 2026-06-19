package ldap

import "testing"

func TestAddRequestAccessors(t *testing.T) {
	req := AddRequest{
		dn: "cn=jdoe,dc=example,dc=org",
		attributes: []Attribute{
			{attrType: "objectClass", attrVals: []string{"top", "person"}},
			{attrType: "cn", attrVals: []string{"jdoe"}},
		},
	}
	if req.DN() != "cn=jdoe,dc=example,dc=org" {
		t.Errorf("DN() = %q", req.DN())
	}
	attrs := req.Attributes()
	if len(attrs) != 2 {
		t.Fatalf("Attributes() len = %d, want 2", len(attrs))
	}
	if attrs[0].Type() != "objectClass" || len(attrs[0].Values()) != 2 || attrs[0].Values()[1] != "person" {
		t.Errorf("attr[0] = %q %v", attrs[0].Type(), attrs[0].Values())
	}
	if attrs[1].Type() != "cn" || attrs[1].Values()[0] != "jdoe" {
		t.Errorf("attr[1] = %q %v", attrs[1].Type(), attrs[1].Values())
	}
}

func TestCompareRequestAccessors(t *testing.T) {
	req := CompareRequest{
		dn:  "cn=jdoe,dc=example,dc=org",
		ava: []AttributeValueAssertion{{attributeDesc: "mail", assertionValue: "jdoe@example.org"}},
	}
	if req.DN() != "cn=jdoe,dc=example,dc=org" {
		t.Errorf("DN() = %q", req.DN())
	}
	if req.Attribute() != "mail" {
		t.Errorf("Attribute() = %q", req.Attribute())
	}
	if req.Value() != "jdoe@example.org" {
		t.Errorf("Value() = %q", req.Value())
	}
	if len(req.AVAs()) != 1 || req.AVAs()[0].AttributeDesc() != "mail" || req.AVAs()[0].AssertionValue() != "jdoe@example.org" {
		t.Errorf("AVAs() = %+v", req.AVAs())
	}

	empty := CompareRequest{dn: "cn=x"}
	if empty.Attribute() != "" || empty.Value() != "" {
		t.Errorf("empty compare should yield empty attr/value, got %q/%q", empty.Attribute(), empty.Value())
	}
}

func TestModifyDNRequestAccessors(t *testing.T) {
	req := ModifyDNRequest{
		dn:           "uid=someone,dc=example,dc=org",
		newrdn:       "uid=newname",
		deleteoldrdn: true,
		newSuperior:  "ou=people,dc=example,dc=org",
	}
	if req.DN() != "uid=someone,dc=example,dc=org" {
		t.Errorf("DN() = %q", req.DN())
	}
	if req.NewRDN() != "uid=newname" {
		t.Errorf("NewRDN() = %q", req.NewRDN())
	}
	if !req.DeleteOldRDN() {
		t.Errorf("DeleteOldRDN() = false, want true")
	}
	if req.NewSuperior() != "ou=people,dc=example,dc=org" {
		t.Errorf("NewSuperior() = %q", req.NewSuperior())
	}
}
