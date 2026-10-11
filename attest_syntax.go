package est

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"unicode/utf8"
)

// The syntax of the attested requests, as the wire format proposed for draft-novak-lamps-tacra-est defines their JSON
// in CDDL:
//
//	attested-enrollment-request = { request-common, request-freshness, csr: text .b64u bytes }
//	attested-retrieval-request  = { request-common, request-freshness, cek_pub: text .b64u bytes }
//	request-common = ( target: text, ? credential_type: text, evidence: text .b64u bytes, ? profile: text,
//	                   binding: binding, ? credential_hint: text )
//	request-freshness = ( freshness_kind: "absent-none" //
//	                      freshness_kind: <the other four kinds>, handle: text .b64u bytes )
//	binding = { method: text, ? hash: text }
//
// The EST server refuses, before anything else is done with it, a request that is not one of these. Go's decoder alone
// would take a member name in any case, a member twice (the last one counting), null for a member, invalid UTF-8 and
// data after the object.

// memberType is what a member of an attested request holds.
type memberType int

const (
	textMember    memberType = iota // a text string
	bytesMember                     // a byte string: a text string holding its unpadded base64url encoding
	bindingMember                   // the binding object
)

// requestMembers are the members of the attested request whose subject member is subject: "csr" (attest-enroll) or
// "cek_pub" (attest-retrieve).
func requestMembers(subject string) map[string]memberType {
	return map[string]memberType{
		"target": textMember, "credential_type": textMember, "freshness_kind": textMember, "handle": bytesMember,
		"evidence": bytesMember, "profile": textMember, "binding": bindingMember, "credential_hint": textMember,
		subject: bytesMember,
	}
}

var bindingMembers = map[string]memberType{"method": textMember, "hash": textMember}

// freshnessKinds are the values of freshness_kind, each with whether a request of that kind carries a handle.
var freshnessKinds = map[string]bool{
	FreshnessAbsentNone: false, FreshnessAbsentTimestamp: true, FreshnessAbsentEpoch: true,
	FreshnessPresentNonce: true, FreshnessPresentEpoch: true,
}

// errSyntax is the 400 of a request whose syntax is not the one above, saying why.
func errSyntax(format string, a ...any) error {
	return &estError{status: http.StatusBadRequest, desc: "malformed request: " + fmt.Sprintf(format, a...)}
}

// quoted is s quoted for an error message, cut to 64 octets.
func quoted(s string) string {
	if len(s) > 64 {
		s = s[:64] + "..."
	}
	return strconv.Quote(s)
}

// decodeAttestedRequest reads the body of an attest-enroll (subject "csr") or attest-retrieve (subject "cek_pub")
// request into v, once checkRequestSyntax has taken it. A body over the server's size limit is refused with 413.
func decodeAttestedRequest(r *http.Request, subject string, v interface{}) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return &estError{
				status: http.StatusRequestEntityTooLarge,
				desc:   fmt.Sprintf("request body over the limit of %d octets", tooLarge.Limit),
			}
		}
		return errInvalidJSON
	}
	if err := checkRequestSyntax(body, subject); err != nil {
		return err
	}
	if err := json.Unmarshal(body, v); err != nil {
		return errInvalidJSON // not reached: checkRequestSyntax takes nothing this refuses
	}
	return nil
}

// checkRequestSyntax returns nil if body is the JSON of an attested request whose subject member is subject, and
// otherwise an error saying why it is not.
func checkRequestSyntax(body []byte, subject string) error {
	if !utf8.Valid(body) {
		return errSyntax("the body is not UTF-8 (RFC 8259, Section 8.1)")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	got, err := checkObject(dec, requestMembers(subject), "")
	if err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errSyntax("data after the JSON object")
	}
	for _, m := range []string{"target", "freshness_kind", "evidence", "binding", subject} {
		if _, ok := got[m]; !ok {
			return errSyntax("no member %q", m)
		}
	}
	kind := got["freshness_kind"]
	withHandle, ok := freshnessKinds[kind]
	if !ok {
		return errSyntax("freshness_kind %s is not a Freshness Kind", quoted(kind))
	}
	if _, has := got["handle"]; has != withHandle {
		if has {
			return errSyntax("a handle with %s", kind)
		}
		return errSyntax("no handle with %s", kind)
	}
	return nil
}

// checkObject reads from dec one JSON object whose members are among members, each of its type and at most once, and
// returns the members it has, with the value of each text and byte string member. prefix names the object in errors:
// "" for the request, "binding." for its binding object.
func checkObject(dec *json.Decoder, members map[string]memberType, prefix string) (map[string]string, error) {
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		if prefix == "" {
			return nil, errSyntax("the body is not a JSON object")
		}
		return nil, errSyntax("member %q is not an object", prefix[:len(prefix)-1])
	}
	got := map[string]string{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, errInvalidJSON
		}
		name, _ := t.(string) // in an object, the token before a value is its name
		typ, ok := members[name]
		if !ok {
			return nil, errSyntax("member %s is not defined", quoted(prefix+name))
		}
		if _, dup := got[name]; dup {
			return nil, errSyntax("member %q appears more than once", prefix+name)
		}
		if typ == bindingMember {
			b, err := checkObject(dec, bindingMembers, name+".")
			if err != nil {
				return nil, err
			}
			if _, ok := b["method"]; !ok {
				return nil, errSyntax("no member %q", name+".method")
			}
			got[name] = ""
			continue
		}
		if t, err = dec.Token(); err != nil {
			return nil, errInvalidJSON
		}
		s, isText := t.(string)
		if !isText {
			return nil, errSyntax("member %q is not a text string", prefix+name)
		}
		if typ == bytesMember {
			if _, err := decodeB64U(s); err != nil {
				return nil, errSyntax("member %q is not unpadded base64url (RFC 4648, Section 5)", prefix+name)
			}
		}
		got[name] = s
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil, errInvalidJSON
	}
	return got, nil
}
