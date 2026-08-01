package audit

import (
	"context"
	"encoding/json"
	"testing"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
)

// JCS vectors: RFC 8785 §3.2.2 number rules and the spec's canonicalization
// expectations (key ordering, string escaping, whitespace removal).
func TestCanonicalizeJSON_Vectors(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "key ordering", in: `{"b":1,"a":2}`, want: `{"a":2,"b":1}`},
		{name: "nested", in: `{"z":{"b":true,"a":null},"a":[1,2]}`, want: `{"a":[1,2],"z":{"a":null,"b":true}}`},
		{name: "whitespace removed", in: "{\n  \"a\" : 1 ,\n  \"b\" : [ 1, 2 ]\n}", want: `{"a":1,"b":[1,2]}`},
		{name: "unicode key ordering utf16", in: `{"\u20ac":1,"a":2}`, want: `{"a":2,"€":1}`},
		{name: "string escapes", in: `{"s":"a\"b\\c\td\ne"}`, want: `{"s":"a\"b\\c\td\ne"}`},
		{name: "control char", in: `{"s":"\u0001"}`, want: `{"s":"\u0001"}`},
		{name: "non-ascii raw", in: `{"s":"héllo"}`, want: `{"s":"héllo"}`},

		// Numbers — ECMAScript Number::toString (RFC 8785 §3.2.2.3).
		{name: "int", in: `{"n":123}`, want: `{"n":123}`},
		{name: "negative int", in: `{"n":-42}`, want: `{"n":-42}`},
		{name: "zero", in: `{"n":0}`, want: `{"n":0}`},
		{name: "fraction", in: `{"n":1.5}`, want: `{"n":1.5}`},
		{name: "trailing fraction zeros", in: `{"n":1.50}`, want: `{"n":1.5}`},
		{name: "tenth", in: `{"n":0.1}`, want: `{"n":0.1}`},
		{name: "small decimal", in: `{"n":0.000001}`, want: `{"n":0.000001}`},
		{name: "below 1e-6 goes exponential", in: `{"n":0.0000001}`, want: `{"n":1e-7}`},
		{name: "1e20 plain", in: `{"n":1e20}`, want: `{"n":100000000000000000000}`},
		{name: "1e21 exponential", in: `{"n":1e21}`, want: `{"n":1e+21}`},
		{name: "exponent input normalized", in: `{"n":1.5e3}`, want: `{"n":1500}`},
		{name: "negative fraction", in: `{"n":-0.5}`, want: `{"n":-0.5}`},
		{name: "minus zero", in: `{"n":-0}`, want: `{"n":0}`},
		{name: "float mantissa", in: `{"n":3.141592653589793}`, want: `{"n":3.141592653589793}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CanonicalizeJSON([]byte(tc.in))
			if err != nil {
				t.Fatalf("CanonicalizeJSON(%s) error = %v", tc.in, err)
			}
			if string(got) != tc.want {
				t.Fatalf("CanonicalizeJSON(%s) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

func TestCanonical_DirectValues(t *testing.T) {
	got, err := Canonical(map[string]any{"b": []any{json.Number("1"), "x"}, "a": true})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":true,"b":[1,"x"]}` {
		t.Fatalf("Canonical = %s", got)
	}
}

func TestTargetTouchedEvent(t *testing.T) {
	id := Ident{AgentID: "agent_1", MissionID: "msn_1", TaskID: "tsk_1", ROEID: "roe_1"}
	evt, err := TargetTouchedEvent(id, "api.acme.com", "tok_1", map[string]any{"probe_type": "http"})
	if err != nil {
		t.Fatal(err)
	}
	if evt.GetType() != platformv1.AuditEventType_AUDIT_EVENT_TYPE_TARGET_TOUCHED {
		t.Fatalf("type = %v", evt.GetType())
	}
	if evt.GetActor().GetKind() != "agent" || evt.GetActor().GetId() != "agent_1" {
		t.Fatalf("actor = %+v", evt.GetActor())
	}
	if evt.GetSubject().GetMissionId() != "msn_1" || evt.GetSubject().GetTaskId() != "tsk_1" || evt.GetSubject().GetRoeId() != "roe_1" {
		t.Fatalf("subject = %+v", evt.GetSubject())
	}
	p := evt.GetPayload().AsMap()
	if p["target"] != "api.acme.com" || p["token_jti"] != "tok_1" || p["probe_type"] != "http" {
		t.Fatalf("payload = %v", p)
	}
	if evt.GetEventId() == "" || evt.GetTs() == nil {
		t.Fatalf("event id/ts not set")
	}
}

func TestScopeViolationEvent(t *testing.T) {
	evt, err := ScopeViolationEvent(Ident{AgentID: "agent_1", TaskID: "tsk_1"}, "evil.com", "tok_1", "target not in manifest")
	if err != nil {
		t.Fatal(err)
	}
	if evt.GetType() != platformv1.AuditEventType_AUDIT_EVENT_TYPE_SCOPE_VIOLATION {
		t.Fatalf("type = %v", evt.GetType())
	}
	p := evt.GetPayload().AsMap()
	if p["denied_before_contact"] != true || p["reason"] != "target not in manifest" {
		t.Fatalf("payload = %v", p)
	}
}

func TestScopeHashCheckpointForm(t *testing.T) {
	const h = "9f2c"
	got := ScopeHashValue(h)
	if got != "scope:sha256:9f2c" {
		t.Fatalf("ScopeHashValue = %q", got)
	}
	cp := CheckpointTargetsTouched(h)
	if len(cp) != 1 || cp[0] != "scope:sha256:9f2c" {
		t.Fatalf("CheckpointTargetsTouched = %v", cp)
	}
}

func TestEmitterFunc(t *testing.T) {
	var seen *platformv1.AuditEvent
	e := EmitterFunc(func(_ context.Context, evt *platformv1.AuditEvent) error {
		seen = evt
		return nil
	})
	evt, err := NewEvent(platformv1.AuditEventType_AUDIT_EVENT_TYPE_TARGET_TOUCHED, Ident{AgentID: "a"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Emit(context.Background(), evt); err != nil {
		t.Fatal(err)
	}
	if seen != evt {
		t.Fatalf("emitter did not deliver the event")
	}
}
