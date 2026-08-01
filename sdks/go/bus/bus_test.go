package bus

import (
	"testing"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	payload := &platformv1.TaskResult{
		TaskId:  "tsk_1",
		AgentId: "agent_1",
		Status:  platformv1.TaskResultStatus_TASK_RESULT_STATUS_SUCCEEDED,
	}
	msg, err := BuildMessage(SubjectTaskResult, payload, PublishOptions{
		MissionID: "msn_1",
		Trace:     &platformv1.TraceContext{Traceparent: "00-abc-def-01"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Deterministic dedup id for the outbox path.
	if msg.Header.Get("Nats-Msg-Id") == "" {
		t.Fatalf("Nats-Msg-Id header missing")
	}
	if msg.Subject != SubjectTaskResult {
		t.Fatalf("subject = %q", msg.Subject)
	}

	env, err := UnmarshalEnvelope(msg.Data)
	if err != nil {
		t.Fatal(err)
	}
	if env.GetEventId() != msg.Header.Get("Nats-Msg-Id") {
		t.Fatalf("event_id %q != msg id %q", env.GetEventId(), msg.Header.Get("Nats-Msg-Id"))
	}
	if env.GetType() != "aegisbastion.platform.v1.TaskResult" {
		t.Fatalf("type = %q", env.GetType())
	}
	if env.GetMissionId() != "msn_1" || env.GetTraceContext().GetTraceparent() != "00-abc-def-01" {
		t.Fatalf("envelope metadata = %+v", env)
	}
	if env.GetTs() == nil {
		t.Fatalf("ts missing")
	}

	got, err := UnpackPayload(env)
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := got.(*platformv1.TaskResult)
	if !ok {
		t.Fatalf("payload type = %T", got)
	}
	if tr.GetTaskId() != "tsk_1" {
		t.Fatalf("task_id = %q", tr.GetTaskId())
	}

	// Outbox replay: explicit event id survives.
	env2, err := NewEnvelope(payload, PublishOptions{EventID: "outbox-row-42"})
	if err != nil {
		t.Fatal(err)
	}
	if env2.GetEventId() != "outbox-row-42" {
		t.Fatalf("replay id = %q", env2.GetEventId())
	}
}

func TestSubjectTaskAssign(t *testing.T) {
	if got := SubjectTaskAssign("agent_1"); got != "task.assign.agent_1" {
		t.Fatalf("SubjectTaskAssign = %q", got)
	}
}
