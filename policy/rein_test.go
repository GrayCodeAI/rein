package policy

import (
	"strings"
	"testing"
)

const inputDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const outputDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func call(run, id, callID string) Event {
	return Event{Version: Version, ID: id, RunID: run, Kind: "tool_call", CallID: callID, Tool: "GoTest", InputSHA256: inputDigest}
}

func result(run, id, callID, output string, code int) Event {
	return Event{Version: Version, ID: id, RunID: run, Kind: "tool_result", CallID: callID, OutputSHA256: output, ExitCode: &code}
}

func TestRepeatedFailureAuditAndGate(t *testing.T) {
	events := []Event{call("run-a", "c1", "1"), result("run-a", "r1", "1", outputDigest, 1), call("run-a", "c2", "2"), result("run-a", "r2", "2", outputDigest, 1)}
	p := Policy{}
	findings, err := p.Audit(events)
	if err != nil || len(findings) != 1 || findings[0].Rule != "repeated-failure" || strings.Join(findings[0].Evidence, ",") != "r1,r2" {
		t.Fatalf("findings = %+v, %v", findings, err)
	}
	proposed := call("run-a", "c3", "3")
	observed, err := p.Check(events, proposed, "observe")
	if err != nil || observed.Outcome != "observe" {
		t.Fatalf("observe = %+v, %v", observed, err)
	}
	enforced, err := p.Check(events, proposed, "enforce")
	if err != nil || enforced.Outcome != "deny" || len(enforced.Evidence) != 2 {
		t.Fatalf("enforce = %+v, %v", enforced, err)
	}
	otherRun, err := p.Check(events, call("run-b", "c1", "1"), "enforce")
	if err != nil || otherRun.Outcome != "allow" {
		t.Fatalf("other run = %+v, %v", otherRun, err)
	}
}

func TestSuccessAndDifferentOutputResetFailure(t *testing.T) {
	p := Policy{}
	different := strings.Repeat("c", 64)
	events := []Event{call("run", "c1", "1"), result("run", "r1", "1", outputDigest, 1), call("run", "c2", "2"), result("run", "r2", "2", different, 1)}
	decision, err := p.Check(events, call("run", "c3", "3"), "enforce")
	if err != nil || decision.Outcome != "allow" {
		t.Fatalf("different output = %+v, %v", decision, err)
	}
	events = append(events, call("run", "c3", "3"), result("run", "r3", "3", different, 0))
	decision, err = p.Check(events, call("run", "c4", "4"), "enforce")
	if err != nil || decision.Outcome != "allow" {
		t.Fatalf("successful retry = %+v, %v", decision, err)
	}
}

func TestStrictInputAndEventOrder(t *testing.T) {
	raw := `{"version":1,"id":"c1","run_id":"run","kind":"tool_call","call_id":"1","tool":"Bash","input_sha256":"` + inputDigest + `","raw_command":"cat .env"}`
	if _, err := LoadJSONL(strings.NewReader(raw)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("raw field accepted: %v", err)
	}
	if _, err := (Policy{}).Audit([]Event{result("run", "r1", "1", outputDigest, 1)}); err == nil || !strings.Contains(err.Error(), "no preceding call") {
		t.Fatalf("orphan result accepted: %v", err)
	}
	if _, err := (Policy{RepeatFailures: 1}).Audit(nil); err == nil {
		t.Fatal("invalid threshold accepted")
	}
	bad := call("run", "c1", "1")
	bad.InputSHA256 = "not-a-digest"
	if err := Validate(bad); err == nil {
		t.Fatal("invalid digest accepted")
	}
}
