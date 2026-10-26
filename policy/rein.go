// Package policy finds repeated failures in agent tool events and returns
// deterministic policy decisions. Hosts keep ownership of tool execution.
package policy

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const Version = 1

var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Event carries digests and identifiers, never raw prompts, arguments, or output.
// A tool_result references the preceding tool_call through call_id.
type Event struct {
	Version      int    `json:"version"`
	ID           string `json:"id"`
	RunID        string `json:"run_id"`
	Kind         string `json:"kind"`
	CallID       string `json:"call_id"`
	Tool         string `json:"tool,omitempty"`
	InputSHA256  string `json:"input_sha256,omitempty"`
	OutputSHA256 string `json:"output_sha256,omitempty"`
	ExitCode     *int   `json:"exit_code,omitempty"`
}

type Finding struct {
	Rule     string   `json:"rule"`
	RunID    string   `json:"run_id"`
	Tool     string   `json:"tool"`
	Failures int      `json:"failures"`
	Evidence []string `json:"evidence_event_ids"`
	Summary  string   `json:"summary"`
}

type Decision struct {
	Outcome  string   `json:"outcome"` // allow, observe, or deny
	Rule     string   `json:"rule,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	Evidence []string `json:"evidence_event_ids,omitempty"`
}

type Policy struct {
	RepeatFailures int
}

func (p Policy) threshold() (int, error) {
	if p.RepeatFailures == 0 {
		return 2, nil
	}
	if p.RepeatFailures < 2 {
		return 0, errors.New("repeat failures must be at least 2")
	}
	return p.RepeatFailures, nil
}

func Validate(e Event) error {
	if e.Version != Version {
		return fmt.Errorf("unsupported event version %d", e.Version)
	}
	if e.ID == "" || e.RunID == "" || e.CallID == "" {
		return errors.New("id, run_id, and call_id are required")
	}
	if strings.ContainsAny(e.ID+e.RunID+e.CallID, "\x00\r\n\t") {
		return errors.New("IDs must be single-line values")
	}
	switch e.Kind {
	case "tool_call":
		if e.Tool == "" || !digestPattern.MatchString(e.InputSHA256) {
			return errors.New("tool_call needs tool and lowercase input_sha256")
		}
		if e.OutputSHA256 != "" || e.ExitCode != nil {
			return errors.New("tool_call cannot contain a result")
		}
	case "tool_result":
		if !digestPattern.MatchString(e.OutputSHA256) || e.ExitCode == nil {
			return errors.New("tool_result needs lowercase output_sha256 and exit_code")
		}
		if e.Tool != "" || e.InputSHA256 != "" {
			return errors.New("tool_result cannot contain call fields")
		}
	default:
		return fmt.Errorf("unsupported event kind %q", e.Kind)
	}
	return nil
}

// LoadJSONL reads a bounded sequence of strict JSON events. Unknown fields are
// rejected so an adapter cannot accidentally persist raw tool arguments.
func LoadJSONL(r io.Reader) ([]Event, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var events []Event
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if len(events) >= 100000 {
			return nil, errors.New("event file exceeds 100000 events")
		}
		var e Event
		dec := json.NewDecoder(strings.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("event %d: %w", len(events)+1, err)
		}
		if err := Validate(e); err != nil {
			return nil, fmt.Errorf("event %d: %w", len(events)+1, err)
		}
		if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("event %d: trailing JSON", len(events)+1)
		}
		events = append(events, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

type failureState struct {
	Output   string
	Count    int
	Evidence []string
}

type analysis struct {
	states   map[string]failureState
	findings []Finding
}

func key(run, tool, input string) string { return run + "\x00" + tool + "\x00" + input }

func analyze(events []Event, threshold int) (analysis, error) {
	a := analysis{states: make(map[string]failureState), findings: make([]Finding, 0)}
	calls := make(map[string]Event)
	seen := make(map[string]bool)
	for i, e := range events {
		if err := Validate(e); err != nil {
			return a, fmt.Errorf("event %d: %w", i+1, err)
		}
		uniqueID := e.RunID + "\x00" + e.ID
		if seen[uniqueID] {
			return a, fmt.Errorf("event %d: duplicate ID %q", i+1, e.ID)
		}
		seen[uniqueID] = true
		callKey := e.RunID + "\x00" + e.CallID
		if e.Kind == "tool_call" {
			if _, exists := calls[callKey]; exists {
				return a, fmt.Errorf("event %d: duplicate call_id %q", i+1, e.CallID)
			}
			calls[callKey] = e
			continue
		}
		call, exists := calls[callKey]
		if !exists {
			return a, fmt.Errorf("event %d: result has no preceding call", i+1)
		}
		delete(calls, callKey)
		stateKey := key(e.RunID, call.Tool, call.InputSHA256)
		if *e.ExitCode == 0 {
			delete(a.states, stateKey)
			continue
		}
		state := a.states[stateKey]
		if state.Output != e.OutputSHA256 {
			state = failureState{Output: e.OutputSHA256}
		}
		state.Count++
		state.Evidence = append(state.Evidence, e.ID)
		a.states[stateKey] = state
		if state.Count == threshold {
			a.findings = append(a.findings, Finding{Rule: "repeated-failure", RunID: e.RunID, Tool: call.Tool, Failures: state.Count, Evidence: append([]string(nil), state.Evidence...), Summary: "Same tool input failed with the same output repeatedly"})
		}
	}
	return a, nil
}

func (p Policy) Audit(events []Event) ([]Finding, error) {
	threshold, err := p.threshold()
	if err != nil {
		return nil, err
	}
	a, err := analyze(events, threshold)
	if err != nil {
		return nil, err
	}
	return a.findings, nil
}

// Check evaluates a proposed tool call against prior completed calls. Observe
// reports a would-deny decision without blocking. Enforce returns deny.
func (p Policy) Check(history []Event, proposed Event, mode string) (Decision, error) {
	if mode != "observe" && mode != "enforce" {
		return Decision{}, errors.New("mode must be observe or enforce")
	}
	if err := Validate(proposed); err != nil {
		return Decision{}, err
	}
	if proposed.Kind != "tool_call" {
		return Decision{}, errors.New("proposed event must be a tool_call")
	}
	threshold, err := p.threshold()
	if err != nil {
		return Decision{}, err
	}
	a, err := analyze(history, threshold)
	if err != nil {
		return Decision{}, err
	}
	state := a.states[key(proposed.RunID, proposed.Tool, proposed.InputSHA256)]
	if state.Count < threshold {
		return Decision{Outcome: "allow"}, nil
	}
	outcome := "observe"
	if mode == "enforce" {
		outcome = "deny"
	}
	return Decision{Outcome: outcome, Rule: "repeated-failure", Reason: "This tool call already failed repeatedly with the same result; inspect the prior failure before retrying", Evidence: append([]string(nil), state.Evidence...)}, nil
}
