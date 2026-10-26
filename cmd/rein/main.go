package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/GrayCodeAI/rein/policy"
)

const usage = `Rein: inspect agent failures and evaluate local policies

Usage:
  rein audit --input EVENTS.jsonl [--repeat N]
  rein check --input EVENTS.jsonl --event CALL.json [--mode observe|enforce] [--repeat N]

Use - as the input or event path for stdin, but not both. A deny exits with code 3.
`

func main() { os.Exit(run(os.Args[1:])) }

func run(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	if argv[0] == "help" || argv[0] == "--help" {
		fmt.Print(usage)
		return 0
	}
	command := argv[0]
	if command != "audit" && command != "check" {
		fmt.Fprintf(os.Stderr, "unknown command %q\n%s", command, usage)
		return 2
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	input := fs.String("input", "", "prior JSONL events")
	event := fs.String("event", "", "proposed tool call JSON")
	mode := fs.String("mode", "observe", "observe or enforce")
	repeat := fs.Int("repeat", 2, "identical failures before a finding")
	if err := fs.Parse(argv[1:]); err != nil {
		return 2
	}
	if *input == "" || fs.NArg() != 0 || (command == "check" && (*event == "" || (*input == "-" && *event == "-"))) {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	historyReader, err := open(*input)
	if err != nil {
		return fail(err)
	}
	defer historyReader.Close()
	history, err := policy.LoadJSONL(historyReader)
	if err != nil {
		return fail(err)
	}
	rule := policy.Policy{RepeatFailures: *repeat}
	encoder := json.NewEncoder(os.Stdout)
	if command == "audit" {
		findings, err := rule.Audit(history)
		if err != nil {
			return fail(err)
		}
		if err := encoder.Encode(findings); err != nil {
			return fail(err)
		}
		return 0
	}
	proposedReader, err := open(*event)
	if err != nil {
		return fail(err)
	}
	defer proposedReader.Close()
	proposed, err := policy.LoadJSONL(proposedReader)
	if err != nil {
		return fail(err)
	}
	if len(proposed) != 1 {
		return fail(errors.New("--event must contain exactly one JSON event"))
	}
	decision, err := rule.Check(history, proposed[0], *mode)
	if err != nil {
		return fail(err)
	}
	if err := encoder.Encode(decision); err != nil {
		return fail(err)
	}
	if decision.Outcome == "deny" {
		return 3
	}
	return 0
}

func open(path string) (io.ReadCloser, error) {
	if path == "-" {
		return io.NopCloser(os.Stdin), nil
	}
	return os.Open(path)
}

func fail(err error) int { fmt.Fprintln(os.Stderr, "rein:", err); return 1 }
