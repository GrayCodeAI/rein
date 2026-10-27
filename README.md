# Rein

Rein is a small Go library and CLI for turning observed agent failures into deterministic policy decisions. It reads versioned JSONL tool events, reports repeat failures with event IDs, and evaluates the next tool call in **observe** or **enforce** mode. It has no model, network, or external Go dependency.

The first rule is deliberately specific: if the same tool and input fail at least twice with the same output in one run, Rein reports the pattern. In observe mode it returns `observe` without blocking. In enforce mode it returns `deny` and the CLI exits with status 3. A successful call or a different failure output resets the count. The host must honor a deny before executing the proposed call.

## Try it

```sh
go build -o rein ./cmd/rein
./rein audit --input examples/repeated-failure.jsonl
./rein check --input examples/repeated-failure.jsonl \
  --event examples/next-call.json --mode observe
./rein check --input examples/repeated-failure.jsonl \
  --event examples/next-call.json --mode enforce
```

The event stream contains `tool_call` and `tool_result` pairs linked by `call_id`. It stores tool names, IDs, SHA-256 digests of inputs and outputs, and exit codes. Raw prompts, arguments, and output are outside this format; unknown JSON fields are rejected. A host appends results after tools execute and supplies prior events when asking Rein about a proposed call. `--repeat` changes the threshold (minimum 2). `--input -` or `--event -` reads stdin.

## GrayCode boundary

Rein owns portable failure findings and policy verdicts. Reflect owns the actual tool boundary, permissions, and user approval; it can feed privacy-safe events to Rein and enforce a `deny`. Record can cite finding event IDs in a checkpoint; Recall can store a reviewed lesson linked to the checkpoint. This first release is standalone and is **not wired into Reflect** yet.

Rein was designed after studying agent reliability systems such as Failproof AI. It is independent code and does not copy Failproof's implementation or policy pack. Add more rules only when a real failure trace and an evaluation show they help without excessive false positives.

## License

MIT — see [LICENSE](LICENSE) for details. Contributions are welcome under the terms in [CONTRIBUTING.md](CONTRIBUTING.md); report security issues privately as described in [SECURITY.md](SECURITY.md).

© 2026 GrayCode AI
