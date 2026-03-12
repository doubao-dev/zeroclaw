# Runtime Debugging Guide

This note explains the three different debugging surfaces that are easy to confuse when running ZeroClaw locally.

## 1. `runtime_trace_mode` writes structured JSONL traces

These settings live under `[observability]` in `config.toml`:

```toml
[observability]
backend = "none"
runtime_trace_mode = "full"
runtime_trace_path = "state/runtime-trace.jsonl"
runtime_trace_redact = true
runtime_trace_store_raw = false
```

What this does:

- Persists runtime events to `state/runtime-trace.jsonl`
- Captures structured tool/model diagnostics for later inspection
- Supports `none`, `rolling`, and `full`

What this does not do:

- It does not increase live CLI or daemon log verbosity
- It does not control what progress text appears interactively while the process is running

Useful follow-up command:

```bash
zeroclaw doctor traces --limit 20
```

## 2. `RUST_LOG` controls live `tracing` logs

Use `RUST_LOG` when you want more real-time log output from `tracing::debug!`, `tracing::info!`, and similar calls.

Examples:

```bash
RUST_LOG=info zeroclaw daemon
RUST_LOG=debug zeroclaw daemon
RUST_LOG=debug zeroclaw agent --message "hello"
```

This affects terminal log output for the current process only. It does not change the JSONL runtime trace settings in `config.toml`.

## 3. CLI and daemon progress output is separate

ZeroClaw also has an internal progress/draft stream used for operator-facing status such as:

- thinking
- tool call counts
- retries
- loop-detection notices
- in-place tool progress blocks

This is separate from both `runtime_trace_mode` and `RUST_LOG`.

If live CLI or daemon output is still too quiet even with `RUST_LOG=debug`, the missing behavior is usually in the progress-display plumbing rather than in your `config.toml`.

## Recommended local debugging setup

Use this when you want both persisted diagnostics and verbose live logs:

```toml
[observability]
backend = "none"
runtime_trace_mode = "full"
runtime_trace_path = "state/runtime-trace.jsonl"
runtime_trace_redact = true
runtime_trace_store_raw = false
runtime_trace_include_system_prompt = false
```

```bash
RUST_LOG=debug zeroclaw daemon
```

After reproducing the issue:

```bash
zeroclaw doctor traces --limit 20
```

## Safety note

`runtime_trace_store_raw = true` can persist sensitive payloads in plaintext. Keep it off unless you are debugging in a controlled environment and plan to rotate or delete the trace file afterward.
