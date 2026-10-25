# Architecture — headerprobe

## Overview

`headerprobe` (api-security) is a single-package Python CLI: a `src/headerprobe/` package
with a pure logic module and a Click command layer, console-script entry point
`headerprobe = headerprobe.cli:main`, and no runtime services.

### `src/headerprobe/analysis.py`

Pure rules over (url, status, headers): cookie flags and lifetimes, CORS policy, WWW-Authenticate schemes, security headers. No I/O; each rule appends finding(check, severity, message).

### `src/headerprobe/probe.py`

The only network code. fetch() issues one GET with a timeout and returns a plain Response dataclass; probe() composes fetch + analyze and accepts an injectable fetcher for tests.

### `src/headerprobe/cli.py`

Click group with `check` (--url, --timeout, --insecure, --no-redirects, --fail-on, --json-out). Exits 0/1/2.


## Design decisions

- **Logic/rendering separation.** Every decision (classify, parse, lint, plan,
  probe) lives in a pure module with no console output, so tests assert on data
  rather than on terminal formatting.
- **Exit codes as the CI contract.** 0 = clean/success, 1 = findings or failed
  requirement, 2 = usage or read error. `--json-out` switches stdout to
  machine-readable JSON without changing exit codes.
- **Small dependency surface.** Only `click` (CLI), `rich` (tables) and, where
  network I/O is the point, `requests`; everything else is the standard library.

## Data flow

```
input (file / URL / ports + flags)
   -> Click command validates arguments
   -> pure module computes findings / profiles / verdicts / plan
   -> renderer prints table or JSON
   -> process exits 0 / 1 / 2
```

## Testing strategy

tests/test_probe.py covers every rule offline (cookie flags, CORS cases, challenge schemes, security headers), finding sort order and counts, plus CLI exit codes through a stub transport: 0 clean, 1 at/above threshold, 2 usage or network error.
