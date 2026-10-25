# Results — headerprobe

## Environment
- OS: Windows (msys2 shell), Python 3.14.3
- Runtime: python.exe in a fresh virtualenv
- Dependency manager: pip (`pip install -e .`)

## Validation performed
- install: PASS (exit 0)
- unit tests: PASS (exit 0)
- CLI help: PASS (exit 0)
- CLI demo (findings, exit 1 expected): PASS (exit 1)
- CLI usage error (exit 2 expected): PASS (exit 2)
- demo run: PASS (231 lines captured in results/demo-output.txt)
- secret/path scan: PASS (no secrets, no machine-specific paths)

## Commands executed

```shell
-m pip install -q -e .
```
# -> install: exit 0
```shell
-m pytest -q
```
# -> unit tests: exit 0
```shell
headerprobe --help
```
# -> CLI help: exit 0
```shell
headerprobe check --url http://127.0.0.1:8791/login
```
# -> CLI demo (findings, exit 1 expected): exit 1
```shell
headerprobe check --url ftp://127.0.0.1/
```
# -> CLI usage error (exit 2 expected): exit 2

## Observed result

**install**

```

```

**unit tests**

```
..........................                                               [100%]
26 passed in 0.42s
```

**CLI help**

```
  --help     Show this message and exit.
Commands:
  check  Probe URL and report auth-header findings.
```

**CLI demo (findings, exit 1 expected)**

```
│ LOW      │ csp-missing               │ no Content-Security-Policy header    │
└──────────┴───────────────────────────┴──────────────────────────────────────┘
high: 2  medium: 1  low: 5  info: 0
```

**CLI usage error (exit 2 expected)**

```
error: unsupported URL scheme: 'ftp://127.0.0.1/' (http/https only)
```

## Generated artifacts

- `results/demo-output.txt` — full demo transcript with real exit codes
- `docs/ARCHITECTURE.md`, `docs/USAGE.md`, `docs/PROJECT_SPEC.md`
- `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, `README.md`

## Known limitations

See the **Limitations** section of `README.md`. In short: single-process scope,
heuristic detection where noted, and advisory output that must be interpreted by
a human who knows the system under test.
