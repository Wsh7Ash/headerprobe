# headerprobe

**Inspect the auth-related response headers of endpoints you own — session
cookies, `WWW-Authenticate` and CORS — and get a severity-ranked list of what
an attacker would notice first.**

## The problem

Auth misconfigurations hide in response headers: a session cookie without
`HttpOnly`, a `WWW-Authenticate: Basic` challenge on plain HTTP, CORS
advertising `*` together with `Allow-Credentials: true`. Reading every header
by hand for each endpoint is slow, so these issues ship. headerprobe fetches a
URL once and runs 24 header rules against what came back.

## Features

- **Cookie analysis** — `HttpOnly`, `Secure`, `SameSite` (including
  `SameSite=None` without `Secure`), and lifetimes over 30 days.
- **CORS analysis** — wildcard-with-credentials, `null` origin, credentialed
  CORS without `Vary: Origin`, redundant same-origin policies.
- **`WWW-Authenticate` analysis** — Basic over cleartext, legacy NTLM/Negotiate,
  401s with no challenge at all.
- **Security headers** — HSTS on HTTPS, `nosniff`, clickjacking protection,
  CSP presence and `unsafe-inline`.
- **`--fail-on` threshold** and `--json-out`, so it gates a CI job as easily
  as it reads in a terminal.

## Example output

```console
$ headerprobe check --url http://127.0.0.1:8765/login
http://127.0.0.1:8765/login  status 401
                                   Findings
┌──────────┬───────────────────────────┬────────────────────────────────────┐
│ Severity │ Check                     │ Message                            │
├──────────┼───────────────────────────┼────────────────────────────────────┤
│ HIGH     │ cors-wildcard-credentials │ Access-Control-Allow-Origin: * ... │
│ HIGH     │ auth-basic-cleartext      │ Basic credentials are base64 ...   │
│ MEDIUM   │ cookie-httponly           │ cookie 'session' is missing        │
│ LOW      │ cookie-samesite           │ cookie 'session' has no SameSite   │
└──────────┴───────────────────────────┴────────────────────────────────────┘
high: 2  medium: 1  low: 5  info: 0
[exit 1]
```

Exit codes: `0` nothing at/above `--fail-on`, `1` findings at/above the
threshold, `2` usage or network error.

## Architecture

Two layers, deliberately separated:

```
src/headerprobe/
├── analysis.py   # pure rules: (url, status, headers) -> findings  (no I/O)
├── probe.py      # the only code that touches the network: fetch() -> Response
└── cli.py        # click group: rendering, thresholds, exit codes
```

Because the rules are pure functions, the test suite exercises every one of
them offline, and the CLI tests substitute a stub transport.

## Requirements

- Python 3.10+
- `click`, `requests`, `rich` (installed automatically)

## Installation

```shell
git clone https://github.com/Wsh7Ash/headerprobe
cd headerprobe
pip install -e .
```

## Quick start

```shell
# a local target with deliberately weak headers ships with the repo
python examples/demo_server.py --port 8765 &
headerprobe check --url http://127.0.0.1:8765/login
```

## Usage

```shell
# default threshold: exit 1 on medium or worse
headerprobe check --url https://staging.myapp.example/login

# strictest gate for CI
headerprobe check --url https://staging.myapp.example/login --fail-on info

# machine-readable report
headerprobe check --url https://staging.myapp.example/login --json-out

# self-signed staging cert, don't follow redirects
headerprobe check --url https://10.0.0.5/ --insecure --no-redirects
```

```shell
headerprobe check --url http://127.0.0.1:8765/login --json-out \
  | jq '.counts, .findings[0].severity'
```

## Configuration

| Option | Default | Purpose |
| --- | --- | --- |
| `--timeout` | `10.0` | request timeout in seconds |
| `--insecure` | off | skip TLS verification (testing only) |
| `--no-redirects` | off | inspect the first response instead of the final one |
| `--fail-on` | `medium` | severity that turns a finding into exit 1 |

## Testing

```shell
pip install -e . pytest
pytest -q            # 26 tests, fully offline (stub transport)
```

## Project structure

```
headerprobe/
├── src/headerprobe/{analysis,probe,cli}.py
├── tests/test_probe.py
├── examples/demo_server.py
├── docs/{ARCHITECTURE,USAGE,PROJECT_SPEC}.md
├── results/demo-output.txt
├── RESULTS.md
└── .github/workflows/ci.yml
```

## Limitations

- One request per run, and only `GET`: it is a header inspector, not a crawler.
- CORS rules see only the response headers; an `Origin`-reflecting policy is
  detected via `Vary`, not by replaying requests with different origins.
- Redirect chains are collapsed to the final response unless `--no-redirects`.
- Rules are advisory: whether a finding matters depends on your app.

## Roadmap

- Optional `Origin` replay to verify reflected-CORS policies.
- `--header` for passing an authenticated session cookie.
- Baseline files so CI can compare against yesterday's findings.

## Security

Only probe endpoints you own or are authorized to test. Tokens and cookies in
responses are sensitive: `--json-out` output contains header values verbatim.
See [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
