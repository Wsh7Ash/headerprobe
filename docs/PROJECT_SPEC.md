# PROJECT SPEC — headerprobe

| Field | Value |
|---|---|
| Name | `headerprobe` |
| Category | api-security |
| Target user | Developers and reviewers checking endpoints they own |
| Problem | Auth misconfigurations live in response headers — a session cookie without HttpOnly, Basic auth over plain HTTP, wildcard CORS with credentials — and manual re-reading per endpoint is slow, so they ship. |
| Solution | A CLI that fetches one URL and runs 24 pure header rules over the response, returning severity-ranked findings with a CI-friendly --fail-on threshold and JSON output. |
| Core workflow | point at a URL -> read ranked findings -> fix headers -> gate CI |
| Stack | Python >=3.10, click, rich |
| Test strategy | tests/test_probe.py covers every rule offline (cookie flags, CORS cases, challenge schemes, security headers), finding sort order and counts, plus CLI exit codes through a stub transport: 0 clean, 1 at/above threshold, 2 usage or network error. |
| Demo strategy | `logs/2026-10-25/run_demos.py` runs the real workflow and captures `results/demo-output.txt` with asserted exit codes |
| Safety | Probes only the URL you name. No crawling, no scanning of hosts you did not pass, no payload injection. Response headers may contain session cookies — treat --json-out as sensitive. |
| Definition of done | install + pytest + CLI smoke + demo transcript + secret scan all pass; docs (README, ARCHITECTURE, USAGE, CHANGELOG, CONTRIBUTING, SECURITY) present; pushed with green CI |

## Must-have features

- Core workflow end to end: point at a URL -> read ranked findings -> fix headers -> gate CI
- Exit-code contract (0/1/2) usable from CI
- `--json-out` machine-readable output where a machine should read it

## Nice-to-have (deferred)

- See README Roadmap.
