# Usage — headerprobe

## Install

```shell
pip install -e .
```

## Commands

```shell
headerprobe --help
```

## Examples

### Probe a local demo target

```shell
headerprobe check --url http://127.0.0.1:8765/login
```

### Strict CI gate

```shell
headerprobe check --url https://staging.myapp.example/login --fail-on info
```

### JSON findings for a pipeline

```shell
headerprobe check --url https://staging.myapp.example/login --json-out | jq ".counts"
```

### Self-signed cert, first response only

```shell
headerprobe check --url https://10.0.0.5/ --insecure --no-redirects
```

## Checks

| area | checks |
|---|---|
| cookies | `cookie-httponly`, `cookie-secure`, `cookie-samesite`, `cookie-samesite-none`, `cookie-lifetime` |
| CORS | `cors-wildcard-credentials`, `cors-wildcard`, `cors-null-origin`, `cors-same-origin`, `cors-vary-origin` |
| auth challenge | `auth-challenge-missing`, `auth-basic-cleartext`, `auth-basic`, `auth-legacy-scheme`, `auth-unknown-scheme`, `auth-multiple-challenges` |
| headers | `hsts-missing`, `nosniff-missing`, `frame-protection-missing`, `csp-missing`, `csp-unsafe-inline` |

Severities are `high`, `medium`, `low`, `info`, sorted worst-first. A run exits 1
when the worst finding is at or above `--fail-on` (default `medium`).

## Validation gates

- **install**: `pip install -e . (fresh venv)`
- **unit tests**: `pytest -q (26 tests, offline)`
- **CLI smoke**: `headerprobe --help; headerprobe check --url <local demo>`
- **demo run**: `logs/2026-10-25/run_demos.py -> results/demo-output.txt`
- **secret scan**: `no tokens/keys/.env/machine paths in tree`

## Exit codes

- `0` — success / nothing at or above the threshold
- `1` — findings, failures, or an unmet `--require`
- `2` — usage error, unreadable input, or rejected target
