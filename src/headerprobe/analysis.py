"""Pure analysis of an HTTP response's auth-relevant headers.

Everything here operates on plain (url, status, headers) data — no I/O —
so the rules can be exercised offline in tests. Severities:

    high    exploitable or credential-exposing misconfiguration
    medium  weak/broken defensive control worth fixing now
    low     hardening gap
    info    observation, no action required
"""

from __future__ import annotations

from urllib.parse import urlparse

SEVERITIES = ("high", "medium", "low", "info")
_SEVERITY_ORDER = {name: idx for idx, name in enumerate(SEVERITIES)}

SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
)

_VALID_SAMESITE = {"lax", "strict", "none"}


def finding(check: str, severity: str, message: str) -> dict:
    if severity not in _SEVERITY_ORDER:
        raise ValueError(f"unknown severity: {severity}")
    return {"check": check, "severity": severity, "message": message}


def parse_cookies(header_values: list[str]) -> list[dict]:
    """Split raw Set-Cookie values into (name, attributes) dictionaries."""
    cookies = []
    for raw in header_values:
        parts = [p.strip() for p in raw.split(";")]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0].strip()
        attrs: dict[str, str | bool] = {}
        for attr in parts[1:]:
            if "=" in attr:
                key, val = attr.split("=", 1)
                key = key.strip().lower()
                # SameSite tokens are case-insensitive; normalise once here.
                attrs[key] = val.strip().lower() if key == "samesite" else val.strip()
            else:
                attrs[attr.strip().lower()] = True
        cookies.append({"name": name, "attrs": attrs})
    return cookies


def _get_all(headers: dict, key: str) -> list[str]:
    """Return every value for a header, tolerating dict-of-list or str."""
    val = headers.get(key)
    if val is None:
        return []
    if isinstance(val, (list, tuple)):
        return [str(v) for v in val]
    return [str(val)]


def _has(headers: dict, key: str) -> bool:
    return bool(_get_all(headers, key))


def check_cookies(url: str, headers: dict) -> list[dict]:
    findings = []
    secure_ctx = urlparse(url).scheme == "https"
    for i, raw in enumerate(_get_all(headers, "set-cookie")):
        cookies = parse_cookies([raw])
        if not cookies:
            continue
        cookie = cookies[0]
        name, attrs = cookie["name"], cookie["attrs"]
        label = f"cookie {name!r}"
        if "httponly" not in attrs:
            findings.append(finding(
                "cookie-httponly", "medium",
                f"{label} is missing HttpOnly (readable from JavaScript)"))
        if "secure" not in attrs and secure_ctx:
            findings.append(finding(
                "cookie-secure", "medium",
                f"{label} is missing the Secure flag on an HTTPS response"))
        if "samesite" not in attrs:
            findings.append(finding(
                "cookie-samesite", "low",
                f"{label} has no SameSite attribute (defaults vary by browser)"))
        elif attrs["samesite"] is True or str(attrs["samesite"]).lower() not in _VALID_SAMESITE:
            findings.append(finding(
                "cookie-samesite", "low",
                f"{label} has an unrecognised SameSite value: {attrs['samesite']!r}"))
        elif str(attrs["samesite"]).lower() == "none" and "secure" not in attrs:
            findings.append(finding(
                "cookie-samesite-none", "high",
                f"{label} sets SameSite=None without Secure; browsers reject it"))
        if isinstance(attrs.get("max-age"), str):
            try:
                if int(attrs["max-age"]) > 86400 * 30:
                    findings.append(finding(
                        "cookie-lifetime", "low",
                        f"{label} lives longer than 30 days (max-age={attrs['max-age']})"))
            except ValueError:
                findings.append(finding(
                    "cookie-lifetime", "low",
                    f"{label} has a non-numeric max-age={attrs['max-age']!r}"))
        del i
    return findings


def check_cors(url: str, headers: dict) -> list[dict]:
    findings = []
    acao = _get_all(headers, "access-control-allow-origin")
    acac = [v.lower() for v in _get_all(headers, "access-control-allow-credentials")]
    allows_credentials = any(v == "true" for v in acac)
    if not acao:
        return findings
    for origin in acao:
        if origin == "*" and allows_credentials:
            findings.append(finding(
                "cors-wildcard-credentials", "high",
                "Access-Control-Allow-Origin: * combined with "
                "Allow-Credentials: true is rejected by browsers and indicates "
                "a misconfigured policy"))
        elif origin == "*":
            findings.append(finding(
                "cors-wildcard", "info",
                "wildcard CORS allows any site to read public responses"))
        elif origin == "null":
            findings.append(finding(
                "cors-null-origin", "medium",
                "Access-Control-Allow-Origin: null can be set by sandboxed "
                "iframes and should not be trusted"))
        elif urlparse(origin).netloc and urlparse(origin).netloc == urlparse(url).netloc:
            findings.append(finding(
                "cors-same-origin", "low",
                "CORS allows the response's own origin — CORS is redundant here"))
        if allows_credentials and origin not in ("*", "null") and not _has(headers, "vary"):
            findings.append(finding(
                "cors-vary-origin", "low",
                "credentialed CORS without 'Vary: Origin' risks cached cross-origin "
                "responses"))
    return findings


def check_www_authenticate(url: str, status: int, headers: dict) -> list[dict]:
    findings = []
    challenges = _get_all(headers, "www-authenticate")
    scheme = urlparse(url).scheme
    if status == 401 and not challenges:
        findings.append(finding(
            "auth-challenge-missing", "low",
            "401 response carries no WWW-Authenticate challenge"))
        return findings
    for raw in challenges:
        first = raw.split(",")[0].strip().lower()
        realm = raw.split("realm=", 1)[-1].split(",")[0].strip().strip('"') if "realm=" in raw.lower() else ""
        if first.startswith("basic"):
            if scheme != "https":
                findings.append(finding(
                    "auth-basic-cleartext", "high",
                    "Basic credentials are base64, not encryption — challenge offered "
                    "over a non-HTTPS connection"))
            else:
                findings.append(finding(
                    "auth-basic", "medium",
                    f"Basic auth (realm={realm or 'unset'}) sends credentials on every "
                    "request with no expiry; prefer a token scheme"))
        elif first.startswith(("ntlm", "negotiate")):
            findings.append(finding(
                "auth-legacy-scheme", "medium",
                f"{first.title()} is a connection-oriented legacy scheme; prefer "
                "Bearer tokens"))
        elif first.startswith("bearer"):
            pass  # token scheme is the expected modern answer
        else:
            findings.append(finding(
                "auth-unknown-scheme", "info",
                f"unrecognised auth scheme: {first.split(' ')[0]!r}"))
    if len(challenges) > 1:
        findings.append(finding(
            "auth-multiple-challenges", "info",
            f"{len(challenges)} WWW-Authenticate challenges advertised"))
    return findings


def check_security_headers(url: str, headers: dict) -> list[dict]:
    findings = []
    secure_ctx = urlparse(url).scheme == "https"
    if secure_ctx and not _has(headers, "strict-transport-security"):
        findings.append(finding(
            "hsts-missing", "medium",
            "no Strict-Transport-Security header on an HTTPS response"))
    if not _has(headers, "x-content-type-options"):
        findings.append(finding(
            "nosniff-missing", "low",
            "no X-Content-Type-Options: nosniff"))
    has_frame = _has(headers, "x-frame-options")
    csp = " ".join(_get_all(headers, "content-security-policy"))
    if not has_frame and "frame-ancestors" not in csp:
        findings.append(finding(
            "frame-protection-missing", "low",
            "no X-Frame-Options and no CSP frame-ancestors (clickjacking)"))
    if not csp:
        findings.append(finding(
            "csp-missing", "low",
            "no Content-Security-Policy header"))
    elif "unsafe-inline" in csp:
        findings.append(finding(
            "csp-unsafe-inline", "low",
            "Content-Security-Policy uses 'unsafe-inline'"))
    return findings


def analyze(url: str, status: int, headers: dict) -> dict:
    """Run every rule and return a report dict with sorted findings."""
    findings = []
    findings += check_cookies(url, headers)
    findings += check_cors(url, headers)
    findings += check_www_authenticate(url, status, headers)
    findings += check_security_headers(url, headers)
    findings.sort(key=lambda f: _SEVERITY_ORDER[f["severity"]])
    counts = {name: 0 for name in SEVERITIES}
    for f in findings:
        counts[f["severity"]] += 1
    return {"url": url, "status": status, "findings": findings, "counts": counts}


def worst(findings: list[dict]) -> str | None:
    """Highest severity present, or None when there are no findings."""
    for name in SEVERITIES:
        if any(f["severity"] == name for f in findings):
            return name
    return None
