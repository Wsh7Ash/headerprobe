"""Tests for headerprobe: analysis rules, fetch contract and CLI exit codes.

All tests are offline — `probe()` is called with a stub fetcher and the CLI
is driven through Click's test runner with `headerprobe.probe.fetch` patched.
"""

import json

import pytest
from click.testing import CliRunner

import headerprobe.probe as probe_mod
from headerprobe.analysis import (
    analyze,
    check_cookies,
    check_cors,
    check_security_headers,
    check_www_authenticate,
    parse_cookies,
    worst,
)
from headerprobe.cli import main

HTTPS = "https://app.example.test/login"


def codes(findings):
    return {f["check"] for f in findings}


# ---------------------------------------------------------------- cookies

def test_parse_cookies_attributes():
    parsed = parse_cookies(["sid=abc; Path=/; HttpOnly; Secure; SameSite=Lax"])
    assert parsed[0]["name"] == "sid"
    assert parsed[0]["attrs"]["httponly"] is True
    assert parsed[0]["attrs"]["secure"] is True
    assert parsed[0]["attrs"]["samesite"] == "lax"
    assert parsed[0]["attrs"]["path"] == "/"


def test_cookie_missing_flags_on_https():
    out = check_cookies(HTTPS, {"set-cookie": "sid=abc; Path=/"})
    assert "cookie-httponly" in codes(out)
    assert "cookie-secure" in codes(out)
    assert "cookie-samesite" in codes(out)


def test_cookie_all_flags_clean():
    out = check_cookies(
        HTTPS, {"set-cookie": "sid=abc; HttpOnly; Secure; SameSite=Strict"})
    assert out == []


def test_cookie_samesite_none_requires_secure():
    out = check_cookies(
        HTTPS, {"set-cookie": "sid=abc; HttpOnly; Secure; SameSite=None"})
    assert out == []
    out = check_cookies(
        HTTPS, {"set-cookie": "sid=abc; HttpOnly; SameSite=None"})
    assert "cookie-samesite-none" in codes(out)


def test_cookie_long_lifetime_flagged():
    out = check_cookies(HTTPS, {
        "set-cookie": "sid=abc; HttpOnly; Secure; SameSite=Lax; Max-Age=99999999"})
    assert "cookie-lifetime" in codes(out)


def test_cookie_secure_not_required_over_plain_http():
    out = check_cookies("http://app.example.test/", {
        "set-cookie": "sid=abc; HttpOnly; SameSite=Lax"})
    assert "cookie-secure" not in codes(out)


# ------------------------------------------------------------------- cors

def test_cors_wildcard_with_credentials_is_high():
    out = check_cors(HTTPS, {
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true"})
    assert out[0]["check"] == "cors-wildcard-credentials"
    assert out[0]["severity"] == "high"


def test_cors_wildcard_alone_is_info():
    out = check_cors(HTTPS, {"access-control-allow-origin": "*"})
    assert out[0]["severity"] == "info"


def test_cors_null_origin_flagged():
    out = check_cors(HTTPS, {"access-control-allow-origin": "null"})
    assert "cors-null-origin" in codes(out)


def test_cors_credentialed_without_vary_flagged():
    out = check_cors(HTTPS, {
        "access-control-allow-origin": "https://admin.example.test",
        "access-control-allow-credentials": "true"})
    assert "cors-vary-origin" in codes(out)
    out = check_cors(HTTPS, {
        "access-control-allow-origin": "https://admin.example.test",
        "access-control-allow-credentials": "true",
        "vary": "Origin"})
    assert out == []


# ------------------------------------------------------- www-authenticate

def test_basic_over_http_is_high():
    out = check_www_authenticate("http://api.example.test/", 401,
                                 {"www-authenticate": 'Basic realm="x"'})
    assert out[0]["severity"] == "high"
    assert out[0]["check"] == "auth-basic-cleartext"


def test_basic_over_https_is_medium_only():
    out = check_www_authenticate(HTTPS, 401,
                                 {"www-authenticate": 'Basic realm="x"'})
    assert out[0]["severity"] == "medium"


def test_bearer_challenge_is_clean():
    assert check_www_authenticate(
        HTTPS, 401, {"www-authenticate": "Bearer"}) == []


def test_401_without_challenge_flagged():
    out = check_www_authenticate(HTTPS, 401, {})
    assert "auth-challenge-missing" in codes(out)


def test_legacy_ntlm_flagged():
    out = check_www_authenticate(HTTPS, 401,
                                 {"www-authenticate": "NTLM"})
    assert "auth-legacy-scheme" in codes(out)


# ------------------------------------------------------ security headers

def test_https_without_hsts_flagged_http_not():
    assert "hsts-missing" in codes(check_security_headers(HTTPS, {}))
    assert "hsts-missing" not in codes(check_security_headers("http://x.test/", {}))


def test_complete_security_headers_clean():
    hdrs = {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
    }
    assert check_security_headers(HTTPS, hdrs) == []


def test_clickjacking_and_csp_missing_flagged():
    out = check_security_headers(HTTPS, {"x-content-type-options": "nosniff"})
    assert {"frame-protection-missing", "csp-missing"} <= codes(out)


# --------------------------------------------------------------- analyze

def test_analyze_counts_sorted_and_worst():
    report = analyze(HTTPS, 200, {
        "set-cookie": "sid=1",
        "www-authenticate": 'Basic realm="x"',
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true",
    })
    assert report["url"] == HTTPS
    # wildcard+credentials is the only high; cookies/basic/hsts are medium
    assert report["counts"]["high"] == 1
    assert sum(report["counts"].values()) == len(report["findings"])
    # findings are sorted worst-first
    order = [f["severity"] for f in report["findings"]]
    ranks = [{"high": 0, "medium": 1, "low": 2, "info": 3}[s] for s in order]
    assert ranks == sorted(ranks)
    assert worst(report["findings"]) == "high"
    assert worst([]) is None


def test_unknown_severity_rejected():
    from headerprobe.analysis import finding
    with pytest.raises(ValueError):
        finding("x", "urgent", "nope")


# --------------------------------------------------------------- probe/cli

class StubFetcher:
    def __init__(self, status=200, headers=None, url=HTTPS, error=None):
        self.status, self.headers, self.url, self.error = status, headers or {}, url, error
        self.calls = []

    def __call__(self, url, timeout=10.0, verify=True, redirects=True):
        self.calls.append({"url": url, "timeout": timeout, "verify": verify,
                           "redirects": redirects})
        if self.error:
            raise self.error
        return probe_mod.Response(url=self.url, status=self.status,
                                  headers={k.lower(): v for k, v in self.headers.items()})


def test_probe_uses_stub_fetcher(monkeypatch):
    stub = StubFetcher(headers={"set-cookie": "sid=1; HttpOnly; Secure; SameSite=Strict",
                                "x-frame-options": "DENY",
                                "x-content-type-options": "nosniff",
                                "content-security-policy": "default-src 'self'",
                                "strict-transport-security": "max-age=1"})
    monkeypatch.setattr(probe_mod, "fetch", stub)
    report = probe_mod.probe(HTTPS)
    assert report["status"] == 200
    assert report["findings"] == []
    assert stub.calls[0]["url"] == HTTPS


def test_probe_rejects_bad_scheme():
    with pytest.raises(ValueError):
        probe_mod.fetch("ftp://example.test/")


def test_cli_exit_codes(monkeypatch):
    runner = CliRunner()
    monkeypatch.setattr(probe_mod, "fetch",
                        StubFetcher(headers={"www-authenticate": 'Basic realm="x"'}))
    # worst finding is medium >= default --fail-on medium -> exit 1
    res = runner.invoke(main, ["check", "--url", HTTPS])
    assert res.exit_code == 1, res.output

    # raising the threshold above the worst finding -> exit 0
    res = runner.invoke(main, ["check", "--url", HTTPS, "--fail-on", "high"])
    assert res.exit_code == 0, res.output

    # a high finding trips even the strictest threshold
    monkeypatch.setattr(probe_mod, "fetch", StubFetcher(headers={
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true"}))
    res = runner.invoke(main, ["check", "--url", HTTPS, "--fail-on", "high"])
    assert res.exit_code == 1, res.output

    # completely clean response -> exit 0
    monkeypatch.setattr(probe_mod, "fetch", StubFetcher(headers={
        "set-cookie": "sid=1; HttpOnly; Secure; SameSite=Strict",
        "x-frame-options": "DENY", "x-content-type-options": "nosniff",
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=1"}))
    res = runner.invoke(main, ["check", "--url", HTTPS])
    assert res.exit_code == 0, res.output


def test_cli_json_out_is_valid_json(monkeypatch):
    monkeypatch.setattr(probe_mod, "fetch", StubFetcher(status=401))
    res = CliRunner().invoke(main, ["check", "--url", HTTPS, "--json-out"])
    payload = json.loads(res.output)
    assert payload["status"] == 401
    assert isinstance(payload["findings"], list)
    assert res.exit_code in (0, 1)


def test_cli_network_error_exits_2(monkeypatch):
    import requests
    monkeypatch.setattr(probe_mod, "fetch",
                        StubFetcher(error=requests.exceptions.ConnectionError("refused")))
    res = CliRunner().invoke(main, ["check", "--url", HTTPS])
    assert res.exit_code == 2
    assert "request failed" in res.output


def test_cli_bad_scheme_exits_2(monkeypatch):
    monkeypatch.setattr(probe_mod, "fetch",
                        StubFetcher(error=ValueError("unsupported URL scheme")))
    res = CliRunner().invoke(main, ["check", "--url", "ftp://x/"])
    assert res.exit_code == 2
