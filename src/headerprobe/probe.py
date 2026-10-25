"""HTTP fetch layer for headerprobe.

`fetch()` is the only function that touches the network, which keeps
`analysis.py` fully testable offline and lets the CLI tests substitute
a stub transport.
"""

from __future__ import annotations

from dataclasses import dataclass

import requests

from .analysis import analyze

DEFAULT_TIMEOUT = 10.0
USER_AGENT = "headerprobe/0.1 (+authorized-testing-only)"


@dataclass
class Response:
    url: str
    status: int
    headers: dict


def fetch(url: str, timeout: float = DEFAULT_TIMEOUT, verify: bool = True,
          redirects: bool = True) -> Response:
    """GET `url` and return a plain data object. Raises requests.RequestException."""
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"unsupported URL scheme: {url!r} (http/https only)")
    resp = requests.get(
        url,
        timeout=timeout,
        verify=verify,
        allow_redirects=redirects,
        headers={"User-Agent": USER_AGENT},
    )
    return Response(url=str(resp.url), status=resp.status_code,
                    headers={k.lower(): v for k, v in resp.headers.items()})


def probe(url: str, timeout: float = DEFAULT_TIMEOUT, verify: bool = True,
          redirects: bool = True, fetcher=None) -> dict:
    """Fetch `url` and analyze its auth-relevant response headers.

    `fetcher` defaults to the module-level `fetch` looked up at call time so
    tests (and the CLI tests) can substitute a stub transport.
    """
    resp = (fetcher or fetch)(url, timeout=timeout, verify=verify,
                              redirects=redirects)
    report = analyze(resp.url, resp.status, resp.headers)
    report["final_url"] = resp.url
    return report
