#!/usr/bin/env python3
"""Local demo target for headerprobe — deliberately weak response headers.

Standard library only. Run it, then point headerprobe at it:

    python examples/demo_server.py --port 8765
    headerprobe check --url http://127.0.0.1:8765/login

The response intentionally omits HttpOnly/Secure/SameSite, HSTS, CSP and
frame protection, and advertises Basic auth, so the scanner has findings to
report. Never expose this server off your own machine.
"""

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"ok": true}'
        self.send_response(401)
        self.send_header("Content-Type", "application/json")
        # deliberately weak: no HttpOnly, no Secure, no SameSite, long lived
        self.send_header("Set-Cookie", "session=demo; Path=/; Max-Age=7776000")
        self.send_header("WWW-Authenticate", 'Basic realm="demo"')
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    server = HTTPServer((args.host, args.port), Handler)
    print(f"demo target on http://{args.host}:{args.port}/ — Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
