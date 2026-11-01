"""Serve site/ locally with the same headers render.yaml gives Render.

    python3 serve_site.py [port]

So the Content-Security-Policy is tested before deploy, not after.
"""
import functools
import http.server
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent
HEADERS = re.findall(r'name: (\S+)\n\s+value: "(.*)"', (ROOT / "render.yaml").read_text())


class Handler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        for name, value in HEADERS:
            self.send_header(name, value)
        super().end_headers()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8791
    handler = functools.partial(Handler, directory=str(ROOT / "site"))
    print(f"serving site/ with {len(HEADERS)} Render headers on http://127.0.0.1:{port}")
    http.server.ThreadingHTTPServer(("127.0.0.1", port), handler).serve_forever()
