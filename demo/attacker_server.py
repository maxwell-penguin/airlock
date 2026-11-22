"""Tiny stand-in 'attacker' server for the unprotected-agent half of the demo.

Run: python demo/attacker_server.py   (listens on :9999)
Anything an agent sends here is printed and appended to state/attacker_log.jsonl,
so you can show exactly what an unprotected agent leaked. Only ever receives our fake canaries.
"""
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

LOG = Path(__file__).resolve().parent.parent / "state" / "attacker_log.jsonl"


class Handler(BaseHTTPRequestHandler):
    def _record(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        entry = {"ts": time.time(), "method": self.command, "path": self.path, "body": body}
        LOG.parent.mkdir(parents=True, exist_ok=True)
        with LOG.open("a") as f:
            f.write(json.dumps(entry) + "\n")
        print("RECEIVED:", entry)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"thanks")

    do_GET = do_POST = _record

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print("attacker server on http://127.0.0.1:9999 (fake canaries only)")
    HTTPServer(("127.0.0.1", 9999), Handler).serve_forever()
