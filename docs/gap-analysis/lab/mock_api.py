# AI-Generated Code - 2026-11-25 - Auto
# This is AI generated code
"""Deliberately vulnerable mock API used to verify ASTF v2.0.2 detection gaps.

Lab-only. Binds to loopback. Every request is appended to requests.log so the
exact traffic ASTF sends (method, path, body) can be inspected afterwards.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PORT = int(os.environ.get("MOCK_PORT", "47811"))
LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requests.log")
VALID_TOKENS = {"Bearer alice-token": "alice", "Bearer bob-token": "bob"}
MAX_BODY = 64 * 1024
DELETED = set()


class Handler(BaseHTTPRequestHandler):
    server_version = "mock"

    def log_message(self, fmt, *args):
        return

    def _body(self):
        length = min(int(self.headers.get("Content-Length") or 0), MAX_BODY)
        return self.rfile.read(length).decode("utf-8", "replace") if length else ""

    def _record(self, body):
        user = VALID_TOKENS.get(self.headers.get("Authorization", ""), "-")
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"m": self.command, "p": self.path, "user": user, "body": body[:300]}) + "\n")
        return user

    def _send(self, status, obj=None, headers=None):
        payload = json.dumps(obj if obj is not None else {}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _handle(self):
        body = self._body()
        user = self._record(body)
        url = urlparse(self.path)
        path, qs = url.path, parse_qs(url.query)

        # Open redirect: any of these params is reflected into Location without validation.
        if path == "/api/v1/go":
            for p in ("next", "redirect", "url", "return", "goto"):
                if p in qs:
                    return self._send(302, {}, {"Location": qs[p][0]})
            return self._send(200, {"ok": True})

        # Debug endpoint leaking config, unauthenticated.
        if path == "/actuator/env":
            return self._send(200, {"propertySources": [{"name": "systemEnvironment",
                                                         "properties": {"DB_PASSWORD": {"value": "******"}}}]})

        if path == "/openapi.json":
            return self._send(200, {"openapi": "3.0.0", "paths": {}})

        if user == "-":
            return self._send(401, {"error": "unauthorized"})

        # Sensitive flow that rejects every request with a validation error.
        if path == "/api/v1/checkout":
            return self._send(422, {"error": "cart_id is required"})

        # Mass assignment: real bug, but only reachable when required fields are present.
        if path == "/api/v1/register" and self.command == "POST":
            try:
                data = json.loads(body or "{}")
            except ValueError:
                return self._send(400, {"error": "bad json"})
            if not isinstance(data, dict) or "username" not in data or "password" not in data:
                return self._send(400, {"error": "username and password are required"})
            data.pop("password", None)
            return self._send(201, data)

        # PATCH-only resource: anyone authenticated can patch anyone's note.
        if path.startswith("/api/v1/notes/"):
            if self.command == "PATCH":
                return self._send(200, {"id": path.rsplit("/", 1)[-1], "patched_by": user})
            return self._send(405, {"error": "method not allowed"})

        if path.startswith("/api/v1/items/") and self.command == "DELETE":
            item_id = path.rsplit("/", 1)[-1]
            if os.environ.get("STATEFUL") == "1":
                if item_id in DELETED:
                    return self._send(404, {"error": "not found"})
                DELETED.add(item_id)
            return self._send(200, {"deleted": item_id, "by": user})

        return self._send(404, {"error": "not found"})

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
