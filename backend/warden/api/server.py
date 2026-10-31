"""HTTP server: serves the web console and routes /api/* to the handlers. Standard library only.

    python3 -m warden.api.server            # host and port come from config/settings.json
"""
from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from warden import config
from warden.api import handlers


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(config.FRONTEND_DIR), **kwargs)

    def log_message(self, fmt, *args):  # keep the terminal quiet during demos
        pass

    def _send_json(self, status: int, payload) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _api(self, method: str) -> None:
        path = self.path.split("?", 1)[0].rstrip("/")
        handler = handlers.ROUTES.get((method, path))
        if handler is None:
            known = any(p == path for _, p in handlers.ROUTES)
            self._send_json(405 if known else 404,
                            {"error": f"{method} {path} is not supported." if known else f"No API endpoint at {path}."})
            return
        body = {}
        if method == "POST":
            length = int(self.headers.get("Content-Length") or 0)
            if length > handlers.server_cfg()["max_body_bytes"]:
                self._send_json(413, {"error": "The request body is too large."})
                return
            raw = self.rfile.read(length) if length else b""
            try:
                body = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                self._send_json(400, {"error": "The request body is not valid JSON."})
                return
            if not isinstance(body, dict):
                self._send_json(400, {"error": "The request body must be a JSON object."})
                return
        try:
            self._send_json(200, handler(body))
        except handlers.ApiError as e:
            self._send_json(e.status, {"error": str(e)})
        except config.DataError as e:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"A data file is broken: {e}"})
        except Exception as e:  # never leak a traceback to the page
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR,
                            {"error": f"Something went wrong on the server ({type(e).__name__})."})

    def do_GET(self):
        if self.path.startswith("/api/"):
            self._api("GET")
        else:
            super().do_GET()

    def do_POST(self):
        if self.path.startswith("/api/"):
            self._api("POST")
        else:
            self._send_json(404, {"error": "Not found."})

    def end_headers(self):
        if not self.path.startswith("/api/"):
            self.send_header("Cache-Control", "no-cache")
        super().end_headers()


def make_server(port: int | None = None, host: str | None = None) -> ThreadingHTTPServer:
    handlers.STATE = handlers.State()
    cfg = handlers.server_cfg()
    return ThreadingHTTPServer((host or cfg["host"], cfg["port"] if port is None else port), Handler)


def main() -> None:
    cfg = handlers.server_cfg()
    ap = argparse.ArgumentParser(description="Warden: provenance firewall for AI agents")
    ap.add_argument("--port", type=int, default=cfg["port"])
    ap.add_argument("--host", default=cfg["host"])
    args = ap.parse_args()
    srv = make_server(args.port, args.host)
    print(f"Warden is running at http://{args.host}:{args.port}  (Ctrl+C to stop)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
