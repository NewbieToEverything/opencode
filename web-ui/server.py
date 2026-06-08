#!/usr/bin/env python3
"""OpenCode Web Session Browser — reverse proxy + static file server.

Zero-dependency Python server. Auto-discovers a running `opencode serve`
instance (port, PID, cwd), serves a self-contained HTML/JS session browser
at the web port, and proxies REST API calls to the OpenCode backend — no
CORS needed, auth forwarded transparently.

Usage:
    python3 server.py                       # web :8080, auto-detect
    python3 server.py 9090                  # web :9090, auto-detect
    python3 server.py 9090 4096             # web :9090, opencode on :4096

Requirements: Python 3.13+, Linux with /proc filesystem.

Files:
  server.py    — This script.
  index.html   — Self-contained SPA (~400 lines), served statically.
                 Must be in the same directory as server.py.
"""
import http.server
import urllib.request
import urllib.parse
import urllib.error
import socket
import glob
import json
import re
import sys
import os

WEB_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
OC_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else None

PROXY_PREFIXES = ("/project", "/experimental")


def _listen_pid(port):
    """Return PID of process listening on localhost:port via /proc/net/tcp."""
    hex_port = format(port, "04x")
    inode = None
    try:
        for line in open("/proc/net/tcp", "r"):
            parts = line.strip().split()
            if len(parts) < 10:
                continue
            addr = parts[1]
            colon = addr.find(":")
            if colon < 0:
                continue
            if addr[colon + 1 :].lower() == hex_port and parts[3] == "0A":
                inode = parts[9]
                break
    except OSError:
        return None
    if not inode:
        return None
    for proc in glob.glob("/proc/[0-9]*/fd/[0-9]*"):
        try:
            link = os.readlink(proc)
            if f"socket:[{inode}]" in link:
                return int(proc.split("/")[2])
        except OSError:
            pass
    return None


def find_opencode_port():
    """Find port and cwd of running opencode serve instance.
    Returns (port, cwd) tuple.
    """
    for port in (4096, 1234, 4097, 4095, 3000, 8080):
        if not _check_port(port):
            continue
        pid = _listen_pid(port)
        if pid is not None:
            try:
                cwd = os.readlink(f"/proc/{pid}/cwd")
                return port, cwd
            except OSError:
                pass
        return port, ""

    # Fallback: scan cmdlines for non-standard ports
    for proc in glob.glob("/proc/[0-9]*/cmdline"):
        try:
            text = open(proc, "rb").read().decode("utf-8", errors="ignore")
            if "opencode" not in text or "serve" not in text:
                continue
            m = re.search(r"--port[= ](\d+)", text)
            if m:
                port = int(m.group(1))
                if _check_port(port):
                    pid = _listen_pid(port)
                    if pid is not None:
                        try:
                            cwd = os.readlink(f"/proc/{pid}/cwd")
                            return port, cwd
                        except OSError:
                            pass
                    return port, ""
        except (OSError, ValueError):
            pass

    return None, ""


def _check_port(port):
    """Return True if http://localhost:port responds to GET /project."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)
    result = s.connect_ex(("127.0.0.1", port))
    s.close()
    if result != 0:
        return False
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/project")
        with urllib.request.urlopen(req, timeout=1) as resp:
            body = resp.read().decode("utf-8", errors="ignore").strip()
            return body.startswith("[")
    except Exception:
        return False



class Handler(http.server.SimpleHTTPRequestHandler):
    backend = None
    cwd = ""
    vcs = ""

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/__backend":
            self._json({"url": f"http://localhost:{self.backend}" if self.backend else None,
                        "connected": self.backend is not None,
                        "cwd": self.cwd,
                        "vcs": self.vcs})

        elif parsed.path.startswith(PROXY_PREFIXES):
            if not self.backend:
                self._error(502, {"error": "no opencode server found"})
                return
            self._proxy(parsed.path + ("?" + parsed.query if parsed.query else ""))

        else:
            super().do_GET()

    def _json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status, data):
        self._json(data, status)

    def _proxy(self, path):
        url = f"http://localhost:{self.backend}{path}"
        try:
            req = urllib.request.Request(url)
            if "Authorization" in self.headers:
                req.add_header("Authorization", self.headers["Authorization"])
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
                self.send_response(resp.status)
                for key, val in resp.headers.items():
                    if key.lower() == "transfer-encoding":
                        continue
                    self.send_header(key, val)
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as e:
            body = e.read()
            self.send_response(e.code)
            for key, val in e.headers.items():
                if key.lower() == "transfer-encoding":
                    continue
                self.send_header(key, val)
            self.end_headers()
            self.wfile.write(body)
        except urllib.error.URLError:
            self._error(502, {"error": "cannot connect to opencode server"})

    def log_message(self, fmt, *args):
        if args and isinstance(args[0], str) and args[0].startswith(PROXY_PREFIXES):
            super().log_message(fmt, *args)


def main():
    if OC_PORT is not None:
        port = OC_PORT
        cwd = ""
        if _check_port(port):
            pid = _listen_pid(port)
            if pid is not None:
                try:
                    cwd = os.readlink(f"/proc/{pid}/cwd")
                except OSError:
                    pass
        Handler.backend = port
        Handler.cwd = cwd
        Handler.vcs = "git" if cwd and os.path.isdir(os.path.join(cwd, ".git")) else ""
        print(f"opencode API:  http://localhost:{port}")
        if cwd:
            print(f"Serving dir:   {cwd}")
    else:
        port, cwd = find_opencode_port()
        if port:
            Handler.backend = port
            Handler.cwd = cwd
            Handler.vcs = "git" if cwd and os.path.isdir(os.path.join(cwd, ".git")) else ""
            print(f"opencode API:  http://localhost:{port}")
            if cwd:
                print(f"Serving dir:   {cwd}")
        else:
            Handler.backend = None
            Handler.cwd = ""
            print("WARNING: no opencode serve found; open in browser will show connection error")

    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    srv = http.server.HTTPServer(("0.0.0.0", WEB_PORT), Handler)
    print(f"Web UI:        http://localhost:{WEB_PORT}/")
    print("Press Ctrl+C to stop")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        srv.server_close()


if __name__ == "__main__":
    main()
