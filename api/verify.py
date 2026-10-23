import ipaddress
import json
import socket
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, urljoin

import requests


MAX_BODY = 1_000_000
MAX_REDIRECTS = 3
TOKEN_PREFIX = "CLEAN-ARCHIVE-OWNERSHIP:"


def validate_public_url(raw_url):
    if not isinstance(raw_url, str) or len(raw_url) > 2048:
        raise ValueError("Enter a valid public website URL.")
    parsed = urlparse(raw_url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Only public HTTP or HTTPS website URLs are supported.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing usernames or passwords are not allowed.")
    if parsed.port and parsed.port not in (80, 443):
        raise ValueError("Only standard web ports (80 and 443) are allowed.")
    hostname = parsed.hostname.rstrip(".")
    if hostname.lower() == "localhost" or hostname.lower().endswith(".localhost"):
        raise ValueError("Local and private websites cannot be verified.")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)}
    except socket.gaierror:
        raise ValueError("The website hostname could not be resolved.")
    if not addresses:
        raise ValueError("The website hostname could not be resolved.")
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%")[0])
        if not ip.is_global:
            raise ValueError("Private, local, and non-public network addresses cannot be verified.")
    return raw_url.strip()


def fetch_public_page(url):
    headers = {"User-Agent": "CleanArchiveSiteVerifier/1.0 (+public website ownership check)", "Accept": "text/html,text/plain;q=0.9,*/*;q=0.1"}
    session = requests.Session()
    session.trust_env = False
    current = url
    try:
        for redirect_count in range(MAX_REDIRECTS + 1):
            current = validate_public_url(current)
            response = session.get(current, headers=headers, timeout=(4, 7), allow_redirects=False, stream=True)
            if response.is_redirect or response.is_permanent_redirect:
                location = response.headers.get("Location")
                response.close()
                if not location or redirect_count >= MAX_REDIRECTS:
                    raise ValueError("The website redirected too many times.")
                current = urljoin(current, location)
                continue
            response.raise_for_status()
            chunks = []
            total = 0
            for chunk in response.iter_content(chunk_size=16384):
                if not chunk:
                    continue
                total += len(chunk)
                if total > MAX_BODY:
                    break
                chunks.append(chunk)
            response.close()
            encoding = response.encoding or "utf-8"
            return b"".join(chunks).decode(encoding, errors="replace")
        raise ValueError("The website redirected too many times.")
    finally:
        session.close()


class handler(BaseHTTPRequestHandler):
    def _send(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Access-Control-Allow-Origin", "same-origin")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        self._send(405, {"verified": False, "message": "Use POST to verify a website."})

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 8192:
                return self._send(400, {"verified": False, "message": "Invalid request size."})
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            url = validate_public_url(payload.get("url"))
            token = payload.get("token")
            if not isinstance(token, str) or not token.startswith(TOKEN_PREFIX) or len(token) > 128:
                return self._send(400, {"verified": False, "message": "Generate a new verification text first."})
            page = fetch_public_page(url)
            if token.casefold() in page.casefold():
                return self._send(200, {"verified": True, "message": "Verified: the exact verification text was found on the public website."})
            return self._send(200, {"verified": False, "message": "The verification text was not found. Publish it on a public page on your website, then try again."})
        except ValueError as exc:
            self._send(400, {"verified": False, "message": str(exc)})
        except requests.RequestException:
            self._send(502, {"verified": False, "message": "Could not read the website. Check that it is public and accessible, then try again."})
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send(400, {"verified": False, "message": "Invalid JSON request."})
        except Exception:
            self._send(500, {"verified": False, "message": "The verification service encountered an unexpected error."})
