import ipaddress
import json
import os
import base64
import urllib.request
import urllib.error
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
            response = session.get(current, headers=headers, timeout=(3, 5), allow_redirects=False, stream=True)
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


REGISTRY_REPO = os.environ.get("CLEAN_ARCHIVE_REGISTRY_REPO", "otizemlanetzag/clean-archive")
REGISTRY_PATH = "data/OFFICIAL_SITES.json"


def github_api(method, path, payload=None):
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise RuntimeError("Registry storage is not configured. Set GITHUB_TOKEN in the deployment environment.")
    url = "https://api.github.com" + path
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
        "User-Agent": "CleanArchiveSiteRegistry"
    })
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read(500).decode("utf-8", errors="replace")
        raise RuntimeError("Registry storage returned GitHub HTTP " + str(exc.code) + ": " + detail)


def add_to_official_registry(site_url):
    repo = REGISTRY_REPO
    api_path = "/repos/" + repo + "/contents/" + REGISTRY_PATH
    try:
        current = github_api("GET", api_path)
        raw = base64.b64decode(current["content"]).decode("utf-8")
        registry = json.loads(raw)
        sha = current["sha"]
    except RuntimeError as exc:
        if "HTTP 404" not in str(exc):
            raise
        registry, sha = [], None
    if not isinstance(registry, list):
        raise RuntimeError("Official registry JSON must contain a list.")
    normalized = site_url.rstrip("/")
    for entry in registry:
        if isinstance(entry, dict) and str(entry.get("url", "")).rstrip("/").casefold() == normalized.casefold():
            return False
    registry.append({"url": normalized, "verified": True, "open_source_confirmed": True})
    encoded = base64.b64encode((json.dumps(registry, ensure_ascii=False, indent=2) + "\\n").encode("utf-8")).decode("ascii")
    body = {"message": "Add verified open-source site to official registry", "content": encoded}
    if sha:
        body["sha"] = sha
    github_api("PUT", api_path, body)
    return True


class handler(BaseHTTPRequestHandler):
    def _send(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
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
            consent = payload.get("consent")
            if consent is not True:
                return self._send(400, {"verified": False, "message": "You must confirm: I own this website and confirm it is open source."})
            if not isinstance(token, str) or not token.startswith(TOKEN_PREFIX) or len(token) > 128:
                return self._send(400, {"verified": False, "message": "Generate a new verification text first."})
            page = fetch_public_page(url)
            if token.casefold() in page.casefold():
                try:
                    added = add_to_official_registry(url)
                except RuntimeError as exc:
                    return self._send(503, {"verified": True, "added": False, "message": "Ownership verified, but the official registry could not be updated: " + str(exc)})
                message = "Website verified and added to the official registry." if added else "Website verified; it is already in the official registry."
                return self._send(200, {"verified": True, "added": added, "message": message})
            return self._send(200, {"verified": False, "message": "The verification text was not found. Publish it on a public page on your website, then try again."})
        except ValueError as exc:
            self._send(400, {"verified": False, "message": str(exc)})
        except requests.RequestException:
            self._send(502, {"verified": False, "message": "Could not read the website. Check that it is public and accessible, then try again."})
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send(400, {"verified": False, "message": "Invalid JSON request."})
        except Exception:
            self._send(500, {"verified": False, "message": "The verification service encountered an unexpected error."})
