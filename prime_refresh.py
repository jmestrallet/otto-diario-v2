#!/usr/bin/env python3
import base64
import hashlib
import http.server
import json
import os
import secrets
import threading
import urllib.parse
import webbrowser

import requests

REDIRECT_URI = "http://localhost:8721/callback"
SCOPE = "users.read tweet.read tweet.write media.write offline.access"
AUTH_URL = "https://twitter.com/i/oauth2/authorize"
TOKEN_URL = "https://api.x.com/2/oauth2/token"

def _pkce_pair():
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge

def main():
    client_id = os.environ["X_CLIENT_ID"]
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(16)
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    url = AUTH_URL + "?" + urllib.parse.urlencode(params)
    print("Open:", url)
    webbrowser.open(url)

    code_box = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            qs = urllib.parse.urlparse(self.path).query
            q = urllib.parse.parse_qs(qs)
            if "code" in q:
                code_box["code"] = q["code"][0]
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Code received. You may close this window.")
            else:
                self.send_response(400)
                self.end_headers()

        def log_message(self, format, *args):
            pass

    server = http.server.HTTPServer(("localhost", 8721), Handler)

    def _serve():
        server.handle_request()

    threading.Thread(target=_serve, daemon=True).start()

    while "code" not in code_box:
        pass
    server.server_close()

    data = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code_box["code"],
        "redirect_uri": REDIRECT_URI,
        "code_verifier": verifier,
    }
    r = requests.post(TOKEN_URL, data=data)
    print(json.dumps(r.json(), indent=2))


if __name__ == "__main__":
    main()
