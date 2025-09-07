#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Obtiene tokens vía OAuth2 PKCE para X (Twitter) y muestra el refresh_token.

- Tipo de app: Native App
- REDIRECT_URI: http://localhost:8721/callback  (agregar también http://127.0.0.1:8721/callback en la app)
- SCOPES: users.read tweet.read tweet.write media.write offline.access
"""

import base64
import hashlib
import json
import os
import secrets
import socket
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlencode, urlparse, parse_qs

import requests

AUTH_BASE = "https://x.com/i/oauth2/authorize"
TOKEN_URL = "https://api.x.com/2/oauth2/token"
REDIRECT_URI = "http://localhost:8721/callback"
SCOPES = "users.read tweet.read tweet.write media.write offline.access"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def mk_verifier() -> str:
    # 43–128 chars
    v = secrets.token_urlsafe(64)
    return v[:128]


def run_server_once(result_holder: dict):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path != "/callback":
                self.send_response(404)
                self.end_headers()
                return
            qs = parse_qs(parsed.query)
            code = qs.get("code", [""])[0]
            state = qs.get("state", [""])[0]
            result_holder["code"] = code
            result_holder["state"] = state
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"OK. Volver a la terminal.")
        def log_message(self, *args, **kwargs):
            return

    # Bind robusto (puerto fijo 8721)
    httpd = HTTPServer(("0.0.0.0", 8721), Handler)
    httpd.handle_request()  # una sola solicitud
    httpd.server_close()


def main():
    client_id = os.getenv("X_CLIENT_ID", "").strip()
    if not client_id:
        print("Definí X_CLIENT_ID en el entorno.")
        return

    code_verifier = mk_verifier()
    code_challenge = b64url(hashlib.sha256(code_verifier.encode("ascii")).digest())
    state = secrets.token_urlsafe(16)

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    url = f"{AUTH_BASE}?{urlencode(params)}"
    print("Abriendo navegador para autorizar…")
    print(url)

    holder = {}
    t = threading.Thread(target=run_server_once, args=(holder,), daemon=True)
    t.start()
    webbrowser.open(url)

    # Esperar a que llegue el code
    t.join(timeout=300)
    if "code" not in holder:
        print("No se recibió 'code'.")
        return

    data = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": holder["code"],
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    r = requests.post(TOKEN_URL, data=data, headers=headers, timeout=60)
    try:
        j = r.json()
    except Exception:
        j = {"error": r.text[:200]}
    print(json.dumps(j, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
