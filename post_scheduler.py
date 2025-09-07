#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Programación de publicaciones en X (Twitter) con OAuth2 PKCE y API v2.
- Lee calendar.csv (zona horaria America/Montevideo).
- Publica si when_utc ∈ [now - WINDOW_MIN, now].
- Soporta texto + 1 imagen (ruta local o URL).
- Múltiples cuentas via refresh_token por cuenta (ACC1..ACC3).
- Evita duplicados con posted.csv.
Requisitos: Python 3.11, requests (nada más).
"""

from __future__ import annotations

import csv
import json
import os
import sys
import time
import hashlib
import mimetypes
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from typing import Optional, Dict, Tuple
from urllib.parse import urlparse

import requests

API_BASE = "https://api.x.com"
OAUTH_TOKEN_URL = f"{API_BASE}/2/oauth2/token"
MEDIA_UPLOAD_URL = "https://upload.x.com/2/media/upload"  # <- esta es la que cambiamos
MEDIA_METADATA_URL = f"{API_BASE}/2/media/metadata"
TWEETS_URL = f"{API_BASE}/2/tweets"
ME_URL = f"{API_BASE}/2/users/me"

MVD_TZ = ZoneInfo("America/Montevideo")


@dataclass
class Account:
    key: str        # "ACC1", "ACC2", ...
    lang: str       # "es" | "en" | "de"
    refresh_token: str


def env(name: str, default: Optional[str] = None) -> str:
    v = os.getenv(name)
    if v is None or v == "":
        return default
    return v


def load_accounts() -> list[Account]:
    # Mapeo por defecto
    accounts_json = env("ACCOUNTS_JSON", '{"ACC1":"es","ACC2":"en","ACC3":"de"}')
    mapping = json.loads(accounts_json)
    accs: list[Account] = []
    for key, lang in mapping.items():
        rt = env(f"REFRESH_TOKEN_{key}", "")
        if rt:
            accs.append(Account(key=key, lang=lang, refresh_token=rt))
    return accs


def parse_csv_row(row: dict) -> dict:
    # Normaliza claves esperadas
    required = [
        "fecha", "hora_MVD", "imagen",
        "alt_es", "alt_en", "alt_de",
        "texto_es", "texto_en", "texto_de",
    ]
    for r in required:
        if r not in row:
            row[r] = ""
    return row


def when_utc_from_row(fecha: str, hora_mvd: str) -> datetime:
    # fecha: YYYY-MM-DD ; hora: HH:MM (MVD)
    dt_local = datetime.strptime(f"{fecha} {hora_mvd}", "%Y-%m-%d %H:%M").replace(tzinfo=MVD_TZ)
    return dt_local.astimezone(timezone.utc)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def in_window(when_utc: datetime, window_min: int) -> bool:
    n = now_utc()
    return (n - timedelta(minutes=window_min)) <= when_utc <= n


def unique_row_key(row: dict) -> str:
    # Clave única definida por el requerimiento (basada en ES)
    return f"{row['fecha']}_{row['hora_MVD']}_{row['texto_es'][:20]}"


def read_posted(state_file: str) -> set[Tuple[str, str]]:
    # Devuelve set de (row_key, account_key)
    s: set[Tuple[str, str]] = set()
    if os.path.exists(state_file):
        with open(state_file, "r", encoding="utf-8", newline="") as f:
            r = csv.DictReader(f)
            for row in r:
                s.add((row.get("key", ""), row.get("account", "")))
    return s


def append_posted(state_file: str, key: str, account: str, tweet_id: str) -> None:
    exists = os.path.exists(state_file)
    with open(state_file, "a", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(["key", "account", "posted_at_utc", "tweet_id"])
        w.writerow([key, account, datetime.now(timezone.utc).isoformat(), tweet_id])


def detect_mime(path_or_url: str, content_bytes: Optional[bytes]) -> str:
    # Prioriza por extensión; cae a cabecera si está disponible
    mime = None
    parsed = urlparse(path_or_url)
    ext = os.path.splitext(parsed.path)[1].lower()
    if ext:
        mime = {
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".webp": "image/webp",
            ".gif": "image/gif",
        }.get(ext)
    if not mime and content_bytes:
        guess = mimetypes.guess_type("file")[0]
        mime = guess or "application/octet-stream"
    return mime or "application/octet-stream"


def get_bytes(path_or_url: str, timeout: int = 30) -> Tuple[bytes, str]:
    if not path_or_url:
        raise ValueError("ruta/URL vacía")
    if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
        resp = requests.get(path_or_url, timeout=timeout)
        resp.raise_for_status()
        data = resp.content
        ctype = resp.headers.get("content-type", "")
        mime = ctype.split(";")[0].strip() if ctype else detect_mime(path_or_url, data)
        return data, mime
    else:
        with open(path_or_url, "rb") as f:
            data = f.read()
        mime = detect_mime(path_or_url, data)
        return data, mime


def refresh_access_token(client_id: str, refresh_token: str) -> dict:
    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    resp = requests.post(OAUTH_TOKEN_URL, data=data, headers=headers, timeout=30)
    try:
        payload = resp.json()
    except Exception:
        payload = {"error": f"non-json response: {resp.text[:200]}"}
    print(f"TOKEN STATUS: {resp.status_code} expires_in={payload.get('expires_in')} token_type={payload.get('token_type')}")
    if "scope" in payload:
        print(f"SCOPES: {payload['scope']}")
    if resp.status_code >= 400:
        raise RuntimeError(f"refresh_access_token failed: {payload}")
    return payload


def get_me(access_token: str) -> dict:
    resp = requests.get(ME_URL, headers={"Authorization": f"Bearer {access_token}"}, timeout=30)
    payload = resp.json()
    if resp.status_code >= 400:
        raise RuntimeError(f"/2/users/me failed: {payload}")
    user = payload.get("data", {})
    print(f"ME: id={user.get('id')} username=@{user.get('username')}")
    return user


def upload_media_v2(access_token: str, media_bytes: bytes, media_type: str) -> str:
    # INIT (JSON)
    h_json = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    init_payload = {
        "command": "INIT",
        "media_type": media_type,
        "total_bytes": len(media_bytes),
        "media_category": "tweet_image",
    }
    r1 = requests.post(MEDIA_UPLOAD_URL, headers=h_json, json=init_payload, timeout=60)
    try:
        j1 = r1.json()
    except Exception:
        j1 = {"error": r1.text[:200]}
    print("MEDIA INIT", r1.status_code, j1)
    if r1.status_code >= 400:
        raise RuntimeError(f"MEDIA INIT error: {j1}")

    media_id = (
        j1.get("data", {}).get("id")
        or j1.get("data", {}).get("media_id")
        or j1.get("media_id_string")
        or j1.get("media_id")
    )
    if not media_id:
        raise RuntimeError(f"MEDIA INIT missing id: {j1}")

    # APPEND (multipart con el binario; sin JSON)
    files = {"media": ("chunk", media_bytes, media_type)}
    r2 = requests.post(
        MEDIA_UPLOAD_URL,
        headers={"Authorization": f"Bearer {access_token}"},
        params={"command": "APPEND", "media_id": str(media_id), "segment_index": "0"},
        files=files,
        timeout=120,
    )
    print("MEDIA APPEND", r2.status_code)
    if r2.status_code >= 400:
        try:
            jj = r2.json()
        except Exception:
            jj = {"error": r2.text[:200]}
        raise RuntimeError(f"MEDIA APPEND error: {jj}")

    # FINALIZE (JSON)
    fin_payload = {"command": "FINALIZE", "media_id": str(media_id)}
    r3 = requests.post(MEDIA_UPLOAD_URL, headers=h_json, json=fin_payload, timeout=60)
    try:
        j3 = r3.json()
    except Exception:
        j3 = {"error": r3.text[:200]}
    print("MEDIA FINALIZE", r3.status_code, j3)
    if r3.status_code >= 400:
        raise RuntimeError(f"MEDIA FINALIZE error: {j3}")

    # Poll de procesamiento si lo informa (para imágenes casi nunca)
    proc = j3.get("data", {}).get("processing_info") or j3.get("processing_info")
    if proc:
        state = proc.get("state")
        while state in ("pending", "in_progress"):
            time.sleep(int(proc.get("check_after_secs", 1)))
            st = requests.get(
                MEDIA_UPLOAD_URL,
                headers={"Authorization": f"Bearer {access_token}"},
                params={"command": "STATUS", "media_id": str(media_id)},
                timeout=30,
            ).json()
            print("MEDIA STATUS", st)
            proc = st.get("data", {}).get("processing_info") or st.get("processing_info") or {}
            state = proc.get("state")
            if state == "failed":
                raise RuntimeError(f"MEDIA STATUS failed: {st}")

    return str(media_id)


def set_media_alt_text(access_token: str, media_id: str, alt_text: str) -> None:
    if not alt_text:
        return
    payload = {
        "id": media_id,
        "metadata": {"alt_text": {"text": alt_text[:1000]}},
    }
    r = requests.post(
        MEDIA_METADATA_URL,
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json=payload,
        timeout=30,
    )
    # No romper si falla alt
    if r.status_code >= 400:
        try:
            print(f"ALT WARN: {r.status_code} {r.json()}")
        except Exception:
            print(f"ALT WARN: {r.status_code} {r.text[:200]}")


def post_tweet_v2(access_token: str, text: str, media_id: Optional[str]) -> dict:
    body: Dict = {"text": text}
    if media_id:
        body["media"] = {"media_ids": [str(media_id)]}
    r = requests.post(
        TWEETS_URL,
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json=body,
        timeout=30,
    )
    j = r.json()
    if r.status_code >= 400:
        raise RuntimeError(f"/2/tweets error: {j}")
    return j


def main() -> None:
    client_id = env("X_CLIENT_ID")
    if not client_id:
        print("Falta X_CLIENT_ID en variables de entorno.")
        sys.exit(1)

    csv_file = env("CSV_FILE", "calendar.csv")
    state_file = env("STATE_FILE", "posted.csv")
    window_min = int(env("WINDOW_MIN", "10"))

    accounts = load_accounts()
    if not accounts:
        print("No hay cuentas activas (REFRESH_TOKEN_ACC1/2/3). Nada para hacer.")
        return

    # Cargar agenda
    if not os.path.exists(csv_file):
        print(f"No existe {csv_file}.")
        return

    # Pre-carga posted.csv
    posted = read_posted(state_file)

    # Leer CSV
    with open(csv_file, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = [parse_csv_row(r) for r in reader]

    # Recorrer cuentas
    for acc in accounts:
        print(f"\n=== {acc.key} ({acc.lang}) ===")
        try:
            token = refresh_access_token(client_id, acc.refresh_token)
            access_token = token["access_token"]
            _ = get_me(access_token)
        except Exception as e:
            print(f"AUTH ERROR {acc.key}: {e}")
            continue

        # Publicar filas dentro de la ventana
        for row in rows:
            try:
                wutc = when_utc_from_row(row["fecha"], row["hora_MVD"])
            except Exception as e:
                print(f"ROW TIME ERROR: {e} -> {row}")
                continue

            if not in_window(wutc, window_min):
                continue

            row_key = unique_row_key(row)
            if (row_key, acc.key) in posted:
                continue

            # Texto por idioma
            txt_key = f"texto_{acc.lang}"
            alt_key = f"alt_{acc.lang}"
            text = (row.get(txt_key) or "").strip()
            if not text:
                print(f"SKIP (texto vacío) {row_key}")
                continue

            media_id = None
            img = (row.get("imagen") or "").strip()
            if img:
                try:
                    b, mime = get_bytes(img)
                    media_id = upload_media_v2(access_token, b, mime)
                    set_media_alt_text(access_token, media_id, row.get(alt_key, ""))
                except Exception as e:
                    print(f"MEDIA ERROR -> solo texto: {e}")

            try:
                resp = post_tweet_v2(access_token, text, media_id)
                tweet_id = resp.get("data", {}).get("id")
                print(f"publicado (oauth2) {acc.key}: tweet_id={tweet_id} cuando_utc={wutc.isoformat()} key={row_key}")
                append_posted(state_file, row_key, acc.key, tweet_id or "")
                posted.add((row_key, acc.key))
            except Exception as e:
                print(f"TWEET ERROR {acc.key}: {e}")


if __name__ == "__main__":
    main()
