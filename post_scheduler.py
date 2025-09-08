#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import csv, json, os, sys, time, mimetypes, requests
import re, hashlib
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from typing import Optional, Dict, Tuple
from urllib.parse import urlparse

# ==========================
# Config/API endpoints
# ==========================
API_BASE = "https://api.x.com"
OAUTH_TOKEN_URL = f"{API_BASE}/2/oauth2/token"

# Media v2 (initialize/append/finalize) + status
MEDIA_INIT_URL = f"{API_BASE}/2/media/upload/initialize"
MEDIA_APPEND_URL = f"{API_BASE}/2/media/upload/{{id}}/append"
MEDIA_FINALIZE_URL = f"{API_BASE}/2/media/upload/{{id}}/finalize"
MEDIA_STATUS_URL = f"{API_BASE}/2/media/upload"  # GET ?command=STATUS&media_id=...

MEDIA_METADATA_URL = f"{API_BASE}/2/media/metadata"
TWEETS_URL = f"{API_BASE}/2/tweets"
ME_URL = f"{API_BASE}/2/users/me"

MVD_TZ = ZoneInfo("America/Montevideo")

# --- Telegram ---
TG_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TG_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
TG_NOTIFY = (os.getenv("TELEGRAM_NOTIFY", "success,fail") or "").lower()

def tg(text: str):
    if not TG_TOKEN or not TG_CHAT_ID:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
            json={
                "chat_id": TG_CHAT_ID,
                "text": text[:4000],
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
            timeout=15,
        )
    except Exception as e:
        print("TG ERROR", e)


# Archivo de hilos (persistente en repo)
def env(name: str, default: Optional[str] = None) -> str:
    v = os.getenv(name)
    return default if v in (None, "") else v

THREAD_FILE = env("THREAD_FILE", "threads.json")

# ==========================
# Utilidades
# ==========================
def _norm_text(t: str) -> str:
    t = (t or "").strip()
    return re.sub(r"\s+", " ", t)

def dedupe_key_for_timestamp(acc_key: str, when_utc: datetime) -> str:
    # Clave estable por cuenta + minuto UTC programado (independiente de texto/imagen)
    return f"ts:{acc_key}:{when_utc.strftime('%Y-%m-%dT%H:%M')}"

@dataclass
class Account:
    key: str     # ACC1 / ACC2 / ACC3
    lang: str    # es / en / de
    refresh_token: str

def load_accounts() -> list[Account]:
    mapping = json.loads(env("ACCOUNTS_JSON", '{"ACC1":"es","ACC2":"en","ACC3":"de"}'))
    accs: list[Account] = []
    for key, lang in mapping.items():
        rt = env(f"REFRESH_TOKEN_{key}", "")
        if rt:
            accs.append(Account(key=key, lang=lang, refresh_token=rt))
    return accs

def parse_csv_row(row: dict) -> dict:
    for k in ["fecha","hora_MVD","imagen","alt_es","alt_en","alt_de","texto_es","texto_en","texto_de","thread"]:
        row.setdefault(k, "")
    return row

def when_utc_from_row(fecha: str, hora_mvd: str) -> datetime:
    dt_local = datetime.strptime(f"{fecha} {hora_mvd}", "%Y-%m-%d %H:%M").replace(tzinfo=MVD_TZ)
    return dt_local.astimezone(timezone.utc)

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def in_window(when_utc: datetime, window_min: int) -> bool:
    n = now_utc()
    return (n - timedelta(minutes=window_min)) <= when_utc <= n

def read_posted(state_file: str) -> set[Tuple[str, str]]:
    s: set[Tuple[str,str]] = set()
    if os.path.exists(state_file):
        with open(state_file, "r", encoding="utf-8", newline="") as f:
            for r in csv.DictReader(f):
                k = r.get("dedupe_key") or r.get("key") or ""
                s.add((k, r.get("account","")))
    return s

def append_posted(state_file: str, dedupe_key: str, account: str, tweet_id: str, text_preview: str) -> None:
    exists = os.path.exists(state_file)
    with open(state_file, "a", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(["dedupe_key","account","posted_at_utc","tweet_id","text_preview"])
        w.writerow([dedupe_key, account, datetime.now(timezone.utc).isoformat(), tweet_id, text_preview[:60]])

def detect_mime(path_or_url: str, content_bytes: Optional[bytes]) -> str:
    parsed = urlparse(path_or_url)
    ext = os.path.splitext(parsed.path)[1].lower()
    m = {".png":"image/png",".jpg":"image/jpeg",".jpeg":"image/jpeg",".webp":"image/webp",".gif":"image/gif"}.get(ext)
    if not m and content_bytes:
        m = mimetypes.guess_type("file")[0]
    return m or "application/octet-stream"

def get_bytes(path_or_url: str, timeout: int = 30):
    if path_or_url.startswith(("http://","https://")):
        r = requests.get(path_or_url, timeout=timeout); r.raise_for_status()
        data = r.content
        ctype = r.headers.get("content-type","")
        mime = ctype.split(";")[0].strip() if ctype else detect_mime(path_or_url, data)
        return data, mime
    with open(path_or_url, "rb") as f:
        data = f.read()
    return data, detect_mime(path_or_url, data)

def refresh_access_token(client_id: str, refresh_token: str) -> dict:
    data = {"grant_type":"refresh_token","refresh_token":refresh_token,"client_id":client_id}
    r = requests.post(OAUTH_TOKEN_URL, data=data, headers={"Content-Type":"application/x-www-form-urlencoded"}, timeout=30)
    try:
        j = r.json()
    except Exception:
        j = {"error": r.text[:200]}
    print(f"TOKEN STATUS: {r.status_code} expires_in={j.get('expires_in')} token_type={j.get('token_type')}")
    if "scope" in j: print(f"SCOPES: {j['scope']}")
    if r.status_code >= 400: raise RuntimeError(f"refresh_access_token failed: {j}")
    return j

def save_rotating_token(acc_key: str, new_rt: str):
    if not new_rt: return
    path = ".tokens_out.json"
    try:
        data = json.load(open(path,"r",encoding="utf-8"))
    except Exception:
        data = {}
    data[acc_key] = new_rt
    with open(path,"w",encoding="utf-8") as f:
        json.dump(data,f,ensure_ascii=False)

def get_me(access_token: str) -> dict:
    r = requests.get(ME_URL, headers={"Authorization": f"Bearer {access_token}"}, timeout=30)
    j = r.json()
    if r.status_code >= 400: raise RuntimeError(f"/2/users/me failed: {j}")
    u = j.get("data",{})
    print(f"ME: id={u.get('id')} username=@{u.get('username')}")
    return u

def upload_media_v2(access_token: str, media_bytes: bytes, media_type: str) -> str:
    # INIT
    h_json = {"Authorization": f"Bearer {access_token}", "Content-Type":"application/json"}
    init_payload = {"media_type": media_type, "total_bytes": len(media_bytes), "media_category": "tweet_image"}
    r1 = requests.post(MEDIA_INIT_URL, headers=h_json, json=init_payload, timeout=60)
    try: j1 = r1.json()
    except Exception: j1 = {"error": r1.text[:200]}
    print("MEDIA INIT", r1.status_code, j1)
    if r1.status_code >= 400: raise RuntimeError(f"MEDIA INIT error: {j1}")
    media_id = j1.get("data",{}).get("id") or j1.get("media_id_string") or j1.get("media_id")
    if not media_id: raise RuntimeError(f"MEDIA INIT missing id: {j1}")

    # APPEND
    files = {"media": ("chunk", media_bytes, media_type)}
    r2 = requests.post(MEDIA_APPEND_URL.format(id=media_id),
                       headers={"Authorization": f"Bearer {access_token}"},
                       data={"segment_index":"0"}, files=files, timeout=120)
    print("MEDIA APPEND", r2.status_code)
    if r2.status_code >= 400:
        try: jj = r2.json()
        except Exception: jj = {"error": r2.text[:200]}
        raise RuntimeError(f"MEDIA APPEND error: {jj}")

    # FINALIZE
    r3 = requests.post(MEDIA_FINALIZE_URL.format(id=media_id),
                       headers={"Authorization": f"Bearer {access_token}"}, timeout=60)
    try: j3 = r3.json()
    except Exception: j3 = {"error": r3.text[:200]}
    print("MEDIA FINALIZE", r3.status_code, j3)
    if r3.status_code >= 400: raise RuntimeError(f"MEDIA FINALIZE error: {j3}")

    # STATUS si corresponde
    proc = j3.get("data", {}).get("processing_info") or j3.get("processing_info")
    if proc:
        state = proc.get("state")
        while state in ("pending","in_progress"):
            time.sleep(int(proc.get("check_after_secs",1)))
            st = requests.get(MEDIA_STATUS_URL, headers={"Authorization": f"Bearer {access_token}"},
                              params={"command":"STATUS","media_id":str(media_id)}, timeout=30).json()
            print("MEDIA STATUS", st)
            proc = st.get("data", {}).get("processing_info") or st.get("processing_info") or {}
            state = proc.get("state")
            if state == "failed": raise RuntimeError(f"MEDIA STATUS failed: {st}")
    return str(media_id)

def set_media_alt_text(access_token: str, media_id: str, alt_text: str) -> None:
    if not alt_text: return
    payload = {"id": media_id, "metadata": {"alt_text": {"text": alt_text[:1000]}}}
    r = requests.post(MEDIA_METADATA_URL,
                      headers={"Authorization": f"Bearer {access_token}","Content-Type":"application/json"},
                      json=payload, timeout=30)
    if r.status_code >= 400:
        try: print(f"ALT WARN: {r.status_code} {r.json()}")
        except Exception: print(f"ALT WARN: {r.status_code} {r.text[:200]}")

def post_tweet_v2(access_token: str, text: str, media_id: Optional[str] = None,
                  reply_to: Optional[str] = None, max_retries: int = 3) -> dict:
    body: Dict = {"text": text}
    if media_id:
        body["media"] = {"media_ids": [str(media_id)]}
    if reply_to:
        body["reply"] = {"in_reply_to_tweet_id": str(reply_to)}

    last = None
    for attempt in range(1, max_retries + 1):
        r = requests.post(
            TWEETS_URL,
            headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
            json=body, timeout=30
        )
        ctype = r.headers.get("content-type", "")
        try:
            j = r.json() if ctype.startswith("application/json") else {"raw": r.text[:200]}
        except Exception:
            j = {"raw": r.text[:200]}

        if r.status_code == 429 or r.status_code >= 500:
            reset = r.headers.get("x-rate-limit-reset")
            if reset:
                import time
                wait = max(5, int(reset) - int(time.time()))
            else:
                wait = min(60, 5 * (2 ** (attempt - 1)))
            print(f"/2/tweets {r.status_code} -> retry {attempt}/{max_retries} en {wait}s ; resp={j}")
            time.sleep(wait)
            last = j
            continue

        if r.status_code >= 400:
            raise RuntimeError(f"/2/tweets error: {j}")

        return j

    raise RuntimeError(f"/2/tweets retry exhausted: {last}")

def load_threads(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_threads(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)

# ==========================
# Main
# ==========================
def main() -> None:
    client_id = env("X_CLIENT_ID")
    if not client_id:
        print("Falta X_CLIENT_ID."); sys.exit(1)

    csv_file = env("CSV_FILE","calendar.csv")
    state_file = env("STATE_FILE","posted.csv")
    window_min = int(env("WINDOW_MIN","10"))

    accounts = load_accounts()
    print("ACCOUNTS:", [f"{a.key}:{a.lang}" for a in accounts])
    if not accounts:
        print("No hay cuentas activas."); return

    if not os.path.exists(csv_file):
        print(f"No existe {csv_file}."); return

    posted = read_posted(state_file)
    with open(csv_file,"r",encoding="utf-8") as f:
        rows = [parse_csv_row(r) for r in csv.DictReader(f)]

    threads = load_threads(THREAD_FILE)

    # Pausa breve entre cuentas para evitar golpear el endpoint a la vez
    for idx, acc in enumerate(accounts):
        if idx:
            time.sleep(3)  # 2–5s está bien

        print(f"\n=== {acc.key} ({acc.lang}) ===")
        try:
            tok = refresh_access_token(client_id, acc.refresh_token)
            access_token = tok["access_token"]
            new_rt = tok.get("refresh_token", "")
            if new_rt and new_rt != acc.refresh_token:
                # guarda para que el workflow lo rote en Secrets
                save_rotating_token(acc.key, new_rt)
            _ = get_me(access_token)
        except Exception as e:
            print(f"AUTH ERROR {acc.key}: {e}")
            continue

        # >>> ESTE for va fuera del except, al mismo nivel que el try <<<
        for row in rows:
            try:
                wutc = when_utc_from_row(row["fecha"], row["hora_MVD"])
            except Exception as e:
                print(f"ROW TIME ERROR: {e} -> {row}")
                continue

            if not in_window(wutc, window_min):
                continue

            # Texto según idioma
            txt_key, alt_key = f"texto_{acc.lang}", f"alt_{acc.lang}"
            text = (row.get(txt_key) or "").strip()
            if not text:
                continue

            # DEDUPE por fecha+hora (por cuenta)
            dedupe_key = dedupe_key_for_timestamp(acc.key, wutc)
            if (dedupe_key, acc.key) in posted:
                print(f"SKIP (dedupe-ts) {dedupe_key} ya publicado por {acc.key}")
                continue

            # Responder a hilo si hay 'thread'
            thread_key = (row.get("thread") or "").strip()
            reply_to_id = threads.get(f"{acc.key}:{thread_key}") if thread_key else None

            # Imagen opcional (1)
            media_id = None
            img = (row.get("imagen") or "").strip()
            if img:
                try:
                    b, mime = get_bytes(img)
                    media_id = upload_media_v2(access_token, b, mime)
                    set_media_alt_text(access_token, media_id, row.get(alt_key, ""))
                except Exception as e:
                    print(f"MEDIA ERROR -> solo texto: {e}")
                    if "fail" in TG_NOTIFY:
                        tg(f"⚠️ <b>{acc.key} ({acc.lang})</b> media falló {row['fecha']} {row['hora_MVD']}\n<code>{str(e)[:250]}</code>")

            # Post con retries/backoff (tu post_tweet_v2 ya actualizado)
            try:
                resp = post_tweet_v2(access_token, text, media_id, reply_to=reply_to_id)
                tweet_id = resp.get("data", {}).get("id")
                print(f"publicado (oauth2) {acc.key}: tweet_id={tweet_id} cuando_utc={wutc.isoformat()}")
                if "success" in TG_NOTIFY and tweet_id:
                    preview = (text[:180] + "…") if len(text) > 180 else text
                    tg(
                        f"✅ <b>{acc.key} ({acc.lang})</b>\n"
                        f"<b>{row['fecha']} {row['hora_MVD']}</b>\n"
                        f"{preview}\n"
                        f"<a href=\"https://x.com/i/web/status/{tweet_id}\">ver en X</a>"
                    )
                if thread_key and tweet_id:
                    threads[f"{acc.key}:{thread_key}"] = tweet_id
                append_posted(state_file, dedupe_key, acc.key, tweet_id or "", text)
                posted.add((dedupe_key, acc.key))
            except Exception as e:
                print(f"TWEET ERROR {acc.key}: {e}")
                if "fail" in TG_NOTIFY:
                    tg(f"❌ <b>{acc.key} ({acc.lang})</b> publicación falló {row['fecha']} {row['hora_MVD']}\n<code>{str(e)[:300]}</code>")

    save_threads(THREAD_FILE, threads)


if __name__ == "__main__":
    main()
