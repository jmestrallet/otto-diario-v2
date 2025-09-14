#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
import csv, json, os, sys, time, mimetypes, requests, re, math
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from typing import Optional, Dict, Tuple, List
from urllib.parse import urlparse

# ========= Config / Endpoints =========
API_BASE = "https://api.x.com"
OAUTH_TOKEN_URL = f"{API_BASE}/2/oauth2/token"
MEDIA_INIT_URL = f"{API_BASE}/2/media/upload/initialize"
MEDIA_APPEND_URL = f"{API_BASE}/2/media/upload/{{id}}/append"
MEDIA_FINALIZE_URL = f"{API_BASE}/2/media/upload/{{id}}/finalize"
MEDIA_STATUS_URL = f"{API_BASE}/2/media/upload"    # GET ?command=STATUS&media_id=...
MEDIA_METADATA_URL = f"{API_BASE}/2/media/metadata"
TWEETS_URL = f"{API_BASE}/2/tweets"
ME_URL = f"{API_BASE}/2/users/me"
MVD_TZ = ZoneInfo("America/Montevideo")

def env(name: str, default: Optional[str] = None) -> str:
    v = os.getenv(name)
    return default if v in (None, "") else v

THREAD_FILE = env("THREAD_FILE", "threads.json")

# ========= Util =========
def _norm_text(t: str) -> str:
    return re.sub(r"\s+", " ", (t or "").strip())

def dedupe_key_for_timestamp(acc_key: str, when_utc: datetime) -> str:
    return f"ts:{acc_key}:{when_utc.strftime('%Y-%m-%dT%H:%M')}"

@dataclass
class Account:
    key: str     # ACC1/ACC2/ACC3
    lang: str    # es/en/de
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

def append_posted_batch(state_file: str, rows: List[Tuple[str,str,str,str]]) -> None:
    exists = os.path.exists(state_file)
    with open(state_file, "a", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(["dedupe_key","account","posted_at_utc","tweet_id","text_preview"])
        for dkey, account, tweet_id, text in rows:
            w.writerow([dkey, account, now_utc().isoformat(), tweet_id, (text or "")[:60]])

def detect_mime(path_or_url: str, content_bytes: Optional[bytes]) -> str:
    parsed = urlparse(path_or_url)
    ext = os.path.splitext(parsed.path)[1].lower()
    m = {".png":"image/png",".jpg":"image/jpeg",".jpeg":"image/jpeg",".webp":"image/webp",".gif":"image/gif"}.get(ext)
    if not m and content_bytes:
        m = mimetypes.guess_type("file")[0]
    return m or "application/octet-stream"

def get_bytes(path_or_url: str, timeout: int = 60):
    if not path_or_url:
        return None, None
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

def _retry_wait(headers: Dict[str,str], attempt: int, base_wait: int = 5) -> int:
    reset = headers.get("x-rate-limit-reset")
    if reset:
        try:
            return max(3, int(reset) - int(time.time()))
        except Exception:
            pass
    return min(60, base_wait * (2 ** (attempt - 1)))

def get_me(access_token: str, max_retries: int = 3, base_wait: int = 5) -> dict:
    url = ME_URL
    for attempt in range(1, max_retries + 1):
        r = requests.get(url, headers={"Authorization": f"Bearer {access_token}"}, timeout=30)
        try: j = r.json()
        except Exception: j = {"raw": r.text[:200]}
        if r.status_code < 400:
            u = j.get("data", {}) or {}
            if u: print(f"ME: id={u.get('id')} username=@{u.get('username')}")
            else: print("ME: (sin data)")
            return u
        if r.status_code == 429 or r.status_code >= 500:
            wait = _retry_wait(r.headers, attempt, base_wait)
            print(f"/2/users/me {r.status_code} -> retry {attempt}/{max_retries} en {wait}s ; resp={j}")
            time.sleep(wait); continue
        print(f"ME WARN: {r.status_code} {j}")
        return {}
    print("ME WARN: reintentos agotados"); return {}

def upload_media_v2(access_token: str, media_bytes: bytes, media_type: str, max_retries: int = 3) -> str:
    if media_bytes is None or media_type is None:
        return ""
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

    # STATUS
    proc = j3.get("data", {}).get("processing_info") or j3.get("processing_info")
    # (imágenes suelen no tener procesamiento; si lo tienen, hacemos poll corto)
    tries = 0
    while proc and proc.get("state") in ("pending","in_progress") and tries < 5:
        wait = max(1, int(proc.get("check_after_secs", 1)))
        time.sleep(min(wait, 5))
        st = requests.get(MEDIA_STATUS_URL,
                          headers={"Authorization": f"Bearer {access_token}"},
                          params={"command":"STATUS","media_id":str(media_id)}, timeout=30).json()
        print("MEDIA STATUS", st)
        proc = st.get("data", {}).get("processing_info") or st.get("processing_info") or {}
        if proc.get("state") == "failed": raise RuntimeError(f"MEDIA STATUS failed: {st}")
        tries += 1
    return str(media_id)

def set_media_alt_text(access_token: str, media_id: str, alt_text: str) -> None:
    alt_text = (alt_text or "").strip()
    if not media_id or not alt_text: return
    payload = {"id": media_id, "metadata": {"alt_text": {"text": alt_text[:1000]}}}
    r = requests.post(MEDIA_METADATA_URL,
                      headers={"Authorization": f"Bearer {access_token}","Content-Type":"application/json"},
                      json=payload, timeout=30)
    if r.status_code >= 400:
        try: print(f"ALT WARN: {r.status_code} {r.json()}")
        except Exception: print(f"ALT WARN: {r.status_code} {r.text[:200]}")

def post_tweet_v2_retry(access_token: str, text: str, media_id: Optional[str] = None,
                        reply_to: Optional[str] = None, max_retries: int = 3) -> dict:
    body: Dict = {"text": text}
    if media_id: body["media"] = {"media_ids":[str(media_id)]}
    if reply_to: body["reply"] = {"in_reply_to_tweet_id": str(reply_to)}
    for attempt in range(1, max_retries + 1):
        r = requests.post(TWEETS_URL,
                          headers={"Authorization": f"Bearer {access_token}","Content-Type":"application/json"},
                          json=body, timeout=60)
        try: j = r.json()
        except Exception: j = {"raw": r.text[:200]}
        if r.status_code < 400:
            return j
        if r.status_code == 429 or r.status_code >= 500:
            wait = _retry_wait(r.headers, attempt, 5)
            print(f"/2/tweets {r.status_code} -> retry {attempt}/{max_retries} en {wait}s ; resp={j}")
            time.sleep(wait); continue
        raise RuntimeError(f"/2/tweets error: {j}")
    raise RuntimeError("/2/tweets retry agotado")

def load_threads(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_threads(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)

# ========= Selección de candidatos / Flags =========
CATCH_UP       = int(env("CATCH_UP", "1"))       # 1=permitir atrasados
LOOKBACK_DAYS  = int(env("LOOKBACK_DAYS", "14")) # ventana de búsqueda hacia atrás
WINDOW_MIN     = int(env("WINDOW_MIN", "30"))    # ventana "on-time"
MIN_GAP_MIN    = int(env("MIN_GAP_MIN", "60"))   # separación mínima entre posts por cuenta
MAX_PER_RUN    = int(env("MAX_PER_RUN", "1"))    # máximo por corrida, por cuenta
STRICT_CHRONO  = int(env("STRICT_CHRONO", "1"))  # 1=no saltar días si hay atrasados
ATOMIC_PREFLIGHT = int(env("ATOMIC_PREFLIGHT", "1")) # 1=sube imagen a TODAS antes de postear

def last_post_time_for(acc_key: str, posted: set[Tuple[str,str]]) -> Optional[datetime]:
    # no tenemos timestamps por cuenta en posted.csv, así que aproximamos por el más reciente en archivo
    # (suficiente para throttle de MIN_GAP_MIN durante una corrida)
    return None

def eligible_rows(rows: List[dict], posted: set[Tuple[str,str]], acc_key: str) -> List[dict]:
    """Filtra filas elegibles para una cuenta: por ventana o catch-up + dedupe."""
    out: List[dict] = []
    n = now_utc()
    earliest = n - timedelta(days=LOOKBACK_DAYS)
    for r in rows:
        try:
            wutc = when_utc_from_row(r["fecha"], r["hora_MVD"])
        except Exception:
            continue
        if wutc < earliest: 
            continue
        dkey = dedupe_key_for_timestamp(acc_key, wutc)
        if (dkey, acc_key) in posted:
            continue
        if CATCH_UP:
            if wutc <= n: out.append(r)
        else:
            if in_window(wutc, WINDOW_MIN): out.append(r)
    # Orden cronológico ascendente
    out.sort(key=lambda rr: when_utc_from_row(rr["fecha"], rr["hora_MVD"]))
    return out

def pick_common_row(per_acc_candidates: Dict[str, List[dict]]) -> Optional[dict]:
    """Elige la primera fila (cronológica) que exista para TODAS las cuentas (mismo fecha/hora)."""
    if not per_acc_candidates: return None
    # index por (fecha,hora)
    sets = []
    for acc_key, lst in per_acc_candidates.items():
        s = {(r["fecha"], r["hora_MVD"]) for r in lst}
        sets.append(s)
    common = set.intersection(*sets) if sets else set()
    if not common: return None
    fecha, hora = sorted(common)[0]  # la más vieja
    # Devolver un dict "representativo" (los textos difieren por idioma, pero fecha/hora/img/thread iguales)
    for lst in per_acc_candidates.values():
        for r in lst:
            if r["fecha"] == fecha and r["hora_MVD"] == hora:
                return r
    return None

# ========= Main =========
def main() -> None:
    client_id = env("X_CLIENT_ID")
    if not client_id:
        print("Falta X_CLIENT_ID."); sys.exit(1)

    csv_file = env("CSV_FILE","calendar.csv")
    state_file = env("STATE_FILE","posted.csv")

    accounts = load_accounts()
    print("ACCOUNTS:", [f"{a.key}:{a.lang}" for a in accounts])
    if not accounts:
        print("No hay cuentas activas."); return
    if not os.path.exists(csv_file):
        print(f"No existe {csv_file}."); return

    # CSV & posted
    posted = read_posted(state_file)
    with open(csv_file,"r",encoding="utf-8") as f:
        rows = [parse_csv_row(r) for r in csv.DictReader(f)]
    threads = load_threads(THREAD_FILE)

    # 1) Auth de TODAS + throttle check
    access: Dict[str,str] = {}
    for acc in accounts:
        print(f"\n=== {acc.key} ({acc.lang}) ===")
        try:
            tok = refresh_access_token(client_id, acc.refresh_token)
            access[acc.key] = tok["access_token"]
            new_rt = tok.get("refresh_token","")
            if new_rt and new_rt != acc.refresh_token:
                save_rotating_token(acc.key, new_rt)
            _ = get_me(access[acc.key])
        except Exception as e:
            print(f"AUTH ERROR {acc.key}: {e}")
            print("ABORT: preflight de auth falló en una cuenta -> no se publica nada.")
            return

    # 2) Candidatos por cuenta
    per_acc: Dict[str, List[dict]] = {acc.key: eligible_rows(rows, posted, acc.key) for acc in accounts}
    for acc in accounts:
        print(f"CANDIDATOS {acc.key}: {len(per_acc[acc.key])} (catch_up={CATCH_UP}, lookback_days={LOOKBACK_DAYS}, window_min={WINDOW_MIN})")

    # 3) Elegir una fila común (misma fecha/hora) para TODAS
    row = pick_common_row(per_acc)
    if not row:
        print("NO HAY nada común para publicar en TODAS las cuentas."); return

    # 4) Chequeo STRICT_CHRONO: si hay algo más viejo pendiente, no saltear
    if STRICT_CHRONO:
        n = now_utc()
        target_utc = when_utc_from_row(row["fecha"], row["hora_MVD"])
        for acc in accounts:
            older = [r for r in per_acc[acc.key] if when_utc_from_row(r["fecha"], r["hora_MVD"]) < target_utc]
            if older:
                print(f"STRICT_CHRONO: {acc.key} tiene más viejo pendiente -> se respeta el orden (no se publica aún).")
                return

    # 5) Throttle MIN_GAP_MIN (usa timestamps de posted.csv si los llevás por fuera; aquí omitimos por simplicidad)
    #    Si querés un throttle real por cuenta, guardá también el posted_at por cuenta y léelo aquí.

    # 6) Prefetch bytes de imagen UNA sola vez (si hay)
    img_path = (row.get("imagen") or "").strip()
    img_bytes, img_mime = (None, None)
    if img_path:
        try:
            img_bytes, img_mime = get_bytes(img_path)
        except Exception as e:
            print(f"MEDIA READ ERROR: {e}")
            print("ABORT: no se publica en ninguna cuenta (imagen inválida).")
            return

    # 7) ATOMIC_PREFLIGHT: subir imagen (y ALT) a TODAS antes de postear. Si una falla, aborta todo.
    media_ids: Dict[str,str] = {}
    if ATOMIC_PREFLIGHT and img_bytes:
        for acc in accounts:
            alt_key = f"alt_{acc.lang}"
            try:
                mid = upload_media_v2(access[acc.key], img_bytes, img_mime)
                set_media_alt_text(access[acc.key], mid, row.get(alt_key,""))
                media_ids[acc.key] = mid
            except Exception as e:
                print(f"MEDIA UPLOAD ERROR {acc.key}: {e}")
                print("ABORT: preflight de media falló en una cuenta -> no se publica nada.")
                return

    # 8) Publicar en TODAS (sin rollback), commit de estado SOLO al final si todas OK
    to_append: List[Tuple[str,str,str,str]] = []
    new_threads = threads.copy()
    try:
        count_done = 0
        for acc in accounts:
            txt_key, alt_key = f"texto_{acc.lang}", f"alt_{acc.lang}"
            text = (row.get(txt_key) or "").strip()
            if not text:
                raise RuntimeError(f"Sin texto para {acc.key}/{acc.lang}")
            wutc = when_utc_from_row(row["fecha"], row["hora_MVD"])
            dkey = dedupe_key_for_timestamp(acc.key, wutc)
            # reply a hilo si corresponde
            thread_key = (row.get("thread") or "").strip()
            reply_to_id = new_threads.get(f"{acc.key}:{thread_key}") if thread_key else None

            mid = media_ids.get(acc.key) if img_bytes else None
            resp = post_tweet_v2_retry(access[acc.key], text, mid, reply_to=reply_to_id)
            tid = resp.get("data",{}).get("id") or ""
            print(f"publicado (oauth2) {acc.key}: tweet_id={tid} cuando_utc={wutc.isoformat()}")

            if thread_key and tid:
                new_threads[f"{acc.key}:{thread_key}"] = tid
            to_append.append((dkey, acc.key, tid, text))
            count_done += 1

        # si TODAS publicaron, recién ahí persistimos
        append_posted_batch(state_file, to_append)
        save_threads(THREAD_FILE, new_threads)
        print("OK: lote atómico sin rollback completado.")

    except Exception as e:
        print(f"ABORT DURANTE PUBLICACIÓN: {e}")
        print("No se escribió posted.csv ni threads.json (commit solo si TODAS publican).")
        return

if __name__ == "__main__":
    main()
