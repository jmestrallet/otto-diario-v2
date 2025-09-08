#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, csv, json, requests
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from typing import Dict, List

# === ENV ===
def env(name: str, default: str = "") -> str:
    v = os.getenv(name)
    return default if v in (None, "") else v

API_BASE = "https://api.x.com"
OAUTH_TOKEN_URL = f"{API_BASE}/2/oauth2/token"
TWEETS_URL = f"{API_BASE}/2/tweets"

X_CLIENT_ID = env("X_CLIENT_ID")
ACCOUNTS_JSON = json.loads(env("ACCOUNTS_JSON", '{"ACC1":"es","ACC2":"en","ACC3":"de"}'))

CSV_FILE = env("CSV_FILE", "calendar.csv")           # no se usa aquí, pero lo dejamos homogéneo
STATE_FILE = env("STATE_FILE", "posted.csv")
MVD = ZoneInfo("America/Montevideo")

TG_TOKEN = env("TELEGRAM_BOT_TOKEN")
TG_CHAT_ID = env("TELEGRAM_CHAT_ID")

def tg_send(html: str):
    if not TG_TOKEN or not TG_CHAT_ID: return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
            json={"chat_id": TG_CHAT_ID, "text": html[:4000], "parse_mode":"HTML", "disable_web_page_preview": True},
            timeout=20
        )
    except Exception as e:
        print("TG ERROR", e)

def refresh_access_token(client_id: str, refresh_token: str) -> dict:
    r = requests.post(
        OAUTH_TOKEN_URL,
        data={"grant_type":"refresh_token","refresh_token":refresh_token,"client_id":client_id},
        headers={"Content-Type":"application/x-www-form-urlencoded"},
        timeout=30
    )
    j = r.json() if r.headers.get("content-type","").startswith("application/json") else {"raw": r.text}
    print(f"TOKEN STATUS: {r.status_code} expires_in={j.get('expires_in')} token_type={j.get('token_type')}")
    if "scope" in j: print("SCOPES:", j["scope"])
    if r.status_code >= 400:
        raise RuntimeError(f"refresh_access_token failed: {j}")
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
        json.dump(data, f, ensure_ascii=False)

def load_posted(path: str) -> List[dict]:
    if not os.path.exists(path): return []
    with open(path, "r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))

def filter_last_48h(rows: List[dict]) -> List[dict]:
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=48)
    out = []
    for r in rows:
        ts = r.get("posted_at_utc") or ""
        try:
            dt = datetime.fromisoformat(ts)
        except Exception:
            continue
        if since <= dt.replace(tzinfo=timezone.utc) <= now:
            out.append(r)
    return out

def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i+n]

def fetch_public_metrics(access_token: str, ids: List[str]) -> Dict[str, dict]:
    out = {}
    for batch in chunks(ids, 100):
        params = {
            "ids": ",".join(batch),
            "tweet.fields": "created_at,public_metrics"
        }
        r = requests.get(TWEETS_URL, headers={"Authorization": f"Bearer {access_token}"}, params=params, timeout=30)
        j = r.json()
        if r.status_code >= 400:
            raise RuntimeError(f"/2/tweets error: {j}")
        for t in j.get("data", []):
            out[t["id"]] = t
    return out

def fmt_mvd(dt_utc_str: str) -> str:
    try:
        dt = datetime.fromisoformat(dt_utc_str)
    except Exception:
        return dt_utc_str
    return dt.astimezone(MVD).strftime("%Y-%m-%d %H:%M")

def main():
    rows = load_posted(STATE_FILE)
    last48 = filter_last_48h(rows)

    # Agrupar por cuenta
    by_acc: Dict[str, List[dict]] = {}
    for r in last48:
        acc = r.get("account","")
        if not acc: continue
        by_acc.setdefault(acc, []).append(r)

    # Para cada cuenta con tweets, refrescar y consultar métricas
    summaries = []
    grand = {"likes":0,"replies":0,"retweets":0,"quotes":0,"n":0}
    any_data = False

    for acc_key, lang in ACCOUNTS_JSON.items():
        acc_rows = by_acc.get(acc_key, [])
        if not acc_rows:
            continue
        any_data = True

        rt = env(f"REFRESH_TOKEN_{acc_key}", "")
        if not rt:
            summaries.append(f"<b>{acc_key} ({lang})</b>: sin token, no se midió.")
            continue

        try:
            tok = refresh_access_token(X_CLIENT_ID, rt)
        except Exception as e:
            summaries.append(f"<b>{acc_key} ({lang})</b>: error auth: <code>{str(e)[:180]}</code>")
            continue

        access = tok["access_token"]
        new_rt = tok.get("refresh_token","")
        if new_rt and new_rt != rt:
            save_rotating_token(acc_key, new_rt)

        ids = [r.get("tweet_id","") for r in acc_rows if r.get("tweet_id")]
        if not ids:
            summaries.append(f"<b>{acc_key} ({lang})</b>: 0 tuits en el período.")
            continue

        try:
            data = fetch_public_metrics(access, ids)
        except Exception as e:
            summaries.append(f"<b>{acc_key} ({lang})</b>: error métrica: <code>{str(e)[:180]}</code>")
            continue

        # Agregar métricas
        total = {"likes":0,"replies":0,"retweets":0,"quotes":0,"n":0}
        scored = []
        for r in acc_rows:
            tid = r.get("tweet_id")
            t = data.get(tid)
            if not t: continue
            m = t.get("public_metrics", {})
            likes = int(m.get("like_count",0))
            replies = int(m.get("reply_count",0))
            rts = int(m.get("retweet_count",0))
            quotes = int(m.get("quote_count",0))
            total["likes"] += likes
            total["replies"] += replies
            total["retweets"] += rts
            total["quotes"] += quotes
            total["n"] += 1
            score = likes + replies + rts + quotes
            scored.append((score, tid, r.get("posted_at_utc",""), r.get("text_preview","")))

        grand["likes"] += total["likes"]
        grand["replies"] += total["replies"]
        grand["retweets"] += total["retweets"]
        grand["quotes"] += total["quotes"]
        grand["n"] += total["n"]

        scored.sort(reverse=True)
        top = scored[:3]
        lines = [
            f"<b>{acc_key} ({lang})</b>: {total['n']} tuits",
            f"• 👍 {total['likes']}   💬 {total['replies']}   🔁 {total['retweets']}   ❝ {total['quotes']}   ⟶ <b>{total['likes']+total['replies']+total['retweets']+total['quotes']}</b> interacciones",
        ]
        if top:
            lines.append("Top 3:")
            for i,(score, tid, ts, prev) in enumerate(top, start=1):
                prev = (prev[:80] + "…") if prev and len(prev) > 80 else (prev or "")
                lines.append(f"{i}. <a href=\"https://x.com/i/web/status/{tid}\">tweet</a> ({fmt_mvd(ts)} MVD) — {score} int — {prev}")
        summaries.append("\n".join(lines))

    # Construir mensaje final (últimas 48h en MVD)
    now = datetime.now(MVD)
    since = (datetime.now(timezone.utc) - timedelta(hours=48)).astimezone(MVD)
    header = (f"📊 <b>Informe 48 h</b>\n"
              f"{since.strftime('%Y-%m-%d %H:%M')} → {now.strftime('%Y-%m-%d %H:%M')} MVD\n")

    if not any_data:
        tg_send(header + "\nNo hubo publicaciones en las últimas 48 h.")
        return

    overall = (f"\n<b>Total global</b>: {grand['n']} tuits\n"
               f"• 👍 {grand['likes']}   💬 {grand['replies']}   🔁 {grand['retweets']}   ❝ {grand['quotes']}   "
               f"⟶ <b>{grand['likes']+grand['replies']+grand['retweets']+grand['quotes']}</b> interacciones")

    msg = header + "\n\n".join(summaries) + "\n" + overall
    tg_send(msg)

if __name__ == "__main__":
    main()
