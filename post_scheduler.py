#!/usr/bin/env python3
import csv
import json
import mimetypes
import os
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import requests

WINDOW_MIN = int(os.getenv("WINDOW_MIN", "5"))
CSV_FILE = os.getenv("CSV_FILE", "calendar.csv")
STATE_FILE = os.getenv("STATE_FILE", "posted.csv")
CLIENT_ID = os.environ.get("X_CLIENT_ID", "")
ACCOUNTS = json.loads(os.getenv("ACCOUNTS_JSON", '{"ACC1":"es","ACC2":"en","ACC3":"de"}'))


def read_posted():
    posted = set()
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            for line in f:
                line = line.strip()
                if line and line != "key":
                    posted.add(line)
    return posted


def save_posted(key):
    with open(STATE_FILE, "a") as f:
        f.write(key + "\n")


def refresh_access_token(client_id, refresh_token):
    data = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh_token,
    }
    r = requests.post("https://api.x.com/2/oauth2/token", data=data)
    print("TOKEN STATUS", r.status_code)
    if r.ok:
        print("SCOPES", r.json().get("scope"))
        return r.json()
    return None


def get_me(token):
    r = requests.get("https://api.x.com/2/users/me", headers={"Authorization": f"Bearer {token}"})
    if r.ok:
        print("ME:", r.json())
        return r.json()
    print("ME FAIL", r.status_code)
    return None


def get_bytes(path_or_url):
    if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
        r = requests.get(path_or_url)
        mime = r.headers.get("content-type", "application/octet-stream")
        return r.content, mime
    with open(path_or_url, "rb") as f:
        data = f.read()
    mime = mimetypes.guess_type(path_or_url)[0] or "application/octet-stream"
    return data, mime


def upload_media_v2(token, data, mime):
    headers = {"Authorization": f"Bearer {token}"}
    init = {"command": "INIT", "total_bytes": len(data), "media_type": mime}
    r = requests.post("https://api.x.com/2/media/upload", data=init, headers=headers)
    if not r.ok:
        return None
    media_id = r.json().get("media_id")
    append = {"command": "APPEND", "media_id": media_id, "segment_index": 0}
    files = {"media": data}
    r = requests.post("https://api.x.com/2/media/upload", data=append, files=files, headers=headers)
    if not r.ok:
        return None
    finalize = {"command": "FINALIZE", "media_id": media_id}
    r = requests.post("https://api.x.com/2/media/upload", data=finalize, headers=headers)
    if not r.ok:
        return None
    return media_id


def set_media_alt_text(token, media_id, alt_text):
    if not alt_text:
        return
    url = f"https://api.x.com/2/media/{media_id}/metadata"
    r = requests.post(url, json={"alt_text": alt_text}, headers={"Authorization": f"Bearer {token}"})
    return r.ok


def post_tweet_v2(token, text, media_id=None):
    payload = {"text": text}
    if media_id:
        payload["media"] = {"media_ids": [media_id]}
    r = requests.post("https://api.x.com/2/tweets", json=payload, headers={"Authorization": f"Bearer {token}"})
    print("publicado", r.status_code)
    return r.json() if r.ok else None


def main():
    tz = ZoneInfo("America/Montevideo")
    posted = read_posted()
    with open(CSV_FILE) as f:
        rows = list(csv.DictReader(f))
    now = datetime.now(timezone.utc)
    for row in rows:
        dt = datetime.strptime(f"{row['fecha']} {row['hora_MVD']}", "%Y-%m-%d %H:%M")
        when_utc = dt.replace(tzinfo=tz).astimezone(timezone.utc)
        key = f"{row['fecha']}_{row['hora_MVD']}_{row['texto_es'][:20]}"
        if key in posted:
            continue
        if not (now - timedelta(minutes=WINDOW_MIN) <= when_utc <= now):
            continue
        for acc, lang in ACCOUNTS.items():
            refresh_token = os.getenv(f"REFRESH_TOKEN_{acc}")
            if not refresh_token:
                continue
            tok = refresh_access_token(CLIENT_ID, refresh_token)
            if not tok:
                continue
            access = tok.get("access_token")
            if not access:
                continue
            get_me(access)
            text = row.get(f"texto_{lang}")
            media_id = None
            img = row.get("imagen", "")
            if img:
                try:
                    data, mime = get_bytes(img)
                    media_id = upload_media_v2(access, data, mime)
                    set_media_alt_text(access, media_id, row.get(f"alt_{lang}", ""))
                except Exception as e:
                    print("media fail", e)
                    media_id = None
            post_tweet_v2(access, text, media_id)
        posted.add(key)
        save_posted(key)


if __name__ == "__main__":
    main()
