"""
SecureMessage web relay — same crypto and auth as the terminal app.

Passwords never leave the browser as plaintext. The server stores scrypt
verifiers, relays ciphertext, and cannot read message contents.
"""
import json
import os
import re
import hmac
import time
import hashlib
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from secure_message import b64, unb64

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
DB_FILE = os.environ.get("SM_USERS", str(ROOT / "users_db.json"))
HOST = os.environ.get("SM_HOST", "127.0.0.1")
PORT = int(os.environ.get("SM_PORT", "8000"))
EVIL = os.environ.get("SM_EVIL") == "1"
SSL_CERTFILE = os.environ.get("SM_SSL_CERTFILE")
SSL_KEYFILE = os.environ.get("SM_SSL_KEYFILE")
NAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
MAX_FAILS, LOCK_SECONDS = 5, 30

lock = asyncio.Lock()
db = {}
bundles = {}
online = {}
fails = {}


def load_db():
    global db
    if os.path.exists(DB_FILE):
        with open(DB_FILE, encoding="utf-8") as fh:
            db = json.load(fh)
    else:
        db = {}


def save_db():
    with open(DB_FILE, "w", encoding="utf-8") as fh:
        json.dump(db, fh, indent=1)

def public_profiles():
    return {
        username: {
            "first_name": account.get("first_name", ""),
            "last_name": account.get("last_name", ""),
        }
        for username, account in db.items()
    }


async def ws_send(ws, obj):
    await ws.send_text(json.dumps(obj))


async def broadcast_users():
    payload = {
        "type": "users",
        "online": sorted(online),
        "all": sorted(db),
        "profiles": public_profiles(),
    }
    dead = []
    for name, peer in list(online.items()):
        try:
            await ws_send(peer, payload)
        except Exception:
            dead.append(name)
    for name in dead:
        online.pop(name, None)
        bundles.pop(name, None)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    load_db()
    print(
        f"[web] SecureMessage on http://{HOST}:{PORT}  "
        f"{len(db)} registered user(s)"
        + ("  (EVIL mode)" if EVIL else "")
    )
    yield


app = FastAPI(title="SecureMessage", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
async def index():
    return FileResponse(
        STATIC / "index.html",
        headers={"Cache-Control": "no-store, max-age=0", "Pragma": "no-cache"},
    )


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    name = None
    try:
        first = json.loads(await ws.receive_text())
        if not isinstance(first, dict):
            await ws_send(ws, {"type": "error", "msg": "malformed request"})
            return
        user = str(first.get("user", ""))

        if first.get("action") == "register":
            if not NAME_RE.fullmatch(user):
                await ws_send(ws, {"type": "error", "msg": "username must be 3-20 letters, digits or underscore"})
                return
            try:
                salt = unb64(first["salt"])
                verifier = unb64(first["verifier"])
                if len(salt) != 16 or len(verifier) != 32:
                    raise ValueError("invalid credential lengths")
            except (KeyError, ValueError, TypeError):
                await ws_send(ws, {"type": "error", "msg": "invalid registration data"})
                return
            async with lock:
                if user.lower() in {u.lower() for u in db}:
                    err = "username already taken"
                else:
                    db[user] = {"salt": b64(salt), "verifier": b64(verifier)}
                    try:
                        save_db()
                    except OSError:
                        db.pop(user, None)
                        err = "Could not save the account. Check server file permissions."
                    else:
                        err = None
            if err:
                await ws_send(ws, {"type": "error", "msg": err})
            else:
                await ws_send(ws, {"type": "ok"})
                print(f"[web] new user registered: {user}")
            return

        async with lock:
            acct = db.get(user)
            count, until = fails.get(user, (0, 0))
        if time.time() < until:
            await ws_send(
                ws,
                {
                    "type": "error",
                    "msg": f"account locked, try again in {int(until - time.time())}s",
                },
            )
            return
        salt = unb64(acct["salt"]) if acct else os.urandom(16)
        nonce = os.urandom(16)
        await ws_send(ws, {"type": "challenge", "salt": b64(salt), "nonce": b64(nonce)})
        proof_msg = json.loads(await ws.receive_text())
        proof = unb64(proof_msg["proof"])
        good = acct and hmac.compare_digest(
            proof, hmac.new(unb64(acct["verifier"]), nonce, hashlib.sha256).digest()
        )
        async with lock:
            if not good:
                count += 1
                fails[user] = (
                    (0, time.time() + LOCK_SECONDS) if count >= MAX_FAILS else (count, 0)
                )
                await ws_send(ws, {"type": "error", "msg": "invalid username or password"})
                print(f"[web] failed login as '{user}'")
                return
            if user in online:
                await ws_send(ws, {"type": "error", "msg": "already logged in elsewhere"})
                return
            fails.pop(user, None)
            online[user] = ws
            name = user
        await ws_send(
            ws,
            {
                "type": "ok",
                "online": sorted(online),
                "all": sorted(db),
                "profiles": public_profiles(),
            },
        )
        print(f"[web] {name} logged in  (online: {', '.join(sorted(online))})")
        await broadcast_users()

        while True:
            m = json.loads(await ws.receive_text())
            kind = m.get("type")
            if kind == "publish" and m.get("bundle", {}).get("name") == name:
                bundles[name] = m["bundle"]
            elif kind == "users":
                await ws_send(
                    ws,
                    {
                        "type": "users",
                        "online": sorted(online),
                        "all": sorted(db),
                        "profiles": public_profiles(),
                    },
                )
            elif kind == "get_bundle":
                target = m.get("user")
                b = bundles.get(target)
                if b:
                    await ws_send(ws, {"type": "bundle", "bundle": b})
                else:
                    await ws_send(
                        ws,
                        {
                            "type": "error",
                            "msg": f"'{target}' is not available (not registered or never logged in)",
                        },
                    )
            elif kind == "typing":
                target, is_typing = m.get("to"), m.get("typing")
                if isinstance(target, str) and target != name and isinstance(is_typing, bool):
                    dest = online.get(target)
                    if dest:
                        await ws_send(
                            dest,
                            {"type": "typing", "from": name, "typing": is_typing},
                        )
            elif kind == "msg":
                dest, pkt = online.get(m.get("to")), m.get("packet")
                if not isinstance(pkt, dict) or "ciphertext" not in pkt:
                    await ws_send(ws, {"type": "error", "msg": "malformed packet"})
                    continue
                print(
                    f"[web] relaying {name} -> {m.get('to')}: "
                    f"ciphertext={str(pkt.get('ciphertext', ''))[:32]}..."
                )
                if EVIL:
                    raw = bytearray(unb64(pkt["ciphertext"]))
                    raw[0] ^= 1
                    pkt = {**pkt, "ciphertext": b64(bytes(raw))}
                    print("[web] EVIL: flipped a bit in the message")
                if dest:
                    await ws_send(dest, {"type": "msg", "packet": pkt})
                else:
                    await ws_send(ws, {"type": "error", "msg": f"{m.get('to')} is offline"})
    except (WebSocketDisconnect, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        pass
    finally:
        if name:
            async with lock:
                if online.get(name) is ws:
                    online.pop(name, None)
                    bundles.pop(name, None)
            print(f"[web] {name} disconnected")
            try:
                await broadcast_users()
            except Exception:
                pass
        try:
            await ws.close()
        except Exception:
            pass


if __name__ == "__main__":
    import uvicorn

    if bool(SSL_CERTFILE) != bool(SSL_KEYFILE):
        raise SystemExit("Set both SM_SSL_CERTFILE and SM_SSL_KEYFILE to enable HTTPS.")
    uvicorn.run(
        "web_app:app",
        host=HOST,
        port=PORT,
        reload=False,
        ssl_certfile=SSL_CERTFILE,
        ssl_keyfile=SSL_KEYFILE,
    )
