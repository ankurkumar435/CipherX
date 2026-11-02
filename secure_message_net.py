"""
SecureMessage (networked) - Team Cipher-X
Real chat over TCP. ANY user can register their own username and password,
then chat securely with any other registered user.
Needs secure_message.py in the same folder (it provides the crypto: X25519 key exchange,
AES-256-GCM, HMAC-SHA256, Ed25519 signatures).
Install dependencies with: python -m pip install -r requirements.txt

  Terminal 1 (server):   python secure_message_net.py server
  Other terminals:       python secure_message_net.py client [server_ip]
        -> choose 1) Register to create an account, then 2) Login.
  (server_ip is only needed when the server runs on a different laptop.)

Chat commands:  /to <user> <message>   /users   /help   /quit
Extra: start the server with --evil to make the relay secretly modify every message
       in transit, and watch the receiver reject it.

Security notes:
  - Your password is never sent over the network. Registration sends a salt and a
    scrypt-derived verifier; login is a challenge-response proof.
  - The server stores only salts and verifiers (never passwords) in users_db.json.
  - The server sees only ciphertext. It cannot read, forge or alter messages undetected.
  - A malicious server could swap public keys during key exchange, so clients print a
    key fingerprint. Compare fingerprints over another channel (phone call, in person).
"""
import os
import re
import sys
import json
import hmac
import time
import socket
import hashlib
import getpass
import threading

from secure_message import User, b64, unb64

PORT = 5050
DB_FILE = os.environ.get("SM_USERS", "users_db.json")
NAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
MAX_FAILS, LOCK_SECONDS = 5, 30


def scrypt(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)


def send(sock, obj, lock=None):
    data = (json.dumps(obj) + "\n").encode()
    if lock:
        with lock:
            sock.sendall(data)
    else:
        sock.sendall(data)


def fingerprint(bundle):
    h = hashlib.sha256(unb64(bundle["sign_pub"]) + unb64(bundle["dh_pub"])).hexdigest()[:20]
    return " ".join(h[i:i + 4] for i in range(0, 20, 4))


# ================================================================= SERVER
def run_server(evil=False):
    lock = threading.Lock()
    db = {}                                    # name -> {"salt": b64, "verifier": b64}
    if os.path.exists(DB_FILE):
        with open(DB_FILE) as fh:
            db = json.load(fh)
    bundles, online, fails = {}, {}, {}        # fails: name -> (count, locked_until)

    def save_db():
        with open(DB_FILE, "w") as fh:
            json.dump(db, fh, indent=1)

    def handle(conn, addr):
        f = conn.makefile("r")
        name = None
        try:
            first = json.loads(f.readline())
            user = str(first.get("user", ""))

            # ---------- registration
            if first.get("action") == "register":
                with lock:
                    if not NAME_RE.match(user):
                        err = "username must be 3-20 letters, digits or underscore"
                    elif user.lower() in {u.lower() for u in db}:
                        err = "username already taken"
                    else:
                        db[user] = {"salt": first["salt"], "verifier": first["verifier"]}
                        save_db()
                        err = None
                if err:
                    send(conn, {"type": "error", "msg": err})
                else:
                    send(conn, {"type": "ok"})
                    print(f"[server] new user registered: {user}")
                return

            # ---------- login (challenge-response)
            with lock:
                acct = db.get(user)
                count, until = fails.get(user, (0, 0))
            if time.time() < until:
                send(conn, {"type": "error", "msg": f"account locked, try again in {int(until - time.time())}s"})
                return
            salt = unb64(acct["salt"]) if acct else os.urandom(16)
            nonce = os.urandom(16)
            send(conn, {"type": "challenge", "salt": b64(salt), "nonce": b64(nonce)})
            proof = unb64(json.loads(f.readline())["proof"])
            good = acct and hmac.compare_digest(
                proof, hmac.new(unb64(acct["verifier"]), nonce, hashlib.sha256).digest())
            with lock:
                if not good:
                    count += 1
                    fails[user] = (0, time.time() + LOCK_SECONDS) if count >= MAX_FAILS else (count, 0)
                    send(conn, {"type": "error", "msg": "invalid username or password"})
                    print(f"[server] failed login as '{user}' from {addr[0]}")
                    return
                if user in online:
                    send(conn, {"type": "error", "msg": "already logged in elsewhere"})
                    return
                fails.pop(user, None)
                online[user] = conn
            name = user
            send(conn, {"type": "ok"})
            print(f"[server] {name} logged in  (online: {', '.join(sorted(online))})")

            for line in f:
                m = json.loads(line)
                if m["type"] == "publish" and m["bundle"]["name"] == name:
                    bundles[name] = m["bundle"]
                elif m["type"] == "users":
                    send(conn, {"type": "users", "online": sorted(online), "all": sorted(db)}, lock)
                elif m["type"] == "get_bundle":
                    b = bundles.get(m["user"])
                    send(conn, {"type": "bundle", "bundle": b} if b else
                         {"type": "error", "msg": f"'{m['user']}' is not available (not registered or never logged in)"}, lock)
                elif m["type"] == "msg":
                    dest, pkt = online.get(m["to"]), m["packet"]
                    print(f"[server] relaying {name} -> {m['to']}: ciphertext={pkt['ciphertext'][:32]}...")
                    if evil:
                        raw = bytearray(unb64(pkt["ciphertext"]))
                        raw[0] ^= 1
                        pkt = {**pkt, "ciphertext": b64(bytes(raw))}
                        print("[server] EVIL: flipped a bit in the message")
                    if dest:
                        send(dest, {"type": "msg", "packet": pkt}, lock)
                    else:
                        send(conn, {"type": "error", "msg": f"{m['to']} is offline"}, lock)
        except (OSError, ValueError, KeyError, TypeError):
            pass
        finally:
            if name:
                with lock:
                    online.pop(name, None)
                    bundles.pop(name, None)
                print(f"[server] {name} disconnected")
            conn.close()

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen()
    print(f"[server] relay listening on port {PORT}, {len(db)} registered user(s)"
          + ("  (EVIL mode)" if evil else ""))
    while True:
        c, a = srv.accept()
        threading.Thread(target=handle, args=(c, a), daemon=True).start()


# ================================================================= CLIENT
def connect(host):
    sock = socket.create_connection((host, PORT))
    return sock, sock.makefile("r")


def do_register(host):
    name = input("Choose a username (3-20 letters/digits/_): ").strip()
    if not NAME_RE.match(name):
        print("Invalid username.")
        return
    pw = getpass.getpass("Choose a password (min 6 chars): ")
    if len(pw) < 6:
        print("Password too short.")
        return
    if pw != getpass.getpass("Repeat password: "):
        print("Passwords do not match.")
        return
    salt = os.urandom(16)
    sock, f = connect(host)
    send(sock, {"action": "register", "user": name, "salt": b64(salt), "verifier": b64(scrypt(pw, salt))})
    r = json.loads(f.readline())
    sock.close()
    print("Account created! Now choose Login." if r["type"] == "ok" else f"Registration failed: {r['msg']}")


def do_login(host):
    name = input("Username: ").strip()
    pw = getpass.getpass("Password: ")
    sock, f = connect(host)
    send(sock, {"action": "login", "user": name})
    ch = json.loads(f.readline())
    if ch["type"] != "challenge":
        print("Login failed:", ch["msg"])
        return None
    key = scrypt(pw, unb64(ch["salt"]))
    send(sock, {"proof": b64(hmac.new(key, unb64(ch["nonce"]), hashlib.sha256).digest())})
    r = json.loads(f.readline())
    if r["type"] != "ok":
        print("Login failed:", r["msg"])
        return None
    return name, sock, f


def chat(name, sock, f):
    lock = threading.Lock()
    me = User(name)
    send(sock, {"type": "publish", "bundle": me.public_bundle()}, lock)
    print(f"\nLogged in as {name}. Your key fingerprint: {fingerprint(me.public_bundle())}")
    print("Commands: /to <user> <message>   /users   /help   /quit\n")
    pending_out, pending_in = {}, {}

    def prompt():
        print("> ", end="", flush=True)

    def deliver(packet):
        try:
            print(f"\n<{json.loads(unb64(packet['header']))['from']}> {me.receive(packet)}")
        except ValueError as e:
            print(f"\n[!] {e}")
        prompt()

    def reader():
        for line in f:
            m = json.loads(line)
            if m["type"] == "bundle":
                b = m["bundle"]
                peer = b["name"]
                me.key_exchange(b)
                print(f"\n[keys] secure session with {peer}. Fingerprint: {fingerprint(b)}  (verify out-of-band!)")
                for text in pending_out.pop(peer, []):
                    send(sock, {"type": "msg", "to": peer, "packet": me.send(peer, text)}, lock)
                for pkt in pending_in.pop(peer, []):
                    deliver(pkt)
                prompt()
            elif m["type"] == "msg":
                pkt = m["packet"]
                try:
                    sender = json.loads(unb64(pkt["header"]))["from"]
                except (ValueError, KeyError):
                    print("\n[!] REJECTED: malformed message (tampered)")
                    prompt()
                    continue
                if sender in me.session:
                    deliver(pkt)
                else:
                    pending_in.setdefault(sender, []).append(pkt)
                    send(sock, {"type": "get_bundle", "user": sender}, lock)
            elif m["type"] == "users":
                others = [u for u in m["online"] if u != name]
                print(f"\nOnline now: {', '.join(others) or '(nobody else)'}")
                print(f"All registered: {', '.join(m['all'])}")
                prompt()
            elif m["type"] == "error":
                print(f"\n[server] {m['msg']}")
                prompt()
        print("\nDisconnected from server.")
        os._exit(0)

    threading.Thread(target=reader, daemon=True).start()
    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if line == "/quit":
            break
        if line == "/users":
            send(sock, {"type": "users"}, lock)
        elif line == "/help":
            print("/to <user> <message>   /users   /quit")
        elif line.startswith("/to "):
            parts = line.split(" ", 2)
            if len(parts) < 3 or parts[1] == name:
                print("usage: /to <other_user> <message>")
                continue
            peer, text = parts[1], parts[2]
            if peer in me.session:
                send(sock, {"type": "msg", "to": peer, "packet": me.send(peer, text)}, lock)
            else:
                pending_out.setdefault(peer, []).append(text)
                send(sock, {"type": "get_bundle", "user": peer}, lock)
        elif line:
            print("Unknown command. Type /help")
    sock.close()


def run_client(host):
    print("=== SecureMessage ===")
    while True:
        c = input("\n1) Register   2) Login   3) Quit : ").strip()
        try:
            if c == "1":
                do_register(host)
            elif c == "2":
                session = do_login(host)
                if session:
                    chat(*session)
                    return
            elif c == "3":
                return
        except (OSError, ValueError, KeyError) as e:
            print(f"Could not talk to server at {host}:{PORT} ({e})")


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["server"]:
        run_server("--evil" in a)
    elif a[:1] == ["client"]:
        run_client(a[1] if len(a) > 1 else "127.0.0.1")
    else:
        print(__doc__)
