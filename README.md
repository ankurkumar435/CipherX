# SecureMessage

Team Cipher-X. End-to-end encrypted chat: the server stores password verifiers
and relays ciphertext. It cannot read, forge, or silently alter messages.

## Web chat

```powershell
python -m pip install -r requirements.txt
python web_app.py
```

Open `http://127.0.0.1:8000`. Register with a username and password, or
log in with an existing account. Account names and password verifiers are stored
in `users_db.json` (override with `SM_USERS`).

The web UI includes avatar initials, online status, unread message counts, an
emoji picker, contact and conversation search, and responsive layouts for
desktop, tablet, and mobile screens. Search runs locally in the browser.
Typing indicators are relayed only to the selected chat partner.

The browser uses the same cryptography as the terminal client:

- scrypt password hashing and challenge-response login (the password is never
  sent to the server)
- X25519 key exchange, HKDF, AES-256-GCM, Ed25519 signatures
- five failed logins lock the account for 30 seconds
- ephemeral keys for the session; compare fingerprints out-of-band

Default listen address is localhost. Use HTTPS (for example a reverse proxy)
before exposing the app. Optional: `SM_HOST`, `SM_PORT`, `SM_EVIL=1` (flips a
ciphertext bit so the receiver should reject the message).

### Using another device on the same Wi-Fi

The browser cryptography requires a secure context. `http://localhost` is
allowed by browsers, but `http://<computer-LAN-IP>:8000` is not; on a phone,
the Web Crypto API is disabled over plain HTTP. Use a locally trusted HTTPS
certificate for the computer's LAN IP instead of adding an insecure crypto
fallback. The login controls stay disabled unless the browser provides Web
Crypto. Do not enter credentials through a browser certificate warning.

For local development, install `mkcert` on the server computer, then run
PowerShell as your normal user:

```powershell
mkcert -install
mkcert -cert-file lan-cert.pem -key-file lan-key.pem 192.168.1.25 localhost 127.0.0.1
$env:SM_HOST = "0.0.0.0"
$env:SM_SSL_CERTFILE = "$PWD\lan-cert.pem"
$env:SM_SSL_KEYFILE = "$PWD\lan-key.pem"
python web_app.py
```

Replace `192.168.1.25` with the server computer's current Wi-Fi IPv4 address.
Install and trust mkcert's root certificate on the phone as well as on the
server computer; otherwise the browser will still reject the certificate and
disable Web Crypto. `mkcert -CAROOT` shows the root certificate folder. Keep
the root private key (`rootCA-key.pem`) secret and never copy it to the phone.
Then open `https://192.168.1.25:8000` on the phone, accept no certificate
warning (the certificate must validate), and allow the server through Windows
Defender Firewall on Private networks. Recreate the LAN certificate if the
computer's Wi-Fi IP changes.

The server's `INFO: ... "WebSocket /ws" [accepted]` messages are routine
connection logs, not login errors. Browsers open WebSocket connections for
chat communication. The login UI does not use native browser form submission,
so usernames and passwords are not placed in URL query strings.

## Terminal client (unchanged)

```powershell
python secure_message_net.py server
python secure_message_net.py client
```

Commands: `/to <user> <message>`  `/users`  `/help`  `/quit`
