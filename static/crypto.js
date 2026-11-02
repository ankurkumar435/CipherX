/* Client crypto matching secure_message.py: X25519, HKDF, AES-GCM, Ed25519. */
(function (global) {
  "use strict";

  const te = new TextEncoder();
  const td = new TextDecoder();

  function b64(bytes) {
    let s = "";
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
    return btoa(s);
  }

  function unb64(value) {
    if (typeof value !== "string") throw new Error("invalid base64 data");
    const bin = atob(value);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function concatBytes(parts) {
    let n = 0;
    for (const p of parts) n += p.length;
    const out = new Uint8Array(n);
    let o = 0;
    for (const p of parts) {
      out.set(p, o);
      o += p.length;
    }
    return out;
  }

  function canonicalJson(value) {
    if (value === null) return "null";
    const t = typeof value;
    if (t === "boolean") return value ? "true" : "false";
    if (t === "number") return JSON.stringify(value);
    if (t === "string") return JSON.stringify(value);
    if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
    const keys = Object.keys(value).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(value[k])).join(",") + "}";
  }

  function compareBytes(a, b) {
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i++) {
      if (a[i] !== b[i]) return a[i] - b[i];
    }
    return a.length - b.length;
  }

  async function sha256(bytes) {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  }

  async function hkdfSha256(ikm, salt, info, length) {
    const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
    return new Uint8Array(
      await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, length * 8)
    );
  }

  async function hmacSha256(keyBytes, data) {
    const key = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    return new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
  }

  async function scryptVerifier(password, salt) {
    return global.secureScrypt(te.encode(password), salt, 1 << 14, 8, 1, 32);
  }

  class User {
    constructor(name) {
      this.name = name;
      this._signing = nacl.sign.keyPair();
      this._dh = nacl.box.keyPair();
      this.session = {};
    }

    publicBundle() {
      return {
        name: this.name,
        sign_pub: b64(this._signing.publicKey),
        dh_pub: b64(this._dh.publicKey),
      };
    }

    async keyExchange(bundle) {
      const peerName = bundle.name;
      const peerDh = unb64(bundle.dh_pub);
      const peerSign = unb64(bundle.sign_pub);
      if (peerDh.length !== 32 || peerSign.length !== 32) throw new Error("invalid public key bundle");
      if (typeof peerName !== "string" || !peerName || peerName === this.name) {
        throw new Error("invalid peer name");
      }
      const ownDh = this._dh.publicKey;
      const orderedKeys = compareBytes(ownDh, peerDh) <= 0 ? [ownDh, peerDh] : [peerDh, ownDh];
      const orderedNames = [this.name, peerName].sort();
      const shared = nacl.scalarMult(this._dh.secretKey, peerDh);
      const salt = await sha256(concatBytes([te.encode("SecureMessage key exchange v1"), ...orderedKeys]));
      const info = concatBytes([te.encode("SecureMessage session v1"), te.encode(canonicalJson(orderedNames))]);
      const key = await hkdfSha256(shared, salt, info, 32);
      this.session[peerName] = { encryptionKey: key, signingKey: peerSign };
    }

    async send(peer, text) {
      const session = this.session[peer];
      if (!session) throw new Error("no secure session with " + peer);
      if (typeof text !== "string") throw new Error("message must be text");
      const header = te.encode(canonicalJson({ from: this.name, to: peer }));
      const nonce = crypto.getRandomValues(new Uint8Array(12));
      const aesKey = await crypto.subtle.importKey("raw", session.encryptionKey, "AES-GCM", false, ["encrypt"]);
      const ciphertext = new Uint8Array(
        await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: header, tagLength: 128 }, aesKey, te.encode(text))
      );
      const packet = { header: b64(header), nonce: b64(nonce), ciphertext: b64(ciphertext) };
      const signed = te.encode(canonicalJson(packet));
      packet.signature = b64(nacl.sign.detached(signed, this._signing.secretKey));
      return packet;
    }

    async receive(packet) {
      let headerBytes, header, nonce, ciphertext, signature;
      try {
        headerBytes = unb64(packet.header);
        header = JSON.parse(td.decode(headerBytes));
        nonce = unb64(packet.nonce);
        ciphertext = unb64(packet.ciphertext);
        signature = unb64(packet.signature);
      } catch (e) {
        throw new Error("malformed or tampered message");
      }
      const sender = header.from;
      const recipient = header.to;
      const session = this.session[sender];
      if (!session || recipient !== this.name) {
        throw new Error("message is not addressed to this secure session");
      }
      const signed = te.encode(
        canonicalJson({ header: packet.header, nonce: packet.nonce, ciphertext: packet.ciphertext })
      );
      if (!nacl.sign.detached.verify(signed, signature, session.signingKey)) {
        throw new Error("message signature is invalid (tampered)");
      }
      try {
        const aesKey = await crypto.subtle.importKey("raw", session.encryptionKey, "AES-GCM", false, ["decrypt"]);
        const plain = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: nonce, additionalData: headerBytes, tagLength: 128 },
          aesKey,
          ciphertext
        );
        return td.decode(plain);
      } catch (e) {
        throw new Error("message authentication failed (tampered)");
      }
    }
  }

  global.SecureMessage = {
    User,
    b64,
    unb64,
    scryptVerifier,
    hmacSha256,
  };
})(window);
