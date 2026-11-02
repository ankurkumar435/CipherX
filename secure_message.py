"""Client-side cryptography for the SecureMessage network application."""

import base64
import binascii
import hashlib
import json
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

__all__ = ["User", "b64", "unb64"]


def b64(value):
    return base64.b64encode(value).decode("ascii")


def unb64(value):
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, TypeError) as exc:
        raise ValueError("invalid base64 data") from exc


def _raw_public_key(key):
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class _Session:
    encryption_key: bytes
    signing_key: Ed25519PublicKey


class User:
    def __init__(self, name):
        self.name = name
        self._signing_key = Ed25519PrivateKey.generate()
        self._dh_key = X25519PrivateKey.generate()
        self.session = {}

    def public_bundle(self):
        return {
            "name": self.name,
            "sign_pub": b64(_raw_public_key(self._signing_key.public_key())),
            "dh_pub": b64(_raw_public_key(self._dh_key.public_key())),
        }

    def key_exchange(self, bundle):
        try:
            peer_name = bundle["name"]
            peer_dh_bytes = unb64(bundle["dh_pub"])
            peer_sign_bytes = unb64(bundle["sign_pub"])
            peer_dh_key = X25519PublicKey.from_public_bytes(peer_dh_bytes)
            peer_signing_key = Ed25519PublicKey.from_public_bytes(peer_sign_bytes)
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("invalid public key bundle") from exc
        if not isinstance(peer_name, str) or not peer_name or peer_name == self.name:
            raise ValueError("invalid peer name")

        own_dh_bytes = _raw_public_key(self._dh_key.public_key())
        ordered_keys = sorted((own_dh_bytes, peer_dh_bytes))
        ordered_names = sorted((self.name, peer_name))
        shared_secret = self._dh_key.exchange(peer_dh_key)
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hashlib.sha256(
                b"SecureMessage key exchange v1" + b"".join(ordered_keys)
            ).digest(),
            info=b"SecureMessage session v1" + _canonical_json(ordered_names),
        ).derive(shared_secret)
        self.session[peer_name] = _Session(key, peer_signing_key)

    def send(self, peer, text):
        session = self.session.get(peer)
        if session is None:
            raise ValueError(f"no secure session with {peer}")
        if not isinstance(text, str):
            raise ValueError("message must be text")

        header = _canonical_json({"from": self.name, "to": peer})
        nonce = os.urandom(12)
        ciphertext = AESGCM(session.encryption_key).encrypt(
            nonce, text.encode("utf-8"), header
        )
        signed = _canonical_json(
            {"header": b64(header), "nonce": b64(nonce), "ciphertext": b64(ciphertext)}
        )
        return {
            "header": b64(header),
            "nonce": b64(nonce),
            "ciphertext": b64(ciphertext),
            "signature": b64(self._signing_key.sign(signed)),
        }

    def receive(self, packet):
        try:
            header_bytes = unb64(packet["header"])
            header = json.loads(header_bytes)
            sender = header["from"]
            recipient = header["to"]
            nonce = unb64(packet["nonce"])
            ciphertext = unb64(packet["ciphertext"])
            signature = unb64(packet["signature"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("malformed or tampered message") from exc

        session = self.session.get(sender)
        if session is None or recipient != self.name:
            raise ValueError("message is not addressed to this secure session")
        signed = _canonical_json(
            {
                "header": packet["header"],
                "nonce": packet["nonce"],
                "ciphertext": packet["ciphertext"],
            }
        )
        try:
            session.signing_key.verify(signature, signed)
        except InvalidSignature as exc:
            raise ValueError("message signature is invalid (tampered)") from exc
        try:
            plaintext = AESGCM(session.encryption_key).decrypt(
                nonce, ciphertext, header_bytes
            )
        except InvalidTag as exc:
            raise ValueError("message authentication failed (tampered)") from exc
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("message is not valid UTF-8") from exc
