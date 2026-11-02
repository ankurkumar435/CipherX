/* scrypt (RFC 7914) matching Python hashlib.scrypt n/r/p/dklen. */
(function (global) {
  "use strict";

  function xor(a, b) {
    const out = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
    return out;
  }

  function salsa20_8(block) {
    const x = new Int32Array(16);
    const view = new DataView(block.buffer, block.byteOffset, 64);
    for (let i = 0; i < 16; i++) x[i] = view.getInt32(i * 4, true);
    const orig = x.slice();
    function R(a, b, c, rot) {
      const s = (x[b] + x[c]) | 0;
      x[a] ^= (s << rot) | (s >>> (32 - rot));
    }
    for (let i = 0; i < 4; i++) {
      R(4, 0, 12, 7); R(8, 4, 0, 9); R(12, 8, 4, 13); R(0, 12, 8, 18);
      R(9, 5, 1, 7); R(13, 9, 5, 9); R(1, 13, 9, 13); R(5, 1, 13, 18);
      R(14, 10, 6, 7); R(2, 14, 10, 9); R(6, 2, 14, 13); R(10, 6, 2, 18);
      R(3, 15, 11, 7); R(7, 3, 15, 9); R(11, 7, 3, 13); R(15, 11, 7, 18);
      R(1, 0, 3, 7); R(2, 1, 0, 9); R(3, 2, 1, 13); R(0, 3, 2, 18);
      R(6, 5, 4, 7); R(7, 6, 5, 9); R(4, 7, 6, 13); R(5, 4, 7, 18);
      R(11, 10, 9, 7); R(8, 11, 10, 9); R(9, 8, 11, 13); R(10, 9, 8, 18);
      R(12, 15, 14, 7); R(13, 12, 15, 9); R(14, 13, 12, 13); R(15, 14, 13, 18);
    }
    for (let i = 0; i < 16; i++) view.setInt32(i * 4, (x[i] + orig[i]) | 0, true);
  }

  function blockmix(B, r) {
    const X = B.slice(B.length - 64);
    const Y = new Uint8Array(B.length);
    for (let i = 0; i < 2 * r; i++) {
      const block = B.subarray(i * 64, i * 64 + 64);
      for (let j = 0; j < 64; j++) X[j] ^= block[j];
      salsa20_8(X);
      const dest = i % 2 === 0 ? (i / 2) * 64 : (r * 64) + ((i - 1) / 2) * 64;
      Y.set(X, dest);
    }
    B.set(Y);
  }

  function integerify(B, N) {
    const last = B.subarray(B.length - 64);
    return (last[0] | (last[1] << 8) | (last[2] << 16) | (last[3] << 24)) >>> 0 & (N - 1);
  }

  async function pbkdf2(password, salt, dkLen) {
    const key = await crypto.subtle.importKey("raw", password, "PBKDF2", false, ["deriveBits"]);
    return new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: "PBKDF2", hash: "SHA-256", salt, iterations: 1 },
        key,
        dkLen * 8
      )
    );
  }

  async function scrypt(password, salt, N, r, p, dkLen) {
    const blockSize = 128 * r;
    let B = await pbkdf2(password, salt, p * blockSize);
    for (let i = 0; i < p; i++) {
      const block = B.subarray(i * blockSize, (i + 1) * blockSize);
      const V = new Array(N);
      for (let j = 0; j < N; j++) {
        V[j] = block.slice();
        blockmix(block, r);
        if ((j & 511) === 511) await new Promise((resolve) => setTimeout(resolve, 0));
      }
      for (let j = 0; j < N; j++) {
        const k = integerify(block, N);
        const mixed = xor(block, V[k]);
        block.set(mixed);
        blockmix(block, r);
      }
    }
    return pbkdf2(password, B, dkLen);
  }

  global.secureScrypt = scrypt;
})(typeof globalThis !== "undefined" ? globalThis : window);
