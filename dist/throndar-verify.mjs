#!/usr/bin/env node

// tools/verify-cli/cli.ts
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

// node_modules/@noble/hashes/utils.js
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
}
function anumber(n, title = "") {
  if (typeof n !== "number") {
    const prefix = title && `"${title}" `;
    throw new TypeError(`${prefix}expected number, got ${typeof n}`);
  }
  if (!Number.isSafeInteger(n) || n < 0) {
    const prefix = title && `"${title}" `;
    throw new RangeError(`${prefix}expected integer >= 0, got ${n}`);
  }
}
function abytes(value, length, title = "") {
  const bytes = isBytes(value);
  const len = value?.length;
  const needsLen = length !== void 0;
  if (!bytes || needsLen && len !== length) {
    const prefix = title && `"${title}" `;
    const ofLen = needsLen ? ` of length ${length}` : "";
    const got = bytes ? `length=${len}` : `type=${typeof value}`;
    const message = prefix + "expected Uint8Array" + ofLen + ", got " + got;
    if (!bytes)
      throw new TypeError(message);
    throw new RangeError(message);
  }
  return value;
}
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function aoutput(out, instance) {
  abytes(out, void 0, "digestInto() output");
  const min = instance.outputLen;
  if (out.length < min) {
    throw new RangeError('"digestInto() output" expected to be of length >=' + min);
  }
}
function u8(arr) {
  return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
}
function u32(arr) {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
function createView(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
function rotr(word, shift) {
  return word << 32 - shift | word >>> shift;
}
var isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
function byteSwap(word) {
  return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
}
function byteSwap32(arr) {
  for (let i = 0; i < arr.length; i++) {
    arr[i] = byteSwap(arr[i]);
  }
  return arr;
}
var swap32IfBE = isLE ? (u) => u : byteSwap32;
var hasHexBuiltin = /* @__PURE__ */ (() => (
  // @ts-ignore
  typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function"
))();
var hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
function bytesToHex(bytes) {
  abytes(bytes);
  if (hasHexBuiltin)
    return bytes.toHex();
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += hexes[bytes[i]];
  }
  return hex;
}
var asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
function asciiToBase16(ch) {
  if (ch >= asciis._0 && ch <= asciis._9)
    return ch - asciis._0;
  if (ch >= asciis.A && ch <= asciis.F)
    return ch - (asciis.A - 10);
  if (ch >= asciis.a && ch <= asciis.f)
    return ch - (asciis.a - 10);
  return;
}
function hexToBytes(hex) {
  if (typeof hex !== "string")
    throw new TypeError("hex string expected, got " + typeof hex);
  if (hasHexBuiltin) {
    try {
      return Uint8Array.fromHex(hex);
    } catch (error) {
      if (error instanceof SyntaxError)
        throw new RangeError(error.message);
      throw error;
    }
  }
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2)
    throw new RangeError("hex string expected, got unpadded hex of length " + hl);
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex.charCodeAt(hi));
    const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
    if (n1 === void 0 || n2 === void 0) {
      const char = hex[hi] + hex[hi + 1];
      throw new RangeError('hex string expected, got non-hex character "' + char + '" at index ' + hi);
    }
    array[ai] = n1 * 16 + n2;
  }
  return array;
}
function concatBytes(...arrays) {
  let sum = 0;
  for (let i = 0; i < arrays.length; i++) {
    const a = arrays[i];
    abytes(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad2 = 0; i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad2);
    pad2 += a.length;
  }
  return res;
}
function createHasher(hashCons, info = {}) {
  const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
  const tmp = hashCons(void 0);
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.canXOF = tmp.canXOF;
  hashC.create = (opts) => hashCons(opts);
  Object.assign(hashC, info);
  return Object.freeze(hashC);
}
function randomBytes(bytesLength = 32) {
  anumber(bytesLength, "bytesLength");
  const cr = typeof globalThis === "object" ? globalThis.crypto : null;
  if (typeof cr?.getRandomValues !== "function")
    throw new Error("crypto.getRandomValues must be defined");
  if (bytesLength > 65536)
    throw new RangeError(`"bytesLength" expected <= 65536, got ${bytesLength}`);
  return cr.getRandomValues(new Uint8Array(bytesLength));
}
var oidNist = (suffix) => ({
  // Current NIST hashAlgs suffixes used here fit in one DER subidentifier octet.
  // Larger suffix values would need base-128 OID encoding and a different length byte.
  oid: Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2, suffix])
});

// node_modules/@noble/curves/utils.js
var abytes2 = (value, length, title) => abytes(value, length, title);
var anumber2 = anumber;
var _0n = /* @__PURE__ */ BigInt(0);
var _1n = /* @__PURE__ */ BigInt(1);
function abool(value, title = "") {
  if (typeof value !== "boolean") {
    const prefix = title && `"${title}" `;
    throw new TypeError(prefix + "expected boolean, got type=" + typeof value);
  }
  return value;
}
function abignumber(n) {
  if (typeof n === "bigint") {
    if (!isPosBig(n))
      throw new RangeError("positive bigint expected, got " + n);
  } else
    anumber2(n);
  return n;
}
function numberToHexUnpadded(num) {
  const hex = abignumber(num).toString(16);
  return hex.length & 1 ? "0" + hex : hex;
}
function hexToNumber(hex) {
  if (typeof hex !== "string")
    throw new TypeError("hex string expected, got " + typeof hex);
  return hex === "" ? _0n : BigInt("0x" + hex);
}
function bytesToNumberBE(bytes) {
  return hexToNumber(bytesToHex(bytes));
}
function bytesToNumberLE(bytes) {
  return hexToNumber(bytesToHex(copyBytes(abytes(bytes)).reverse()));
}
function numberToBytesBE(n, len) {
  anumber(len);
  if (len === 0)
    throw new RangeError("zero length");
  n = abignumber(n);
  const hex = n.toString(16);
  if (hex.length > len * 2)
    throw new RangeError("number too large");
  return hexToBytes(hex.padStart(len * 2, "0"));
}
function numberToBytesLE(n, len) {
  return numberToBytesBE(n, len).reverse();
}
function copyBytes(bytes) {
  return Uint8Array.from(abytes2(bytes));
}
var isPosBig = (n) => typeof n === "bigint" && _0n <= n;
function bitLen(n) {
  if (n < _0n)
    throw new Error("expected non-negative bigint, got " + n);
  let len;
  for (len = 0; n > _0n; n >>= _1n, len += 1)
    ;
  return len;
}

// node_modules/@noble/hashes/_u64.js
var U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
var _32n = /* @__PURE__ */ BigInt(32);
function fromBig(n, le = false) {
  if (le)
    return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
  return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
  const len = lst.length;
  let Ah = new Uint32Array(len);
  let Al = new Uint32Array(len);
  for (let i = 0; i < len; i++) {
    const { h, l } = fromBig(lst[i], le);
    [Ah[i], Al[i]] = [h, l];
  }
  return [Ah, Al];
}
var rotlSH = (h, l, s) => h << s | l >>> 32 - s;
var rotlSL = (h, l, s) => l << s | h >>> 32 - s;
var rotlBH = (h, l, s) => l << s - 32 | h >>> 64 - s;
var rotlBL = (h, l, s) => h << s - 32 | l >>> 64 - s;

// node_modules/@noble/hashes/sha3.js
var _0n2 = BigInt(0);
var _1n2 = BigInt(1);
var _2n = BigInt(2);
var _7n = BigInt(7);
var _256n = BigInt(256);
var _0x71n = BigInt(113);
var SHA3_PI = [];
var SHA3_ROTL = [];
var _SHA3_IOTA = [];
for (let round = 0, R = _1n2, x = 1, y = 0; round < 24; round++) {
  [x, y] = [y, (2 * x + 3 * y) % 5];
  SHA3_PI.push(2 * (5 * y + x));
  SHA3_ROTL.push((round + 1) * (round + 2) / 2 % 64);
  let t = _0n2;
  for (let j = 0; j < 7; j++) {
    R = (R << _1n2 ^ (R >> _7n) * _0x71n) % _256n;
    if (R & _2n)
      t ^= _1n2 << (_1n2 << BigInt(j)) - _1n2;
  }
  _SHA3_IOTA.push(t);
}
var IOTAS = split(_SHA3_IOTA, true);
var SHA3_IOTA_H = IOTAS[0];
var SHA3_IOTA_L = IOTAS[1];
var rotlH = (h, l, s) => s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s);
var rotlL = (h, l, s) => s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s);
function keccakP(s, rounds = 24) {
  anumber(rounds, "rounds");
  if (rounds < 1 || rounds > 24)
    throw new Error('"rounds" expected integer 1..24');
  const B = new Uint32Array(5 * 2);
  for (let round = 24 - rounds; round < 24; round++) {
    for (let x = 0; x < 10; x++)
      B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
    for (let x = 0; x < 10; x += 2) {
      const idx1 = (x + 8) % 10;
      const idx0 = (x + 2) % 10;
      const B0 = B[idx0];
      const B1 = B[idx0 + 1];
      const Th = rotlH(B0, B1, 1) ^ B[idx1];
      const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
      for (let y = 0; y < 50; y += 10) {
        s[x + y] ^= Th;
        s[x + y + 1] ^= Tl;
      }
    }
    let curH = s[2];
    let curL = s[3];
    for (let t = 0; t < 24; t++) {
      const shift = SHA3_ROTL[t];
      const Th = rotlH(curH, curL, shift);
      const Tl = rotlL(curH, curL, shift);
      const PI = SHA3_PI[t];
      curH = s[PI];
      curL = s[PI + 1];
      s[PI] = Th;
      s[PI + 1] = Tl;
    }
    for (let y = 0; y < 50; y += 10) {
      const b0 = s[y], b1 = s[y + 1], b2 = s[y + 2], b3 = s[y + 3];
      s[y] ^= ~s[y + 2] & s[y + 4];
      s[y + 1] ^= ~s[y + 3] & s[y + 5];
      s[y + 2] ^= ~s[y + 4] & s[y + 6];
      s[y + 3] ^= ~s[y + 5] & s[y + 7];
      s[y + 4] ^= ~s[y + 6] & s[y + 8];
      s[y + 5] ^= ~s[y + 7] & s[y + 9];
      s[y + 6] ^= ~s[y + 8] & b0;
      s[y + 7] ^= ~s[y + 9] & b1;
      s[y + 8] ^= ~b0 & b2;
      s[y + 9] ^= ~b1 & b3;
    }
    s[0] ^= SHA3_IOTA_H[round];
    s[1] ^= SHA3_IOTA_L[round];
  }
  clean(B);
}
var Keccak = class _Keccak {
  state;
  pos = 0;
  posOut = 0;
  finished = false;
  state32;
  destroyed = false;
  blockLen;
  suffix;
  outputLen;
  canXOF;
  enableXOF = false;
  rounds;
  // NOTE: we accept arguments in bytes instead of bits here.
  constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
    this.blockLen = blockLen;
    this.suffix = suffix;
    this.outputLen = outputLen;
    this.enableXOF = enableXOF;
    this.canXOF = enableXOF;
    this.rounds = rounds;
    anumber(outputLen, "outputLen");
    if (!(0 < blockLen && blockLen < 200))
      throw new Error("only keccak-f1600 function is supported");
    this.state = new Uint8Array(200);
    this.state32 = u32(this.state);
  }
  clone() {
    return this._cloneInto();
  }
  keccak() {
    swap32IfBE(this.state32);
    keccakP(this.state32, this.rounds);
    swap32IfBE(this.state32);
    this.posOut = 0;
    this.pos = 0;
  }
  update(data) {
    aexists(this);
    abytes(data);
    const { blockLen, state } = this;
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      for (let i = 0; i < take; i++)
        state[this.pos++] ^= data[pos++];
      if (this.pos === blockLen)
        this.keccak();
    }
    return this;
  }
  finish() {
    if (this.finished)
      return;
    this.finished = true;
    const { state, suffix, pos, blockLen } = this;
    state[pos] ^= suffix;
    if ((suffix & 128) !== 0 && pos === blockLen - 1)
      this.keccak();
    state[blockLen - 1] ^= 128;
    this.keccak();
  }
  writeInto(out) {
    aexists(this, false);
    abytes(out);
    this.finish();
    const bufferOut = this.state;
    const { blockLen } = this;
    for (let pos = 0, len = out.length; pos < len; ) {
      if (this.posOut >= blockLen)
        this.keccak();
      const take = Math.min(blockLen - this.posOut, len - pos);
      out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
      this.posOut += take;
      pos += take;
    }
    return out;
  }
  xofInto(out) {
    if (!this.enableXOF)
      throw new Error("XOF is not possible for this instance");
    return this.writeInto(out);
  }
  xof(bytes) {
    anumber(bytes);
    return this.xofInto(new Uint8Array(bytes));
  }
  digestInto(out) {
    aoutput(out, this);
    if (this.finished)
      throw new Error("digest() was already called");
    this.writeInto(out.subarray(0, this.outputLen));
    this.destroy();
  }
  digest() {
    const out = new Uint8Array(this.outputLen);
    this.digestInto(out);
    return out;
  }
  destroy() {
    this.destroyed = true;
    clean(this.state);
  }
  _cloneInto(to) {
    const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
    to ||= new _Keccak(blockLen, suffix, outputLen, enableXOF, rounds);
    to.blockLen = blockLen;
    to.state32.set(this.state32);
    to.pos = this.pos;
    to.posOut = this.posOut;
    to.finished = this.finished;
    to.rounds = rounds;
    to.suffix = suffix;
    to.outputLen = outputLen;
    to.enableXOF = enableXOF;
    to.canXOF = this.canXOF;
    to.destroyed = this.destroyed;
    return to;
  }
};
var genShake = (suffix, blockLen, outputLen, info = {}) => createHasher((opts = {}) => new Keccak(blockLen, suffix, opts.dkLen === void 0 ? outputLen : opts.dkLen, true), info);
var shake128 = /* @__PURE__ */ genShake(31, 168, 16, /* @__PURE__ */ oidNist(11));
var shake256 = /* @__PURE__ */ genShake(31, 136, 32, /* @__PURE__ */ oidNist(12));

// node_modules/@noble/curves/abstract/fft.js
function checkU32(n) {
  if (!Number.isSafeInteger(n) || n < 0 || n > 4294967295)
    throw new Error("wrong u32 integer:" + n);
  return n;
}
function isPowerOfTwo(x) {
  checkU32(x);
  return (x & x - 1) === 0 && x !== 0;
}
function reverseBits(n, bits) {
  checkU32(n);
  if (!Number.isSafeInteger(bits) || bits < 0 || bits > 32)
    throw new Error(`expected integer 0 <= bits <= 32, got ${bits}`);
  let reversed = 0;
  for (let i = 0; i < bits; i++, n >>>= 1)
    reversed = reversed << 1 | n & 1;
  return reversed >>> 0;
}
function log2(n) {
  checkU32(n);
  return 31 - Math.clz32(n);
}
function bitReversalInplace(values) {
  const n = values.length;
  if (!isPowerOfTwo(n))
    throw new Error("expected positive power-of-two length, got " + n);
  const bits = log2(n);
  for (let i = 0; i < n; i++) {
    const j = reverseBits(i, bits);
    if (i < j) {
      const tmp = values[i];
      values[i] = values[j];
      values[j] = tmp;
    }
  }
  return values;
}
var FFTCore = (F2, coreOpts) => {
  const { N: N2, roots, dit, invertButterflies = false, skipStages = 0, brp = true } = coreOpts;
  const bits = log2(N2);
  if (!isPowerOfTwo(N2))
    throw new Error("FFT: Polynomial size should be power of two");
  if (roots.length !== N2)
    throw new Error(`FFT: wrong roots length: expected ${N2}, got ${roots.length}`);
  const isDit = dit !== invertButterflies;
  isDit;
  return (values) => {
    if (values.length !== N2)
      throw new Error("FFT: wrong Polynomial length");
    if (dit && brp)
      bitReversalInplace(values);
    for (let i = 0, g = 1; i < bits - skipStages; i++) {
      const s = dit ? i + 1 + skipStages : bits - i;
      const m = 1 << s;
      const m2 = m >> 1;
      const stride = N2 >> s;
      for (let k = 0; k < N2; k += m) {
        for (let j = 0, grp = g++; j < m2; j++) {
          const rootPos = invertButterflies ? dit ? N2 - grp : grp : j * stride;
          const i0 = k + j;
          const i1 = k + j + m2;
          const omega = roots[rootPos];
          const b = values[i1];
          const a = values[i0];
          if (isDit) {
            const t = F2.mul(b, omega);
            values[i0] = F2.add(a, t);
            values[i1] = F2.sub(a, t);
          } else if (invertButterflies) {
            values[i0] = F2.add(b, a);
            values[i1] = F2.mul(F2.sub(b, a), omega);
          } else {
            values[i0] = F2.add(a, b);
            values[i1] = F2.mul(F2.sub(a, b), omega);
          }
        }
      }
    }
    if (!dit && brp)
      bitReversalInplace(values);
    return values;
  };
};

// node_modules/@noble/post-quantum/utils.js
var abytesDoc = abytes;
var randomBytes2 = randomBytes;
function equalBytes(a, b) {
  if (a.length !== b.length)
    return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++)
    diff |= a[i] ^ b[i];
  return diff === 0;
}
function byteSwap64(arr) {
  const bytes = new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
  for (let i = 0; i < bytes.length; i += 8) {
    const a0 = bytes[i + 0];
    const a1 = bytes[i + 1];
    const a2 = bytes[i + 2];
    const a3 = bytes[i + 3];
    bytes[i + 0] = bytes[i + 7];
    bytes[i + 1] = bytes[i + 6];
    bytes[i + 2] = bytes[i + 5];
    bytes[i + 3] = bytes[i + 4];
    bytes[i + 4] = a3;
    bytes[i + 5] = a2;
    bytes[i + 6] = a1;
    bytes[i + 7] = a0;
  }
  return arr;
}
var baswap64If = isLE ? (arr) => arr : byteSwap64;
function validateOpts(opts) {
  if (Object.prototype.toString.call(opts) !== "[object Object]")
    throw new TypeError("expected valid options object");
}
function validateVerOpts(opts) {
  validateOpts(opts);
  if (opts.context !== void 0)
    abytes(opts.context, void 0, "opts.context");
}
function validateSigOpts(opts) {
  validateVerOpts(opts);
  if (opts.extraEntropy !== false && opts.extraEntropy !== void 0)
    abytes(opts.extraEntropy, void 0, "opts.extraEntropy");
}
function splitCoder(label, ...lengths) {
  const getLength = (c) => typeof c === "number" ? c : c.bytesLen;
  const bytesLen = lengths.reduce((sum, a) => sum + getLength(a), 0);
  return {
    bytesLen,
    encode: (bufs) => {
      const res = new Uint8Array(bytesLen);
      for (let i = 0, pos = 0; i < lengths.length; i++) {
        const c = lengths[i];
        const l = getLength(c);
        const b = typeof c === "number" ? bufs[i] : c.encode(bufs[i]);
        abytes(b, l, label);
        res.set(b, pos);
        if (typeof c !== "number")
          b.fill(0);
        pos += l;
      }
      return res;
    },
    decode: (buf) => {
      abytes(buf, bytesLen, label);
      const res = [];
      for (const c of lengths) {
        const l = getLength(c);
        const b = buf.subarray(0, l);
        res.push(typeof c === "number" ? b : c.decode(b));
        buf = buf.subarray(l);
      }
      return res;
    }
  };
}
function vecCoder(c, vecLen) {
  const coder = c;
  const bytesLen = vecLen * coder.bytesLen;
  return {
    bytesLen,
    encode: (u) => {
      if (u.length !== vecLen)
        throw new RangeError(`vecCoder.encode: wrong length=${u.length}. Expected: ${vecLen}`);
      const res = new Uint8Array(bytesLen);
      for (let i = 0, pos = 0; i < u.length; i++) {
        const b = coder.encode(u[i]);
        res.set(b, pos);
        b.fill(0);
        pos += b.length;
      }
      return res;
    },
    decode: (a) => {
      abytes(a, bytesLen);
      const r = [];
      for (let i = 0; i < a.length; i += coder.bytesLen)
        r.push(coder.decode(a.subarray(i, i + coder.bytesLen)));
      return r;
    }
  };
}
function cleanBytes(...list) {
  for (const t of list) {
    if (Array.isArray(t))
      for (const b of t)
        b.fill(0);
    else
      t.fill(0);
  }
}
function getMask(bits) {
  if (!Number.isSafeInteger(bits) || bits < 0 || bits > 32)
    throw new RangeError(`expected bits in [0..32], got ${bits}`);
  return bits === 32 ? 4294967295 : ~(-1 << bits) >>> 0;
}
var EMPTY = /* @__PURE__ */ Uint8Array.of();
function getMessage(msg, ctx = EMPTY) {
  abytes(msg);
  abytes(ctx);
  if (ctx.length > 255)
    throw new RangeError("context should be 255 bytes or less");
  return concatBytes(new Uint8Array([0, ctx.length]), ctx, msg);
}
var oidNistP = /* @__PURE__ */ Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2]);
function checkHash(hash, requiredStrength = 0) {
  if (!hash.oid || !equalBytes(hash.oid.subarray(0, 10), oidNistP))
    throw new Error("hash.oid is invalid: expected NIST hash");
  const collisionResistance = hash.outputLen * 8 / 2;
  if (requiredStrength > collisionResistance) {
    throw new Error("Pre-hash security strength too low: " + collisionResistance + ", required: " + requiredStrength);
  }
}
function getMessagePrehash(hash, msg, ctx = EMPTY) {
  abytes(msg);
  abytes(ctx);
  if (ctx.length > 255)
    throw new RangeError("context should be 255 bytes or less");
  const hashed = hash(msg);
  return concatBytes(new Uint8Array([1, ctx.length]), ctx, hash.oid, hashed);
}

// node_modules/@noble/post-quantum/_crystals.js
var genCrystals = (opts) => {
  const { newPoly: newPoly2, N: N2, Q: Q3, F: F2, ROOT_OF_UNITY: ROOT_OF_UNITY2, brvBits, isKyber } = opts;
  const mod2 = (a, modulo = Q3) => {
    const result = a % modulo | 0;
    return (result >= 0 ? result | 0 : modulo + result | 0) | 0;
  };
  const smod = (a, modulo = Q3) => {
    const r = mod2(a, modulo) | 0;
    return (r > modulo >> 1 ? r - modulo | 0 : r) | 0;
  };
  function getZettas() {
    const out = newPoly2(N2);
    for (let i = 0; i < N2; i++) {
      const b = reverseBits(i, brvBits);
      const p = BigInt(ROOT_OF_UNITY2) ** BigInt(b) % BigInt(Q3);
      out[i] = Number(p) | 0;
    }
    return out;
  }
  const nttZetas = getZettas();
  const field = {
    add: (a, b) => mod2((a | 0) + (b | 0)) | 0,
    sub: (a, b) => mod2((a | 0) - (b | 0)) | 0,
    mul: (a, b) => mod2((a | 0) * (b | 0)) | 0,
    inv: (_a) => {
      throw new Error("not implemented");
    }
  };
  const nttOpts = {
    N: N2,
    roots: nttZetas,
    invertButterflies: true,
    skipStages: isKyber ? 1 : 0,
    brp: false
  };
  const dif = FFTCore(field, { dit: false, ...nttOpts });
  const dit = FFTCore(field, { dit: true, ...nttOpts });
  const NTT = {
    encode: (r) => {
      return dif(r);
    },
    decode: (r) => {
      dit(r);
      for (let i = 0; i < r.length; i++)
        r[i] = mod2(F2 * r[i]);
      return r;
    }
  };
  const bitsCoder = (d, c) => {
    const mask = getMask(d);
    const bytesLen = d * (N2 / 8);
    return {
      bytesLen,
      encode: (poly_) => {
        const poly = poly_;
        const r = new Uint8Array(bytesLen);
        for (let i = 0, buf = 0, bufLen = 0, pos = 0; i < poly.length; i++) {
          buf |= (c.encode(poly[i]) & mask) << bufLen;
          bufLen += d;
          for (; bufLen >= 8; bufLen -= 8, buf >>= 8)
            r[pos++] = buf & getMask(bufLen);
        }
        return r;
      },
      decode: (bytes) => {
        const r = newPoly2(N2);
        for (let i = 0, buf = 0, bufLen = 0, pos = 0; i < bytes.length; i++) {
          buf |= bytes[i] << bufLen;
          bufLen += 8;
          for (; bufLen >= d; bufLen -= d, buf >>= d)
            r[pos++] = c.decode(buf & mask);
        }
        return r;
      }
    };
  };
  return {
    mod: mod2,
    smod,
    nttZetas,
    NTT: {
      encode: (r) => NTT.encode(r),
      decode: (r) => NTT.decode(r)
    },
    bitsCoder
  };
};
var createXofShake = (shake) => (seed, blockLen) => {
  if (!blockLen)
    blockLen = shake.blockLen;
  const _seed = new Uint8Array(seed.length + 2);
  _seed.set(seed);
  const seedLen = seed.length;
  const buf = new Uint8Array(blockLen);
  let h = shake.create({});
  let calls = 0;
  let xofs = 0;
  return {
    stats: () => ({ calls, xofs }),
    get: (x, y) => {
      _seed[seedLen + 0] = x;
      _seed[seedLen + 1] = y;
      h.destroy();
      h = shake.create({}).update(_seed);
      calls++;
      return () => {
        xofs++;
        return h.xofInto(buf);
      };
    },
    clean: () => {
      h.destroy();
      cleanBytes(buf, _seed);
    }
  };
};
var XOF128 = /* @__PURE__ */ createXofShake(shake128);
var XOF256 = /* @__PURE__ */ createXofShake(shake256);

// node_modules/@noble/post-quantum/ml-dsa.js
function validateInternalOpts(opts) {
  validateOpts(opts);
  if (opts.externalMu !== void 0)
    abool(opts.externalMu, "opts.externalMu");
}
var N = 256;
var Q = 8380417;
var ROOT_OF_UNITY = 1753;
var F = 8347681;
var D = 13;
var GAMMA2_1 = Math.floor((Q - 1) / 88) | 0;
var GAMMA2_2 = Math.floor((Q - 1) / 32) | 0;
var PARAMS = /* @__PURE__ */ (() => Object.freeze({
  2: Object.freeze({
    K: 4,
    L: 4,
    D,
    GAMMA1: 2 ** 17,
    GAMMA2: GAMMA2_1,
    TAU: 39,
    ETA: 2,
    OMEGA: 80
  }),
  3: Object.freeze({
    K: 6,
    L: 5,
    D,
    GAMMA1: 2 ** 19,
    GAMMA2: GAMMA2_2,
    TAU: 49,
    ETA: 4,
    OMEGA: 55
  }),
  5: Object.freeze({
    K: 8,
    L: 7,
    D,
    GAMMA1: 2 ** 19,
    GAMMA2: GAMMA2_2,
    TAU: 60,
    ETA: 2,
    OMEGA: 75
  })
}))();
var newPoly = (n) => new Int32Array(n);
var crystals = /* @__PURE__ */ genCrystals({
  N,
  Q,
  F,
  ROOT_OF_UNITY,
  newPoly,
  isKyber: false,
  brvBits: 8
});
var id = (n) => n;
var polyCoder = (d, compress = id, verify = id) => crystals.bitsCoder(d, {
  encode: (i) => compress(verify(i)),
  decode: (i) => verify(compress(i))
});
var polyAdd = (a_, b_) => {
  const a = a_;
  const b = b_;
  for (let i = 0; i < a.length; i++)
    a[i] = crystals.mod(a[i] + b[i]);
  return a;
};
var polySub = (a_, b_) => {
  const a = a_;
  const b = b_;
  for (let i = 0; i < a.length; i++)
    a[i] = crystals.mod(a[i] - b[i]);
  return a;
};
var polyShiftl = (p_) => {
  const p = p_;
  for (let i = 0; i < N; i++)
    p[i] <<= D;
  return p;
};
var polyChknorm = (p_, B) => {
  const p = p_;
  for (let i = 0; i < N; i++)
    if (Math.abs(crystals.smod(p[i])) >= B)
      return true;
  return false;
};
var MultiplyNTTs = (a_, b_) => {
  const a = a_;
  const b = b_;
  const c = newPoly(N);
  for (let i = 0; i < a.length; i++)
    c[i] = crystals.mod(a[i] * b[i]);
  return c;
};
function RejNTTPoly(xof_) {
  const xof = xof_;
  const r = newPoly(N);
  for (let j = 0; j < N; ) {
    const b = xof();
    if (b.length % 3)
      throw new Error("RejNTTPoly: unaligned block");
    for (let i = 0; j < N && i <= b.length - 3; i += 3) {
      const t = (b[i + 0] | b[i + 1] << 8 | b[i + 2] << 16) & 8388607;
      if (t < Q)
        r[j++] = t;
    }
  }
  return r;
}
function getDilithium(opts_) {
  const opts = opts_;
  const { K, L, GAMMA1, GAMMA2, TAU, ETA, OMEGA } = opts;
  const { CRH_BYTES, TR_BYTES, C_TILDE_BYTES, XOF128: XOF1282, XOF256: XOF2562, securityLevel } = opts;
  if (![2, 4].includes(ETA))
    throw new Error("Wrong ETA");
  if (![1 << 17, 1 << 19].includes(GAMMA1))
    throw new Error("Wrong GAMMA1");
  if (![GAMMA2_1, GAMMA2_2].includes(GAMMA2))
    throw new Error("Wrong GAMMA2");
  const BETA = TAU * ETA;
  const decompose = (r) => {
    const rPlus = crystals.mod(r);
    const r0 = crystals.smod(rPlus, 2 * GAMMA2) | 0;
    if (rPlus - r0 === Q - 1)
      return { r1: 0 | 0, r0: r0 - 1 | 0 };
    const r1 = Math.floor((rPlus - r0) / (2 * GAMMA2)) | 0;
    return { r1, r0 };
  };
  const HighBits = (r) => decompose(r).r1;
  const LowBits = (r) => decompose(r).r0;
  const MakeHint = (z, r) => {
    const res0 = z <= GAMMA2 || z > Q - GAMMA2 || z === Q - GAMMA2 && r === 0 ? 0 : 1;
    return res0;
  };
  const UseHint = (h, r) => {
    const m = Math.floor((Q - 1) / (2 * GAMMA2));
    const { r1, r0 } = decompose(r);
    if (h === 1)
      return r0 > 0 ? crystals.mod(r1 + 1, m) | 0 : crystals.mod(r1 - 1, m) | 0;
    return r1 | 0;
  };
  const Power2Round = (r) => {
    const rPlus = crystals.mod(r);
    const r0 = crystals.smod(rPlus, 2 ** D) | 0;
    return { r1: Math.floor((rPlus - r0) / 2 ** D) | 0, r0 };
  };
  const hintCoder = {
    bytesLen: OMEGA + K,
    encode: (h_) => {
      const h = h_;
      if (h === false)
        throw new Error("hint.encode: hint is false");
      const res = new Uint8Array(OMEGA + K);
      for (let i = 0, k = 0; i < K; i++) {
        for (let j = 0; j < N; j++)
          if (h[i][j] !== 0)
            res[k++] = j;
        res[OMEGA + i] = k;
      }
      return res;
    },
    decode: (buf) => {
      const h = [];
      let k = 0;
      for (let i = 0; i < K; i++) {
        const hi = newPoly(N);
        if (buf[OMEGA + i] < k || buf[OMEGA + i] > OMEGA)
          return false;
        for (let j = k; j < buf[OMEGA + i]; j++) {
          if (j > k && buf[j] <= buf[j - 1])
            return false;
          hi[buf[j]] = 1;
        }
        k = buf[OMEGA + i];
        h.push(hi);
      }
      for (let j = k; j < OMEGA; j++)
        if (buf[j] !== 0)
          return false;
      return h;
    }
  };
  const ETACoder = polyCoder(ETA === 2 ? 3 : 4, (i) => ETA - i, (i) => {
    if (!(-ETA <= i && i <= ETA))
      throw new Error(`malformed key s1/s3 ${i} outside of ETA range [${-ETA}, ${ETA}]`);
    return i;
  });
  const T0Coder = polyCoder(13, (i) => (1 << D - 1) - i);
  const T1Coder = polyCoder(10);
  const ZCoder = polyCoder(GAMMA1 === 1 << 17 ? 18 : 20, (i) => crystals.smod(GAMMA1 - i));
  const W1Coder = polyCoder(GAMMA2 === GAMMA2_1 ? 6 : 4);
  const W1Vec = vecCoder(W1Coder, K);
  const publicCoder = splitCoder("publicKey", 32, vecCoder(T1Coder, K));
  const secretCoder = splitCoder("secretKey", 32, 32, TR_BYTES, vecCoder(ETACoder, L), vecCoder(ETACoder, K), vecCoder(T0Coder, K));
  const sigCoder = splitCoder("signature", C_TILDE_BYTES, vecCoder(ZCoder, L), hintCoder);
  const CoefFromHalfByte = ETA === 2 ? (n) => n < 15 ? 2 - n % 5 : false : (n) => n < 9 ? 4 - n : false;
  function RejBoundedPoly(xof_) {
    const xof = xof_;
    const r = newPoly(N);
    for (let j = 0; j < N; ) {
      const b = xof();
      for (let i = 0; j < N && i < b.length; i += 1) {
        const d1 = CoefFromHalfByte(b[i] & 15);
        const d2 = CoefFromHalfByte(b[i] >> 4 & 15);
        if (d1 !== false)
          r[j++] = d1;
        if (j < N && d2 !== false)
          r[j++] = d2;
      }
    }
    return r;
  }
  const SampleInBall = (seed) => {
    const pre = newPoly(N);
    const s = shake256.create({}).update(seed);
    const buf = new Uint8Array(shake256.blockLen);
    s.xofInto(buf);
    const masks = buf.slice(0, 8);
    for (let i = N - TAU, pos = 8, maskPos = 0, maskBit = 0; i < N; i++) {
      let b = i + 1;
      for (; b > i; ) {
        b = buf[pos++];
        if (pos < shake256.blockLen)
          continue;
        s.xofInto(buf);
        pos = 0;
      }
      pre[i] = pre[b];
      pre[b] = 1 - ((masks[maskPos] >> maskBit++ & 1) << 1);
      if (maskBit >= 8) {
        maskPos++;
        maskBit = 0;
      }
    }
    return pre;
  };
  const polyPowerRound = (p_) => {
    const p = p_;
    const res0 = newPoly(N);
    const res1 = newPoly(N);
    for (let i = 0; i < p.length; i++) {
      const { r0, r1 } = Power2Round(p[i]);
      res0[i] = r0;
      res1[i] = r1;
    }
    return { r0: res0, r1: res1 };
  };
  const polyUseHint = (u_, h_) => {
    const u = u_;
    const h = h_;
    for (let i = 0; i < N; i++)
      u[i] = UseHint(h[i], u[i]);
    return u;
  };
  const polyMakeHint = (a_, b_) => {
    const a = a_;
    const b = b_;
    const v = newPoly(N);
    let cnt = 0;
    for (let i = 0; i < N; i++) {
      const h = MakeHint(a[i], b[i]);
      v[i] = h;
      cnt += h;
    }
    return { v, cnt };
  };
  const signRandBytes = 32;
  const seedCoder = splitCoder("seed", 32, 64, 32);
  const internal = Object.freeze({
    info: Object.freeze({ type: "internal-ml-dsa" }),
    lengths: Object.freeze({
      secretKey: secretCoder.bytesLen,
      publicKey: publicCoder.bytesLen,
      seed: 32,
      signature: sigCoder.bytesLen,
      signRand: signRandBytes
    }),
    keygen: (seed) => {
      const seedDst = new Uint8Array(32 + 2);
      const randSeed = seed === void 0;
      if (randSeed)
        seed = randomBytes2(32);
      abytesDoc(seed, 32, "seed");
      seedDst.set(seed);
      if (randSeed)
        cleanBytes(seed);
      seedDst[32] = K;
      seedDst[33] = L;
      const [rho, rhoPrime, K_] = seedCoder.decode(shake256(seedDst, { dkLen: seedCoder.bytesLen }));
      const xofPrime = XOF2562(rhoPrime);
      const s1 = [];
      for (let i = 0; i < L; i++)
        s1.push(RejBoundedPoly(xofPrime.get(i & 255, i >> 8 & 255)));
      const s2 = [];
      for (let i = L; i < L + K; i++)
        s2.push(RejBoundedPoly(xofPrime.get(i & 255, i >> 8 & 255)));
      const s1Hat = s1.map((i) => crystals.NTT.encode(i.slice()));
      const t0 = [];
      const t1 = [];
      const xof = XOF1282(rho);
      const t = newPoly(N);
      for (let i = 0; i < K; i++) {
        cleanBytes(t);
        for (let j = 0; j < L; j++) {
          const aij = RejNTTPoly(xof.get(j, i));
          polyAdd(t, MultiplyNTTs(aij, s1Hat[j]));
        }
        crystals.NTT.decode(t);
        const { r0, r1 } = polyPowerRound(polyAdd(t, s2[i]));
        t0.push(r0);
        t1.push(r1);
      }
      const publicKey = publicCoder.encode([rho, t1]);
      const tr = shake256(publicKey, { dkLen: TR_BYTES });
      const secretKey = secretCoder.encode([rho, K_, tr, s1, s2, t0]);
      xof.clean();
      xofPrime.clean();
      cleanBytes(rho, rhoPrime, K_, s1, s2, s1Hat, t, t0, t1, tr, seedDst);
      return {
        publicKey,
        secretKey
      };
    },
    getPublicKey: (secretKey) => {
      const [rho, _K, _tr, s1, s2, _t0] = secretCoder.decode(secretKey);
      const xof = XOF1282(rho);
      const s1Hat = s1.map((p) => crystals.NTT.encode(p.slice()));
      const t1 = [];
      const tmp = newPoly(N);
      for (let i = 0; i < K; i++) {
        tmp.fill(0);
        for (let j = 0; j < L; j++) {
          const aij = RejNTTPoly(xof.get(j, i));
          polyAdd(tmp, MultiplyNTTs(aij, s1Hat[j]));
        }
        crystals.NTT.decode(tmp);
        polyAdd(tmp, s2[i]);
        const { r1 } = polyPowerRound(tmp);
        t1.push(r1);
      }
      xof.clean();
      cleanBytes(tmp, s1Hat, _t0, s1, s2);
      return publicCoder.encode([rho, t1]);
    },
    // NOTE: random is optional.
    sign: (msg, secretKey, opts2 = {}) => {
      validateSigOpts(opts2);
      validateInternalOpts(opts2);
      let { extraEntropy: random, externalMu = false } = opts2;
      const [rho, _K, tr, s1, s2, t0] = secretCoder.decode(secretKey);
      const A = [];
      const xof = XOF1282(rho);
      for (let i = 0; i < K; i++) {
        const pv = [];
        for (let j = 0; j < L; j++)
          pv.push(RejNTTPoly(xof.get(j, i)));
        A.push(pv);
      }
      xof.clean();
      for (let i = 0; i < L; i++)
        crystals.NTT.encode(s1[i]);
      for (let i = 0; i < K; i++) {
        crystals.NTT.encode(s2[i]);
        crystals.NTT.encode(t0[i]);
      }
      const mu = externalMu ? msg : (
        // 6: µ ← H(tr||M, 512)
        //    ▷ Compute message representative µ
        shake256.create({ dkLen: CRH_BYTES }).update(tr).update(msg).digest()
      );
      const rnd = random === false ? new Uint8Array(32) : random === void 0 ? randomBytes2(signRandBytes) : random;
      abytesDoc(rnd, 32, "extraEntropy");
      const rhoprime = shake256.create({ dkLen: CRH_BYTES }).update(_K).update(rnd).update(mu).digest();
      abytesDoc(rhoprime, CRH_BYTES);
      const x256 = XOF2562(rhoprime, ZCoder.bytesLen);
      main_loop: for (let kappa = 0; ; ) {
        const y = [];
        for (let i = 0; i < L; i++, kappa++)
          y.push(ZCoder.decode(x256.get(kappa & 255, kappa >> 8)()));
        const z = y.map((i) => crystals.NTT.encode(i.slice()));
        const w = [];
        for (let i = 0; i < K; i++) {
          const wi = newPoly(N);
          for (let j = 0; j < L; j++)
            polyAdd(wi, MultiplyNTTs(A[i][j], z[j]));
          crystals.NTT.decode(wi);
          w.push(wi);
        }
        const w1 = w.map((j) => j.map(HighBits));
        const cTilde = shake256.create({ dkLen: C_TILDE_BYTES }).update(mu).update(W1Vec.encode(w1)).digest();
        const cHat = crystals.NTT.encode(SampleInBall(cTilde));
        const cs1 = s1.map((i) => MultiplyNTTs(i, cHat));
        for (let i = 0; i < L; i++) {
          polyAdd(crystals.NTT.decode(cs1[i]), y[i]);
          if (polyChknorm(cs1[i], GAMMA1 - BETA))
            continue main_loop;
        }
        let cnt = 0;
        const h = [];
        for (let i = 0; i < K; i++) {
          const cs2 = crystals.NTT.decode(MultiplyNTTs(s2[i], cHat));
          const r0 = polySub(w[i], cs2).map(LowBits);
          if (polyChknorm(r0, GAMMA2 - BETA))
            continue main_loop;
          const ct0 = crystals.NTT.decode(MultiplyNTTs(t0[i], cHat));
          if (polyChknorm(ct0, GAMMA2))
            continue main_loop;
          polyAdd(r0, ct0);
          const hint = polyMakeHint(r0, w1[i]);
          h.push(hint.v);
          cnt += hint.cnt;
        }
        if (cnt > OMEGA)
          continue;
        x256.clean();
        const res = sigCoder.encode([cTilde, cs1, h]);
        cleanBytes(cTilde, cs1, h, cHat, w1, w, z, y, rhoprime, s1, s2, t0, ...A);
        if (!externalMu)
          cleanBytes(mu);
        return res;
      }
      throw new Error("Unreachable code path reached, report this error");
    },
    verify: (sig, msg, publicKey, opts2 = {}) => {
      validateInternalOpts(opts2);
      const { externalMu = false } = opts2;
      const [rho, t1] = publicCoder.decode(publicKey);
      const tr = shake256(publicKey, { dkLen: TR_BYTES });
      if (sig.length !== sigCoder.bytesLen)
        return false;
      const [cTilde, z, h] = sigCoder.decode(sig);
      if (h === false)
        return false;
      for (let i = 0; i < L; i++)
        if (polyChknorm(z[i], GAMMA1 - BETA))
          return false;
      const mu = externalMu ? msg : (
        // 7: µ ← H(tr||M, 512)
        shake256.create({ dkLen: CRH_BYTES }).update(tr).update(msg).digest()
      );
      const c = crystals.NTT.encode(SampleInBall(cTilde));
      const zNtt = z.map((i) => i.slice());
      for (let i = 0; i < L; i++)
        crystals.NTT.encode(zNtt[i]);
      const wTick1 = [];
      const xof = XOF1282(rho);
      for (let i = 0; i < K; i++) {
        const ct12d = MultiplyNTTs(crystals.NTT.encode(polyShiftl(t1[i])), c);
        const Az = newPoly(N);
        for (let j = 0; j < L; j++) {
          const aij = RejNTTPoly(xof.get(j, i));
          polyAdd(Az, MultiplyNTTs(aij, zNtt[j]));
        }
        const wApprox = crystals.NTT.decode(polySub(Az, ct12d));
        wTick1.push(polyUseHint(wApprox, h[i]));
      }
      xof.clean();
      const c2 = shake256.create({ dkLen: C_TILDE_BYTES }).update(mu).update(W1Vec.encode(wTick1)).digest();
      for (const t of h) {
        const sum = t.reduce((acc, i) => acc + i, 0);
        if (!(sum <= OMEGA))
          return false;
      }
      for (const t of z)
        if (polyChknorm(t, GAMMA1 - BETA))
          return false;
      return equalBytes(cTilde, c2);
    }
  });
  return Object.freeze({
    info: Object.freeze({ type: "ml-dsa" }),
    internal,
    securityLevel,
    keygen: internal.keygen,
    lengths: internal.lengths,
    getPublicKey: internal.getPublicKey,
    sign: (msg, secretKey, opts2 = {}) => {
      validateSigOpts(opts2);
      const M = getMessage(msg, opts2.context);
      const res = internal.sign(M, secretKey, opts2);
      cleanBytes(M);
      return res;
    },
    verify: (sig, msg, publicKey, opts2 = {}) => {
      validateVerOpts(opts2);
      return internal.verify(sig, getMessage(msg, opts2.context), publicKey);
    },
    prehash: (hash) => {
      checkHash(hash, securityLevel);
      return Object.freeze({
        info: Object.freeze({ type: "hashml-dsa" }),
        securityLevel,
        lengths: internal.lengths,
        keygen: internal.keygen,
        getPublicKey: internal.getPublicKey,
        sign: (msg, secretKey, opts2 = {}) => {
          validateSigOpts(opts2);
          const M = getMessagePrehash(hash, msg, opts2.context);
          const res = internal.sign(M, secretKey, opts2);
          cleanBytes(M);
          return res;
        },
        verify: (sig, msg, publicKey, opts2 = {}) => {
          validateVerOpts(opts2);
          return internal.verify(sig, getMessagePrehash(hash, msg, opts2.context), publicKey);
        }
      });
    }
  });
}
var ml_dsa87 = /* @__PURE__ */ (() => getDilithium({
  ...PARAMS[5],
  CRH_BYTES: 64,
  TR_BYTES: 64,
  C_TILDE_BYTES: 64,
  XOF128,
  XOF256,
  securityLevel: 256
}))();

// node_modules/@noble/hashes/_md.js
function Chi(a, b, c) {
  return a & b ^ ~a & c;
}
function Maj(a, b, c) {
  return a & b ^ a & c ^ b & c;
}
var HashMD = class {
  blockLen;
  outputLen;
  canXOF = false;
  padOffset;
  isLE;
  // For partial updates less than block size
  buffer;
  view;
  finished = false;
  length = 0;
  pos = 0;
  destroyed = false;
  constructor(blockLen, outputLen, padOffset, isLE3) {
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE3;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
  }
  update(data) {
    aexists(this);
    abytes(data);
    const { view, buffer, blockLen } = this;
    const len = data.length;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        const dataView = createView(data);
        for (; blockLen <= len - pos; pos += blockLen)
          this.process(dataView, pos);
        continue;
      }
      buffer.set(data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
      }
    }
    this.length += data.length;
    this.roundClean();
    return this;
  }
  digestInto(out) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const { buffer, view, blockLen, isLE: isLE3 } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    clean(this.buffer.subarray(pos));
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      pos = 0;
    }
    for (let i = pos; i < blockLen; i++)
      buffer[i] = 0;
    view.setBigUint64(blockLen - 8, BigInt(this.length * 8), isLE3);
    this.process(view, 0);
    const oview = createView(out);
    const len = this.outputLen;
    if (len % 4)
      throw new Error("_sha2: outputLen must be aligned to 32bit");
    const outLen = len / 4;
    const state = this.get();
    if (outLen > state.length)
      throw new Error("_sha2: outputLen bigger than state");
    for (let i = 0; i < outLen; i++)
      oview.setUint32(4 * i, state[i], isLE3);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneInto(to) {
    to ||= new this.constructor();
    to.set(...this.get());
    const { blockLen, buffer, length, finished, destroyed, pos } = this;
    to.destroyed = destroyed;
    to.finished = finished;
    to.length = length;
    to.pos = pos;
    if (length % blockLen)
      to.buffer.set(buffer);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
};
var SHA256_IV = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
]);

// node_modules/@noble/hashes/sha2.js
var SHA256_K = /* @__PURE__ */ Uint32Array.from([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
var SHA256_W = /* @__PURE__ */ new Uint32Array(64);
var SHA2_32B = class extends HashMD {
  constructor(outputLen) {
    super(64, outputLen, 8, false);
  }
  get() {
    const { A, B, C, D: D2, E, F: F2, G, H } = this;
    return [A, B, C, D2, E, F2, G, H];
  }
  // prettier-ignore
  set(A, B, C, D2, E, F2, G, H) {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D2 | 0;
    this.E = E | 0;
    this.F = F2 | 0;
    this.G = G | 0;
    this.H = H | 0;
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4)
      SHA256_W[i] = view.getUint32(offset, false);
    for (let i = 16; i < 64; i++) {
      const W15 = SHA256_W[i - 15];
      const W2 = SHA256_W[i - 2];
      const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
      const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
      SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
    }
    let { A, B, C, D: D2, E, F: F2, G, H } = this;
    for (let i = 0; i < 64; i++) {
      const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
      const T1 = H + sigma1 + Chi(E, F2, G) + SHA256_K[i] + SHA256_W[i] | 0;
      const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
      const T2 = sigma0 + Maj(A, B, C) | 0;
      H = G;
      G = F2;
      F2 = E;
      E = D2 + T1 | 0;
      D2 = C;
      C = B;
      B = A;
      A = T1 + T2 | 0;
    }
    A = A + this.A | 0;
    B = B + this.B | 0;
    C = C + this.C | 0;
    D2 = D2 + this.D | 0;
    E = E + this.E | 0;
    F2 = F2 + this.F | 0;
    G = G + this.G | 0;
    H = H + this.H | 0;
    this.set(A, B, C, D2, E, F2, G, H);
  }
  roundClean() {
    clean(SHA256_W);
  }
  destroy() {
    this.destroyed = true;
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
    clean(this.buffer);
  }
};
var _SHA256 = class extends SHA2_32B {
  // We cannot use array here since array allows indexing by variable
  // which means optimizer/compiler cannot use registers.
  A = SHA256_IV[0] | 0;
  B = SHA256_IV[1] | 0;
  C = SHA256_IV[2] | 0;
  D = SHA256_IV[3] | 0;
  E = SHA256_IV[4] | 0;
  F = SHA256_IV[5] | 0;
  G = SHA256_IV[6] | 0;
  H = SHA256_IV[7] | 0;
  constructor() {
    super(32);
  }
};
var sha256 = /* @__PURE__ */ createHasher(
  () => new _SHA256(),
  /* @__PURE__ */ oidNist(1)
);

// lib/provenance-canonical.ts
var PROVENANCE_CONTEXT = "throndar-provenance-v1";
var EXPORT_CONTEXT = "throndar-export-v1";
var STH_CONTEXT = "throndar-sth-v1";
var AUTOPILOT_CONTEXT = "throndar-autopilot-v1";
function sha256HexUtf8(text) {
  return bytesToHex(sha256(new TextEncoder().encode(text)));
}
function canonicalBytes(c) {
  const core = {
    v: c.v,
    model: c.model,
    answer_sha256: c.answer_sha256,
    governance_flag: c.governance_flag,
    ts: c.ts
  };
  if (c.council_grounded === false) core.council_grounded = false;
  return new TextEncoder().encode(JSON.stringify(core));
}
function contextBytes(ctx = PROVENANCE_CONTEXT) {
  return new TextEncoder().encode(ctx);
}

// node_modules/@noble/ciphers/utils.js
function isBytes2(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
}
function abool2(b) {
  if (typeof b !== "boolean")
    throw new TypeError(`boolean expected, not ${b}`);
}
function anumber3(n) {
  if (typeof n !== "number")
    throw new TypeError("number expected, got " + typeof n);
  if (!Number.isSafeInteger(n) || n < 0)
    throw new RangeError("positive integer expected, got " + n);
}
function abytes3(value, length, title = "") {
  const bytes = isBytes2(value);
  const len = value?.length;
  const needsLen = length !== void 0;
  if (!bytes || needsLen && len !== length) {
    const prefix = title && `"${title}" `;
    const ofLen = needsLen ? ` of length ${length}` : "";
    const got = bytes ? `length=${len}` : `type=${typeof value}`;
    const message = prefix + "expected Uint8Array" + ofLen + ", got " + got;
    if (!bytes)
      throw new TypeError(message);
    throw new RangeError(message);
  }
  return value;
}
function u82(arr) {
  return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
}
function u322(arr) {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
function clean2(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
var isLE2 = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
var byteSwap2 = (word) => word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
var swap8IfBE = isLE2 ? (n) => n : (n) => byteSwap2(n) >>> 0;
var byteSwap322 = (arr) => {
  for (let i = 0; i < arr.length; i++)
    arr[i] = byteSwap2(arr[i]);
  return arr;
};
var swap32IfBE2 = isLE2 ? (u) => u : byteSwap322;
function overlapBytes(a, b) {
  if (!a.byteLength || !b.byteLength)
    return false;
  return a.buffer === b.buffer && // best we can do, may fail with an obscure Proxy
  a.byteOffset < b.byteOffset + b.byteLength && // a starts before b end
  b.byteOffset < a.byteOffset + a.byteLength;
}
function complexOverlapBytes(input, output) {
  if (overlapBytes(input, output) && input.byteOffset < output.byteOffset)
    throw new Error("complex overlap of input and output is not supported");
}
function checkOpts(defaults, opts) {
  if (opts == null || typeof opts !== "object")
    throw new Error("options must be defined");
  const merged = Object.assign(defaults, opts);
  return merged;
}
var wrapCipher = /* @__NO_SIDE_EFFECTS__ */ (params, constructor) => {
  function wrappedCipher(key, ...args) {
    abytes3(key, void 0, "key");
    if (params.nonceLength !== void 0) {
      const nonce = args[0];
      abytes3(nonce, params.varSizeNonce ? void 0 : params.nonceLength, "nonce");
    }
    const tagl = params.tagLength;
    if (tagl && args[1] !== void 0)
      abytes3(args[1], void 0, "AAD");
    const cipher = constructor(key, ...args);
    const checkOutput = (fnLength, output) => {
      if (output !== void 0) {
        if (fnLength !== 2)
          throw new Error("cipher output not supported");
        abytes3(output, void 0, "output");
      }
    };
    let called = false;
    const wrCipher = {
      encrypt(data, output) {
        if (called)
          throw new Error("cannot encrypt() twice with same key + nonce");
        called = true;
        abytes3(data);
        checkOutput(cipher.encrypt.length, output);
        return cipher.encrypt(data, output);
      },
      decrypt(data, output) {
        abytes3(data);
        if (tagl && data.length < tagl)
          throw new Error('"ciphertext" expected length bigger than tagLength=' + tagl);
        checkOutput(cipher.decrypt.length, output);
        return cipher.decrypt(data, output);
      }
    };
    return wrCipher;
  }
  Object.assign(wrappedCipher, params);
  return wrappedCipher;
};
function getOutput(expectedLength, out, onlyAligned = true) {
  if (out === void 0)
    return new Uint8Array(expectedLength);
  abytes3(out, void 0, "output");
  if (out.length !== expectedLength)
    throw new Error('"output" expected Uint8Array of length ' + expectedLength + ", got: " + out.length);
  if (onlyAligned && !isAligned32(out))
    throw new Error("invalid output, must be aligned");
  return out;
}
function isAligned32(bytes) {
  return bytes.byteOffset % 4 === 0;
}
function copyBytes2(bytes) {
  return Uint8Array.from(abytes3(bytes));
}

// node_modules/@noble/ciphers/aes.js
var BLOCK_SIZE = 16;
var BLOCK_SIZE32 = 4;
var POLY = 283;
function validateKeyLength(key) {
  if (![16, 24, 32].includes(key.length))
    throw new Error('"aes key" expected Uint8Array of length 16/24/32, got length=' + key.length);
}
function mul2(n) {
  return n << 1 ^ POLY & -(n >> 7);
}
function mul(a, b) {
  let res = 0;
  for (; b > 0; b >>= 1) {
    res ^= a & -(b & 1);
    a = mul2(a);
  }
  return res;
}
var incBytes = (data, isLE3, carry = 1) => {
  if (!Number.isSafeInteger(carry) || carry > 4294967040)
    throw new Error("incBytes: wrong carry " + carry);
  abytes3(data);
  for (let i = 0; i < data.length; i++) {
    const pos = !isLE3 ? data.length - 1 - i : i;
    carry = carry + (data[pos] & 255) | 0;
    data[pos] = carry & 255;
    carry >>>= 8;
  }
};
var sbox = /* @__PURE__ */ (() => {
  const t = new Uint8Array(256);
  for (let i = 0, x = 1; i < 256; i++, x ^= mul2(x))
    t[i] = x;
  const box = new Uint8Array(256);
  box[0] = 99;
  for (let i = 0; i < 255; i++) {
    let x = t[255 - i];
    x |= x << 8;
    box[t[i]] = (x ^ x >> 4 ^ x >> 5 ^ x >> 6 ^ x >> 7 ^ 99) & 255;
  }
  clean2(t);
  return box;
})();
var rotr32_8 = (n) => n << 24 | n >>> 8;
var rotl32_8 = (n) => n << 8 | n >>> 24;
function genTtable(sbox2, fn) {
  if (sbox2.length !== 256)
    throw new Error("Wrong sbox length");
  const T0 = new Uint32Array(256).map((_, j) => fn(sbox2[j]));
  const T1 = T0.map(rotl32_8);
  const T2 = T1.map(rotl32_8);
  const T3 = T2.map(rotl32_8);
  const T01 = new Uint32Array(256 * 256);
  const T23 = new Uint32Array(256 * 256);
  const sbox22 = new Uint16Array(256 * 256);
  for (let i = 0; i < 256; i++) {
    for (let j = 0; j < 256; j++) {
      const idx = i * 256 + j;
      T01[idx] = T0[i] ^ T1[j];
      T23[idx] = T2[i] ^ T3[j];
      sbox22[idx] = sbox2[i] << 8 | sbox2[j];
    }
  }
  return { sbox: sbox2, sbox2: sbox22, T0, T1, T2, T3, T01, T23 };
}
var tableEncoding = /* @__PURE__ */ genTtable(sbox, (s) => mul(s, 3) << 24 | s << 16 | s << 8 | mul(s, 2));
var xPowers = /* @__PURE__ */ (() => {
  const p = new Uint8Array(16);
  for (let i = 0, x = 1; i < 16; i++, x = mul2(x))
    p[i] = x;
  return p;
})();
function expandKeyLE(key) {
  abytes3(key);
  const len = key.length;
  validateKeyLength(key);
  const { sbox2 } = tableEncoding;
  const toClean = [];
  if (!isLE2 || !isAligned32(key))
    toClean.push(key = copyBytes2(key));
  const k32 = swap32IfBE2(u322(key));
  const Nk = k32.length;
  const subByte = (n) => applySbox(sbox2, n, n, n, n);
  const xk = new Uint32Array(len + 28);
  xk.set(k32);
  for (let i = Nk; i < xk.length; i++) {
    let t = xk[i - 1];
    if (i % Nk === 0)
      t = subByte(rotr32_8(t)) ^ xPowers[i / Nk - 1];
    else if (Nk > 6 && i % Nk === 4)
      t = subByte(t);
    xk[i] = xk[i - Nk] ^ t;
  }
  clean2(...toClean);
  return xk;
}
function apply0123(T01, T23, s0, s1, s2, s3) {
  return T01[s0 << 8 & 65280 | s1 >>> 8 & 255] ^ T23[s2 >>> 8 & 65280 | s3 >>> 24 & 255];
}
function applySbox(sbox2, s0, s1, s2, s3) {
  return sbox2[s0 & 255 | s1 & 65280] | sbox2[s2 >>> 16 & 255 | s3 >>> 16 & 65280] << 16;
}
function encrypt(xk, s0, s1, s2, s3) {
  const { sbox2, T01, T23 } = tableEncoding;
  let k = 0;
  s0 ^= xk[k++], s1 ^= xk[k++], s2 ^= xk[k++], s3 ^= xk[k++];
  const rounds = xk.length / 4 - 2;
  for (let i = 0; i < rounds; i++) {
    const t02 = xk[k++] ^ apply0123(T01, T23, s0, s1, s2, s3);
    const t12 = xk[k++] ^ apply0123(T01, T23, s1, s2, s3, s0);
    const t22 = xk[k++] ^ apply0123(T01, T23, s2, s3, s0, s1);
    const t32 = xk[k++] ^ apply0123(T01, T23, s3, s0, s1, s2);
    s0 = t02, s1 = t12, s2 = t22, s3 = t32;
  }
  const t0 = xk[k++] ^ applySbox(sbox2, s0, s1, s2, s3);
  const t1 = xk[k++] ^ applySbox(sbox2, s1, s2, s3, s0);
  const t2 = xk[k++] ^ applySbox(sbox2, s2, s3, s0, s1);
  const t3 = xk[k++] ^ applySbox(sbox2, s3, s0, s1, s2);
  return { s0: t0, s1: t1, s2: t2, s3: t3 };
}
function ctrCounter(xk, nonce, src, dst) {
  abytes3(nonce, BLOCK_SIZE, "nonce");
  abytes3(src);
  const srcLen = src.length;
  dst = getOutput(srcLen, dst);
  complexOverlapBytes(src, dst);
  const ctr2 = nonce;
  const c32 = u322(ctr2);
  const src32 = u322(src);
  const dst32 = u322(dst);
  let { s0, s1, s2, s3 } = encrypt(xk, swap8IfBE(c32[0]), swap8IfBE(c32[1]), swap8IfBE(c32[2]), swap8IfBE(c32[3]));
  for (let i = 0; i + 4 <= src32.length; i += 4) {
    dst32[i + 0] = src32[i + 0] ^ swap8IfBE(s0);
    dst32[i + 1] = src32[i + 1] ^ swap8IfBE(s1);
    dst32[i + 2] = src32[i + 2] ^ swap8IfBE(s2);
    dst32[i + 3] = src32[i + 3] ^ swap8IfBE(s3);
    incBytes(ctr2, false, 1);
    ({ s0, s1, s2, s3 } = encrypt(xk, swap8IfBE(c32[0]), swap8IfBE(c32[1]), swap8IfBE(c32[2]), swap8IfBE(c32[3])));
  }
  const start = BLOCK_SIZE * Math.floor(src32.length / BLOCK_SIZE32);
  if (start < srcLen) {
    const b32 = new Uint32Array([s0, s1, s2, s3]);
    swap32IfBE2(b32);
    const buf = u82(b32);
    for (let i = start, pos = 0; i < srcLen; i++, pos++)
      dst[i] = src[i] ^ buf[pos];
    clean2(b32);
  }
  return dst;
}
var ctr = /* @__PURE__ */ wrapCipher({ blockSize: 16, nonceLength: 16 }, function aesctr(key, nonce) {
  function processCtr(buf, dst) {
    abytes3(buf);
    if (dst !== void 0) {
      abytes3(dst);
      if (!isAligned32(dst))
        throw new Error("unaligned destination");
    }
    const xk = expandKeyLE(key);
    const n = copyBytes2(nonce);
    const toClean = [xk, n];
    if (!isAligned32(buf))
      toClean.push(buf = copyBytes2(buf));
    const out = ctrCounter(xk, n, buf, dst);
    clean2(...toClean);
    return out;
  }
  return {
    encrypt: (plaintext, dst) => processCtr(plaintext, dst),
    decrypt: (ciphertext, dst) => processCtr(ciphertext, dst)
  };
});
var _AesCtrDRBG = class {
  blockLen;
  key;
  nonce;
  state;
  reseedCnt;
  constructor(keyLen, seed, personalization) {
    this.blockLen = ctr.blockSize;
    const keyLenBytes = keyLen / 8;
    const nonceLen = 16;
    this.state = new Uint8Array(keyLenBytes + nonceLen);
    this.key = this.state.subarray(0, keyLenBytes);
    this.nonce = this.state.subarray(keyLenBytes, keyLenBytes + nonceLen);
    this.reseedCnt = 1;
    incBytes(this.nonce, false, 1);
    this.addEntropy(seed, personalization);
  }
  update(data) {
    ctr(this.key, this.nonce).encrypt(new Uint8Array(this.state.length), this.state);
    if (data) {
      abytes3(data);
      for (let i = 0; i < data.length; i++)
        this.state[i] ^= data[i];
    }
    incBytes(this.nonce, false, 1);
  }
  // Optional `info` is additional input XORed into the reseed block and is
  // limited to the internal state width.
  addEntropy(seed, info) {
    abytes3(seed, this.state.length, "seed");
    const _seed = seed.slice();
    if (info) {
      abytes3(info);
      if (info.length > _seed.length)
        throw new Error("info length is too big");
      for (let i = 0; i < info.length; i++)
        _seed[i] ^= info[i];
    }
    this.update(_seed);
    _seed.fill(0);
    this.reseedCnt = 1;
  }
  // Optional `info` is additional input for the pre/post-update steps; bytes
  // SP 800-90A Rev. 1 CTR_DRBG without a derivation function limits
  // additional_input to seedlen, which is exactly this internal state width.
  randomBytes(len, info) {
    anumber3(len);
    if (len > 2 ** 16)
      throw new Error("requested output is too big");
    if (this.reseedCnt > 2 ** 48)
      throw new Error("entropy exhausted");
    if (info) {
      abytes3(info);
      if (info.length > this.state.length)
        throw new Error("info length is too big");
      this.update(info);
    }
    const res = new Uint8Array(len);
    ctr(this.key, this.nonce).encrypt(res, res);
    incBytes(this.nonce, false, Math.ceil(len / this.blockLen));
    this.update(info);
    this.reseedCnt++;
    return res;
  }
  // Zeroes the current state and resets the counter, but does not make the
  // instance unusable: later calls continue from the zeroed state.
  clean() {
    this.state.fill(0);
    this.reseedCnt = 0;
  }
};
var createAesDrbg = (keyLen) => {
  return (seed, personalization = void 0) => new _AesCtrDRBG(keyLen, seed, personalization);
};
var rngAesCtrDrbg256 = /* @__PURE__ */ createAesDrbg(256);

// node_modules/@noble/ciphers/_arx.js
var encodeStr = (str) => Uint8Array.from(str.split(""), (c) => c.charCodeAt(0));
var sigma16_32 = /* @__PURE__ */ (() => swap32IfBE2(u322(encodeStr("expand 16-byte k"))))();
var sigma32_32 = /* @__PURE__ */ (() => swap32IfBE2(u322(encodeStr("expand 32-byte k"))))();
function rotl(a, b) {
  return a << b | a >>> 32 - b;
}
var BLOCK_LEN = 64;
var BLOCK_LEN32 = 16;
var MAX_COUNTER = /* @__PURE__ */ (() => 2 ** 32 - 1)();
var U32_EMPTY = /* @__PURE__ */ Uint32Array.of();
function runCipher(core, sigma, key, nonce, data, output, counter, rounds) {
  const len = data.length;
  const block = new Uint8Array(BLOCK_LEN);
  const b32 = u322(block);
  const isAligned = isLE2 && isAligned32(data) && isAligned32(output);
  const d32 = isAligned ? u322(data) : U32_EMPTY;
  const o32 = isAligned ? u322(output) : U32_EMPTY;
  if (!isLE2) {
    for (let pos = 0; pos < len; counter++) {
      core(sigma, key, nonce, b32, counter, rounds);
      swap32IfBE2(b32);
      if (counter >= MAX_COUNTER)
        throw new Error("arx: counter overflow");
      const take = Math.min(BLOCK_LEN, len - pos);
      for (let j = 0, posj; j < take; j++) {
        posj = pos + j;
        output[posj] = data[posj] ^ block[j];
      }
      pos += take;
    }
    return;
  }
  for (let pos = 0; pos < len; counter++) {
    core(sigma, key, nonce, b32, counter, rounds);
    if (counter >= MAX_COUNTER)
      throw new Error("arx: counter overflow");
    const take = Math.min(BLOCK_LEN, len - pos);
    if (isAligned && take === BLOCK_LEN) {
      const pos32 = pos / 4;
      if (pos % 4 !== 0)
        throw new Error("arx: invalid block position");
      for (let j = 0, posj; j < BLOCK_LEN32; j++) {
        posj = pos32 + j;
        o32[posj] = d32[posj] ^ b32[j];
      }
      pos += BLOCK_LEN;
      continue;
    }
    for (let j = 0, posj; j < take; j++) {
      posj = pos + j;
      output[posj] = data[posj] ^ block[j];
    }
    pos += take;
  }
}
function createCipher(core, opts) {
  const { allowShortKeys, extendNonceFn, counterLength, counterRight, rounds } = checkOpts({ allowShortKeys: false, counterLength: 8, counterRight: false, rounds: 20 }, opts);
  if (typeof core !== "function")
    throw new Error("core must be a function");
  anumber3(counterLength);
  anumber3(rounds);
  abool2(counterRight);
  abool2(allowShortKeys);
  return (key, nonce, data, output, counter = 0) => {
    abytes3(key, void 0, "key");
    abytes3(nonce, void 0, "nonce");
    abytes3(data, void 0, "data");
    const len = data.length;
    output = getOutput(len, output, false);
    anumber3(counter);
    if (counter < 0 || counter >= MAX_COUNTER)
      throw new Error("arx: counter overflow");
    const toClean = [];
    let l = key.length;
    let k;
    let sigma;
    if (l === 32) {
      toClean.push(k = copyBytes2(key));
      sigma = sigma32_32;
    } else if (l === 16 && allowShortKeys) {
      k = new Uint8Array(32);
      k.set(key);
      k.set(key, 16);
      sigma = sigma16_32;
      toClean.push(k);
    } else {
      abytes3(key, 32, "arx key");
      throw new Error("invalid key size");
    }
    if (!isLE2 || !isAligned32(nonce))
      toClean.push(nonce = copyBytes2(nonce));
    let k32 = u322(k);
    if (extendNonceFn) {
      if (nonce.length !== 24)
        throw new Error(`arx: extended nonce must be 24 bytes`);
      const n16 = nonce.subarray(0, 16);
      if (isLE2)
        extendNonceFn(sigma, k32, u322(n16), k32);
      else {
        const sigmaRaw = swap32IfBE2(Uint32Array.from(sigma));
        extendNonceFn(sigmaRaw, k32, u322(n16), k32);
        clean2(sigmaRaw);
        swap32IfBE2(k32);
      }
      nonce = nonce.subarray(16);
    } else if (!isLE2)
      swap32IfBE2(k32);
    const nonceNcLen = 16 - counterLength;
    if (nonceNcLen !== nonce.length)
      throw new Error(`arx: nonce must be ${nonceNcLen} or 16 bytes`);
    if (nonceNcLen !== 12) {
      const nc = new Uint8Array(12);
      nc.set(nonce, counterRight ? 0 : 12 - nonce.length);
      nonce = nc;
      toClean.push(nonce);
    }
    const n32 = swap32IfBE2(u322(nonce));
    try {
      runCipher(core, sigma, k32, n32, data, output, counter, rounds);
      return output;
    } finally {
      clean2(...toClean);
    }
  };
}

// node_modules/@noble/ciphers/chacha.js
function chachaCore(s, k, n, out, cnt, rounds = 20) {
  let y00 = s[0], y01 = s[1], y02 = s[2], y03 = s[3], y04 = k[0], y05 = k[1], y06 = k[2], y07 = k[3], y08 = k[4], y09 = k[5], y10 = k[6], y11 = k[7], y12 = cnt, y13 = n[0], y14 = n[1], y15 = n[2];
  let x00 = y00, x01 = y01, x02 = y02, x03 = y03, x04 = y04, x05 = y05, x06 = y06, x07 = y07, x08 = y08, x09 = y09, x10 = y10, x11 = y11, x12 = y12, x13 = y13, x14 = y14, x15 = y15;
  for (let r = 0; r < rounds; r += 2) {
    x00 = x00 + x04 | 0;
    x12 = rotl(x12 ^ x00, 16);
    x08 = x08 + x12 | 0;
    x04 = rotl(x04 ^ x08, 12);
    x00 = x00 + x04 | 0;
    x12 = rotl(x12 ^ x00, 8);
    x08 = x08 + x12 | 0;
    x04 = rotl(x04 ^ x08, 7);
    x01 = x01 + x05 | 0;
    x13 = rotl(x13 ^ x01, 16);
    x09 = x09 + x13 | 0;
    x05 = rotl(x05 ^ x09, 12);
    x01 = x01 + x05 | 0;
    x13 = rotl(x13 ^ x01, 8);
    x09 = x09 + x13 | 0;
    x05 = rotl(x05 ^ x09, 7);
    x02 = x02 + x06 | 0;
    x14 = rotl(x14 ^ x02, 16);
    x10 = x10 + x14 | 0;
    x06 = rotl(x06 ^ x10, 12);
    x02 = x02 + x06 | 0;
    x14 = rotl(x14 ^ x02, 8);
    x10 = x10 + x14 | 0;
    x06 = rotl(x06 ^ x10, 7);
    x03 = x03 + x07 | 0;
    x15 = rotl(x15 ^ x03, 16);
    x11 = x11 + x15 | 0;
    x07 = rotl(x07 ^ x11, 12);
    x03 = x03 + x07 | 0;
    x15 = rotl(x15 ^ x03, 8);
    x11 = x11 + x15 | 0;
    x07 = rotl(x07 ^ x11, 7);
    x00 = x00 + x05 | 0;
    x15 = rotl(x15 ^ x00, 16);
    x10 = x10 + x15 | 0;
    x05 = rotl(x05 ^ x10, 12);
    x00 = x00 + x05 | 0;
    x15 = rotl(x15 ^ x00, 8);
    x10 = x10 + x15 | 0;
    x05 = rotl(x05 ^ x10, 7);
    x01 = x01 + x06 | 0;
    x12 = rotl(x12 ^ x01, 16);
    x11 = x11 + x12 | 0;
    x06 = rotl(x06 ^ x11, 12);
    x01 = x01 + x06 | 0;
    x12 = rotl(x12 ^ x01, 8);
    x11 = x11 + x12 | 0;
    x06 = rotl(x06 ^ x11, 7);
    x02 = x02 + x07 | 0;
    x13 = rotl(x13 ^ x02, 16);
    x08 = x08 + x13 | 0;
    x07 = rotl(x07 ^ x08, 12);
    x02 = x02 + x07 | 0;
    x13 = rotl(x13 ^ x02, 8);
    x08 = x08 + x13 | 0;
    x07 = rotl(x07 ^ x08, 7);
    x03 = x03 + x04 | 0;
    x14 = rotl(x14 ^ x03, 16);
    x09 = x09 + x14 | 0;
    x04 = rotl(x04 ^ x09, 12);
    x03 = x03 + x04 | 0;
    x14 = rotl(x14 ^ x03, 8);
    x09 = x09 + x14 | 0;
    x04 = rotl(x04 ^ x09, 7);
  }
  let oi = 0;
  out[oi++] = y00 + x00 | 0;
  out[oi++] = y01 + x01 | 0;
  out[oi++] = y02 + x02 | 0;
  out[oi++] = y03 + x03 | 0;
  out[oi++] = y04 + x04 | 0;
  out[oi++] = y05 + x05 | 0;
  out[oi++] = y06 + x06 | 0;
  out[oi++] = y07 + x07 | 0;
  out[oi++] = y08 + x08 | 0;
  out[oi++] = y09 + x09 | 0;
  out[oi++] = y10 + x10 | 0;
  out[oi++] = y11 + x11 | 0;
  out[oi++] = y12 + x12 | 0;
  out[oi++] = y13 + x13 | 0;
  out[oi++] = y14 + x14 | 0;
  out[oi++] = y15 + x15 | 0;
}
var chacha20 = /* @__PURE__ */ createCipher(chachaCore, {
  counterRight: false,
  counterLength: 4,
  allowShortKeys: false
});

// node_modules/@noble/curves/abstract/modular.js
var _0n3 = /* @__PURE__ */ BigInt(0);
var _1n3 = /* @__PURE__ */ BigInt(1);
var _2n2 = /* @__PURE__ */ BigInt(2);
var _3n = /* @__PURE__ */ BigInt(3);
var _4n = /* @__PURE__ */ BigInt(4);
var _5n = /* @__PURE__ */ BigInt(5);
var _7n2 = /* @__PURE__ */ BigInt(7);
var _8n = /* @__PURE__ */ BigInt(8);
var _9n = /* @__PURE__ */ BigInt(9);
var _16n = /* @__PURE__ */ BigInt(16);
function mod(a, b) {
  if (b <= _0n3)
    throw new Error("mod: expected positive modulus, got " + b);
  const result = a % b;
  return result >= _0n3 ? result : b + result;
}
function invert(number, modulo) {
  if (number === _0n3)
    throw new Error("invert: expected non-zero number");
  if (modulo <= _0n3)
    throw new Error("invert: expected positive modulus, got " + modulo);
  let a = mod(number, modulo);
  let b = modulo;
  let x = _0n3, y = _1n3, u = _1n3, v = _0n3;
  while (a !== _0n3) {
    const q = b / a;
    const r = b - a * q;
    const m = x - u * q;
    const n = y - v * q;
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  const gcd = b;
  if (gcd !== _1n3)
    throw new Error("invert: does not exist");
  return mod(x, modulo);
}
function assertIsSquare(Fp, root, n) {
  const F2 = Fp;
  if (!F2.eql(F2.sqr(root), n))
    throw new Error("Cannot find square root");
}
function sqrt3mod4(Fp, n) {
  const F2 = Fp;
  const p1div4 = (F2.ORDER + _1n3) / _4n;
  const root = F2.pow(n, p1div4);
  assertIsSquare(F2, root, n);
  return root;
}
function sqrt5mod8(Fp, n) {
  const F2 = Fp;
  const p5div8 = (F2.ORDER - _5n) / _8n;
  const n2 = F2.mul(n, _2n2);
  const v = F2.pow(n2, p5div8);
  const nv = F2.mul(n, v);
  const i = F2.mul(F2.mul(nv, _2n2), v);
  const root = F2.mul(nv, F2.sub(i, F2.ONE));
  assertIsSquare(F2, root, n);
  return root;
}
function sqrt9mod16(P) {
  const Fp_ = Field(P);
  const tn = tonelliShanks(P);
  const c1 = tn(Fp_, Fp_.neg(Fp_.ONE));
  const c2 = tn(Fp_, c1);
  const c3 = tn(Fp_, Fp_.neg(c1));
  const c4 = (P + _7n2) / _16n;
  return ((Fp, n) => {
    const F2 = Fp;
    let tv1 = F2.pow(n, c4);
    let tv2 = F2.mul(tv1, c1);
    const tv3 = F2.mul(tv1, c2);
    const tv4 = F2.mul(tv1, c3);
    const e1 = F2.eql(F2.sqr(tv2), n);
    const e2 = F2.eql(F2.sqr(tv3), n);
    tv1 = F2.cmov(tv1, tv2, e1);
    tv2 = F2.cmov(tv4, tv3, e2);
    const e3 = F2.eql(F2.sqr(tv2), n);
    const root = F2.cmov(tv1, tv2, e3);
    assertIsSquare(F2, root, n);
    return root;
  });
}
function tonelliShanks(P) {
  if (P < _3n)
    throw new Error("sqrt is not defined for small field");
  let Q3 = P - _1n3;
  let S = 0;
  while (Q3 % _2n2 === _0n3) {
    Q3 /= _2n2;
    S++;
  }
  let Z = _2n2;
  const _Fp = Field(P);
  while (FpLegendre(_Fp, Z) === 1) {
    if (Z++ > 1e3)
      throw new Error("Cannot find square root: probably non-prime P");
  }
  if (S === 1)
    return sqrt3mod4;
  let cc = _Fp.pow(Z, Q3);
  const Q1div2 = (Q3 + _1n3) / _2n2;
  return function tonelliSlow(Fp, n) {
    const F2 = Fp;
    if (F2.is0(n))
      return n;
    if (FpLegendre(F2, n) !== 1)
      throw new Error("Cannot find square root");
    let M = S;
    let c = F2.mul(F2.ONE, cc);
    let t = F2.pow(n, Q3);
    let R = F2.pow(n, Q1div2);
    while (!F2.eql(t, F2.ONE)) {
      if (F2.is0(t))
        return F2.ZERO;
      let i = 1;
      let t_tmp = F2.sqr(t);
      while (!F2.eql(t_tmp, F2.ONE)) {
        i++;
        t_tmp = F2.sqr(t_tmp);
        if (i === M)
          throw new Error("Cannot find square root");
      }
      const exponent = _1n3 << BigInt(M - i - 1);
      const b = F2.pow(c, exponent);
      M = i;
      c = F2.sqr(b);
      t = F2.mul(t, c);
      R = F2.mul(R, b);
    }
    return R;
  };
}
function FpSqrt(P) {
  if (P % _4n === _3n)
    return sqrt3mod4;
  if (P % _8n === _5n)
    return sqrt5mod8;
  if (P % _16n === _9n)
    return sqrt9mod16(P);
  return tonelliShanks(P);
}
function FpPow(Fp, num, power) {
  const F2 = Fp;
  if (power < _0n3)
    throw new Error("invalid exponent, negatives unsupported");
  if (power === _0n3)
    return F2.ONE;
  if (power === _1n3)
    return num;
  let p = F2.ONE;
  let d = num;
  while (power > _0n3) {
    if (power & _1n3)
      p = F2.mul(p, d);
    d = F2.sqr(d);
    power >>= _1n3;
  }
  return p;
}
function FpInvertBatch(Fp, nums, passZero = false) {
  const F2 = Fp;
  const inverted = new Array(nums.length).fill(passZero ? F2.ZERO : void 0);
  const multipliedAcc = nums.reduce((acc, num, i) => {
    if (F2.is0(num))
      return acc;
    inverted[i] = acc;
    return F2.mul(acc, num);
  }, F2.ONE);
  const invertedAcc = F2.inv(multipliedAcc);
  nums.reduceRight((acc, num, i) => {
    if (F2.is0(num))
      return acc;
    inverted[i] = F2.mul(acc, inverted[i]);
    return F2.mul(acc, num);
  }, invertedAcc);
  return inverted;
}
function FpLegendre(Fp, n) {
  const F2 = Fp;
  const p1mod2 = (F2.ORDER - _1n3) / _2n2;
  const powered = F2.pow(n, p1mod2);
  const yes = F2.eql(powered, F2.ONE);
  const zero = F2.eql(powered, F2.ZERO);
  const no = F2.eql(powered, F2.neg(F2.ONE));
  if (!yes && !zero && !no)
    throw new Error("invalid Legendre symbol result");
  return yes ? 1 : zero ? 0 : -1;
}
function nLength(n, nBitLength) {
  if (nBitLength !== void 0)
    anumber2(nBitLength);
  if (n <= _0n3)
    throw new Error("invalid n length: expected positive n, got " + n);
  if (nBitLength !== void 0 && nBitLength < 1)
    throw new Error("invalid n length: expected positive bit length, got " + nBitLength);
  const bits = bitLen(n);
  if (nBitLength !== void 0 && nBitLength < bits)
    throw new Error(`invalid n length: expected bit length (${bits}) >= n.length (${nBitLength})`);
  const _nBitLength = nBitLength !== void 0 ? nBitLength : bits;
  const nByteLength = Math.ceil(_nBitLength / 8);
  return { nBitLength: _nBitLength, nByteLength };
}
var FIELD_SQRT = /* @__PURE__ */ new WeakMap();
var _Field = class {
  ORDER;
  BITS;
  BYTES;
  isLE;
  ZERO = _0n3;
  ONE = _1n3;
  _lengths;
  _mod;
  constructor(ORDER, opts = {}) {
    if (ORDER <= _1n3)
      throw new Error("invalid field: expected ORDER > 1, got " + ORDER);
    let _nbitLength = void 0;
    this.isLE = false;
    if (opts != null && typeof opts === "object") {
      if (typeof opts.BITS === "number")
        _nbitLength = opts.BITS;
      if (typeof opts.sqrt === "function")
        Object.defineProperty(this, "sqrt", { value: opts.sqrt, enumerable: true });
      if (typeof opts.isLE === "boolean")
        this.isLE = opts.isLE;
      if (opts.allowedLengths)
        this._lengths = Object.freeze(opts.allowedLengths.slice());
      if (typeof opts.modFromBytes === "boolean")
        this._mod = opts.modFromBytes;
    }
    const { nBitLength, nByteLength } = nLength(ORDER, _nbitLength);
    if (nByteLength > 2048)
      throw new Error("invalid field: expected ORDER of <= 2048 bytes");
    this.ORDER = ORDER;
    this.BITS = nBitLength;
    this.BYTES = nByteLength;
    Object.freeze(this);
  }
  create(num) {
    return mod(num, this.ORDER);
  }
  isValid(num) {
    if (typeof num !== "bigint")
      throw new TypeError("invalid field element: expected bigint, got " + typeof num);
    return _0n3 <= num && num < this.ORDER;
  }
  is0(num) {
    return num === _0n3;
  }
  // is valid and invertible
  isValidNot0(num) {
    return !this.is0(num) && this.isValid(num);
  }
  isOdd(num) {
    return (num & _1n3) === _1n3;
  }
  neg(num) {
    return mod(-num, this.ORDER);
  }
  eql(lhs, rhs) {
    return lhs === rhs;
  }
  sqr(num) {
    return mod(num * num, this.ORDER);
  }
  add(lhs, rhs) {
    return mod(lhs + rhs, this.ORDER);
  }
  sub(lhs, rhs) {
    return mod(lhs - rhs, this.ORDER);
  }
  mul(lhs, rhs) {
    return mod(lhs * rhs, this.ORDER);
  }
  pow(num, power) {
    return FpPow(this, num, power);
  }
  div(lhs, rhs) {
    return mod(lhs * invert(rhs, this.ORDER), this.ORDER);
  }
  // Same as above, but doesn't normalize
  sqrN(num) {
    return num * num;
  }
  addN(lhs, rhs) {
    return lhs + rhs;
  }
  subN(lhs, rhs) {
    return lhs - rhs;
  }
  mulN(lhs, rhs) {
    return lhs * rhs;
  }
  inv(num) {
    return invert(num, this.ORDER);
  }
  sqrt(num) {
    let sqrt = FIELD_SQRT.get(this);
    if (!sqrt)
      FIELD_SQRT.set(this, sqrt = FpSqrt(this.ORDER));
    return sqrt(this, num);
  }
  toBytes(num) {
    return this.isLE ? numberToBytesLE(num, this.BYTES) : numberToBytesBE(num, this.BYTES);
  }
  fromBytes(bytes, skipValidation = false) {
    abytes2(bytes);
    const { _lengths: allowedLengths, BYTES, isLE: isLE3, ORDER, _mod: modFromBytes } = this;
    if (allowedLengths) {
      if (bytes.length < 1 || !allowedLengths.includes(bytes.length) || bytes.length > BYTES) {
        throw new Error("Field.fromBytes: expected " + allowedLengths + " bytes, got " + bytes.length);
      }
      const padded = new Uint8Array(BYTES);
      padded.set(bytes, isLE3 ? 0 : padded.length - bytes.length);
      bytes = padded;
    }
    if (bytes.length !== BYTES)
      throw new Error("Field.fromBytes: expected " + BYTES + " bytes, got " + bytes.length);
    let scalar = isLE3 ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
    if (modFromBytes)
      scalar = mod(scalar, ORDER);
    if (!skipValidation) {
      if (!this.isValid(scalar))
        throw new Error("invalid field element: outside of range 0..ORDER");
    }
    return scalar;
  }
  // TODO: we don't need it here, move out to separate fn
  invertBatch(lst) {
    return FpInvertBatch(this, lst);
  }
  // We can't move this out because Fp6, Fp12 implement it
  // and it's unclear what to return in there.
  cmov(a, b, condition) {
    abool(condition, "condition");
    return condition ? b : a;
  }
};
Object.freeze(_Field.prototype);
function Field(ORDER, opts = {}) {
  return new _Field(ORDER, opts);
}

// node_modules/@noble/post-quantum/falcon.js
var bitsCoderMSB = (newPoly2, N2, d, c) => {
  const mask = getMask(d);
  const bytesLen = d * (N2 / 8);
  return {
    bytesLen,
    encode: (poly) => {
      if (poly.length !== N2)
        throw new Error(`wrong length: expected ${N2}, got ${poly.length}`);
      const r = new Uint8Array(bytesLen);
      for (let i = 0, buf = 0, bufLen = 0, pos = 0; i < poly.length; i++) {
        buf = buf << d | c.encode(poly[i]) & mask;
        bufLen += d;
        for (; bufLen >= 8; bufLen -= 8)
          r[pos++] = buf >>> bufLen - 8 & 255;
      }
      return r;
    },
    decode: (bytes) => {
      const r = newPoly2(N2);
      for (let i = 0, buf = 0, bufLen = 0, pos = 0; i < bytes.length; i++) {
        buf = buf << 8 | bytes[i];
        bufLen += 8;
        for (; bufLen >= d; bufLen -= d)
          r[pos++] = c.decode(buf >>> bufLen - d & mask);
      }
      return r;
    }
  };
};
var headerCoder = (tag, restCoder) => {
  const coder = restCoder;
  return {
    bytesLen: 1 + coder.bytesLen,
    encode(value) {
      const body = coder.encode(value);
      const out = new Uint8Array(1 + body.length);
      out[0] = tag;
      out.set(body, 1);
      cleanBytes(body);
      return out;
    },
    decode(data) {
      if (data[0] !== tag)
        throw new Error(`wrong tag: expected ${tag}, got 0x${data[0]}`);
      return coder.decode(data.subarray(1));
    }
  };
};
var compCoder = (n) => {
  const LIMIT = 2047;
  return {
    encode(data) {
      if (data.length !== n)
        throw new Error("wrong length");
      const res = [];
      let buf = 0;
      let bufLen = 0;
      const writeBits = (n2, v) => {
        bufLen += n2;
        buf = buf << n2 | v;
        for (; bufLen >= 8; buf &= getMask(bufLen)) {
          bufLen -= 8;
          res.push(buf >>> bufLen & 255);
        }
      };
      for (let i = 0; i < n; i++) {
        let v = data[i];
        if (!Number.isInteger(v) || v < -LIMIT || v > LIMIT)
          throw new Error(`data[${i}]=${v} out of range`);
        const sign = v < 0 ? 1 : 0;
        v = Math.abs(v);
        writeBits(1, sign);
        writeBits(7, v & 127);
        writeBits((v >>> 7) + 1, 1);
      }
      if (bufLen > 0)
        res.push(buf << 8 - bufLen & 255);
      return new Uint8Array(res);
    },
    decode(data) {
      const res = new Int16Array(n);
      let buf = 0;
      let bufLen = 0;
      let pos = 0;
      const readBits = (n2) => {
        for (; bufLen < n2 && pos < data.length; bufLen += 8)
          buf = buf << 8 | data[pos++];
        if (bufLen < n2)
          throw new Error(`end of buffer: len=${bufLen} buf=${buf} lastByte=${data[pos]}`);
        bufLen -= n2;
        const val = buf >>> bufLen;
        buf &= getMask(bufLen);
        return val;
      };
      for (let resPos = 0; resPos < n; resPos++) {
        const sign = readBits(1);
        const low = readBits(7);
        let high = 0;
        for (; !readBits(1); high++)
          ;
        const v = low | high << 7;
        if (sign && v === 0)
          throw new Error("negative zero encoding");
        if (v > LIMIT)
          throw new Error(`limit: ${v} > ${LIMIT}`);
        res[resPos] = sign ? -v : v;
      }
      if (buf)
        throw new Error("non-empty accumulator");
      return res;
    }
  };
};
var pad = (len) => ({
  encode(data) {
    const res = new Uint8Array(len);
    res.set(data);
    return res;
  },
  decode(data) {
    let end = data.length;
    while (end > 0 && data[end - 1] === 0)
      end--;
    return data.subarray(0, end);
  }
});
var cleanCPoly = (...list) => {
  for (const p of list) {
    for (let i = 0; i < p.length; i++) {
      p[i].re = 0;
      p[i].im = 0;
    }
  }
};
function getComplex(field) {
  const F2 = field;
  return {
    lift: (x) => {
      if (x.re !== void 0 && x.im !== void 0)
        return x;
      return { re: x, im: F2.ZERO };
    },
    add: (a, b) => ({
      re: F2.add(a.re, b.re),
      im: F2.add(a.im, b.im)
    }),
    sub: (a, b) => ({
      re: F2.sub(a.re, b.re),
      im: F2.sub(a.im, b.im)
    }),
    mul: (a, b) => ({
      re: F2.sub(F2.mul(a.re, b.re), F2.mul(a.im, b.im)),
      im: F2.add(F2.mul(a.re, b.im), F2.mul(a.im, b.re))
    }),
    div: (a, b) => {
      const denom = F2.add(F2.mul(b.re, b.re), F2.mul(b.im, b.im));
      return {
        re: F2.div(F2.add(F2.mul(a.re, b.re), F2.mul(a.im, b.im)), denom),
        im: F2.div(F2.sub(F2.mul(a.im, b.re), F2.mul(a.re, b.im)), denom)
      };
    },
    neg: (a) => ({ re: F2.neg(a.re), im: F2.neg(a.im) }),
    conj: (a) => ({ re: a.re, im: F2.neg(a.im) }),
    scale: (a, x) => ({
      re: F2.mul(a.re, x),
      im: F2.mul(a.im, x)
    }),
    // a.re * a.re + a.im * a.im + b.re * b.re + b.im * b.im;
    magSqSum: (a, b) => F2.add(F2.add(F2.add(F2.mul(a.re, a.re), F2.mul(a.im, a.im)), F2.mul(b.re, b.re)), F2.mul(b.im, b.im)),
    eql: (a, b) => F2.eql(a.re, b.re) && F2.eql(a.im, b.im),
    clone: (a) => ({ re: a.re, im: a.im }),
    inv: () => {
      throw new Error("not implemented");
    }
  };
}
var ComplexArr = {
  decode(lst) {
    const N2 = lst.length;
    const hn = N2 >> 1;
    const len = lst.length;
    if (len === 0)
      return [];
    if (len % 2 !== 0)
      throw new Error("Array length must be even to pair real and imaginary parts.");
    const res = [];
    for (let i = 0; i < hn; i++) {
      res.push({ re: lst[i], im: lst[i + hn] });
    }
    return res;
  },
  encode(lst) {
    const re = [];
    const im = [];
    for (const i of lst) {
      re.push(i.re);
      im.push(i.im);
    }
    return [...re, ...im];
  }
};
var ComplexArrInterleaved = {
  decode(lst) {
    const len = lst.length;
    if (len === 0)
      return [];
    if (len % 2 !== 0)
      throw new Error("Array length must be even to pair real and imaginary parts.");
    const res = [];
    for (let i = 0; i < len; i += 2) {
      res.push({ re: lst[i], im: lst[i + 1] });
    }
    return res;
  },
  encode(lst) {
    const res = [];
    for (const complexNum of lst) {
      res.push(complexNum.re);
      res.push(complexNum.im);
    }
    return res;
  }
};
var u8f = (arr) => new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
var f64a = (arr) => new Float64Array(baswap64If(Uint8Array.from(arr.subarray(0, Math.floor(arr.byteLength / 8) * 8))).buffer);
var Float = /* @__PURE__ */ Object.freeze({
  encode(n) {
    const bytes = new Uint8Array(8);
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    view.setFloat64(0, n, false);
    return bytesToHex(bytes);
  },
  decode(s) {
    const bytes = hexToBytes(s);
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return view.getFloat64(0, false);
  }
});
var f64b = (n) => Float.decode(numberToHexUnpadded(n));
var EMPTY_CHACHA20_BLOCK = /* @__PURE__ */ new Uint8Array(64);
var NONCELEN = 40;
var Q2 = 12289;
var Qhalf = Q2 >> 1;
var QBig = BigInt(Q2);
var R2 = 10952;
var Q0I = 12287;
var F_INV_Q = 1 / Q2;
var F_MINUS_INV_Q = -F_INV_Q;
var MAX_BL_SMALL = [1, 1, 2, 2, 4, 7, 14, 27, 53, 106, 209];
var MAX_BL_LARGE = [2, 2, 5, 7, 12, 21, 40, 78, 157, 308];
var BNORM_MAX = f64b(BigInt("4670353323383631276"));
var BITLENGTH = [
  { avg: 4, std: 0 },
  { avg: 11, std: 1 },
  { avg: 24, std: 1 },
  { avg: 50, std: 1 },
  { avg: 102, std: 1 },
  { avg: 202, std: 2 },
  { avg: 401, std: 4 },
  { avg: 794, std: 5 },
  { avg: 1577, std: 8 },
  { avg: 3138, std: 13 },
  { avg: 6308, std: 25 }
];
var gauss_1024_12289 = [
  1283868770400643928n,
  6416574995475331444n,
  4078260278032692663n,
  2353523259288686585n,
  1227179971273316331n,
  575931623374121527n,
  242543240509105209n,
  91437049221049666n,
  30799446349977173n,
  9255276791179340n,
  2478152334826140n,
  590642893610164n,
  125206034929641n,
  23590435911403n,
  3948334035941n,
  586753615614n,
  77391054539n,
  9056793210n,
  940121950n,
  86539696n,
  7062824n,
  510971n,
  32764n,
  1862n,
  94n,
  4n,
  0n
];
var INV_SIGMA = /* @__PURE__ */ Object.freeze([
  0,
  // unused
  f64b(BigInt("4574611497772390042")),
  f64b(BigInt("4574501679055810265")),
  f64b(BigInt("4574396282908341804")),
  f64b(BigInt("4574245855758572086")),
  f64b(BigInt("4574103865040221165")),
  f64b(BigInt("4573969550563515544")),
  f64b(BigInt("4573842244705920822")),
  f64b(BigInt("4573721358406441454")),
  f64b(BigInt("4573606369665796042")),
  f64b(BigInt("4573496814039276259"))
]);
var SIGMA_MIN = /* @__PURE__ */ Object.freeze([
  0,
  // unused
  f64b(BigInt("4607707126469777035")),
  f64b(BigInt("4607777455861499430")),
  f64b(BigInt("4607846828256951418")),
  f64b(BigInt("4607949175006100261")),
  f64b(BigInt("4608049571757433526")),
  f64b(BigInt("4608148125896792003")),
  f64b(BigInt("4608244935301382692")),
  f64b(BigInt("4608340089478362016")),
  f64b(BigInt("4608433670533905013")),
  f64b(BigInt("4608525754002622308"))
]);
var GAUSS0 = new Uint32Array([
  10745844,
  3068844,
  3741698,
  5559083,
  1580863,
  8248194,
  2260429,
  13669192,
  2736639,
  708981,
  4421575,
  10046180,
  169348,
  7122675,
  4136815,
  30538,
  13063405,
  7650655,
  4132,
  14505003,
  7826148,
  417,
  16768101,
  11363290,
  31,
  8444042,
  8086568,
  1,
  12844466,
  265321,
  0,
  1232676,
  13644283,
  0,
  38047,
  9111839,
  0,
  870,
  6138264,
  0,
  14,
  12545723,
  0,
  0,
  3104126,
  0,
  0,
  28824,
  0,
  0,
  198,
  0,
  0,
  1
]);
var L2BOUND = [
  0,
  // unused
  101498,
  208714,
  428865,
  892039,
  1852696,
  3842630,
  7959734,
  16468416,
  34034726,
  70265242
];
var COMPLEX_ROOTS = /* @__PURE__ */ (() => {
  const roots = f64a(hexToBytes("000000000000000000000000000000000000000000000080000000000000f03fcd3b7f669ea0e63fcd3b7f669ea0e63fcd3b7f669ea0e6bfcd3b7f669ea0e63f468d32cf6b90ed3f63a9aea6e27dd83f63a9aea6e27dd8bf468d32cf6b90ed3f63a9aea6e27dd83f468d32cf6b90ed3f468d32cf6b90edbf63a9aea6e27dd83fb05cf7cf9762ef3f0ba6693cb8f8c83f0ba6693cb8f8c8bfb05cf7cf9762ef3fc868ae393bc7e13fa3a10e29669bea3fa3a10e29669beabfc868ae393bc7e13fa3a10e29669bea3fc868ae393bc7e13fc868ae393bc7e1bfa3a10e29669bea3f0ba6693cb8f8c83fb05cf7cf9762ef3fb05cf7cf9762efbf0ba6693cb8f8c83f2625d1a38dd8ef3f2cb429bca617b93f2cb429bca617b9bf2625d1a38dd8ef3fd61d0925f34ce43f4117156b80bce83f4117156b80bce8bfd61d0925f34ce43fb1bd80f1b238ec3f3bf606385d2bde3f3bf606385d2bdebfb1bd80f1b238ec3f069fd52e0694d23fda2dc656419fee3fda2dc656419feebf069fd52e0694d23fda2dc656419fee3f069fd52e0694d23f069fd52e0694d2bfda2dc656419fee3f3bf606385d2bde3fb1bd80f1b238ec3fb1bd80f1b238ecbf3bf606385d2bde3f4117156b80bce83fd61d0925f34ce43fd61d0925f34ce4bf4117156b80bce83f2cb429bca617b93f2625d1a38dd8ef3f2625d1a38dd8efbf2cb429bca617b93f7e6d79e321f6ef3f14d80df1651fa93f14d80df1651fa9bf7e6d79e321f6ef3fa0ec8c34697de53fafaf6a22dfb5e73fafaf6a22dfb5e7bfa0ec8c34697de53f73c73cf47aedec3fc05ce109105ddb3fc05ce109105ddbbf73c73cf47aedec3fdd1fab759a8fd53fe586f6042121ee3fe586f6042121eebfdd1fab759a8fd53fd73092fb7e0aef3f1b5f217bf919cf3f1b5f217bf919cfbfd73092fb7e0aef3feeff22998773e03f3e6e19458372eb3f3e6e19458372ebbfeeff22998773e03f4187f347e0b3e93f3570e1fcf70fe33f3570e1fcf70fe3bf4187f347e0b3e93f3a618e6e10c8c23f17a5087f55a7ef3f17a5087f55a7efbf3a618e6e10c8c23f17a5087f55a7ef3f3a618e6e10c8c23f3a618e6e10c8c2bf17a5087f55a7ef3f3570e1fcf70fe33f4187f347e0b3e93f4187f347e0b3e9bf3570e1fcf70fe33f3e6e19458372eb3feeff22998773e03feeff22998773e0bf3e6e19458372eb3f1b5f217bf919cf3fd73092fb7e0aef3fd73092fb7e0aefbf1b5f217bf919cf3fe586f6042121ee3fdd1fab759a8fd53fdd1fab759a8fd5bfe586f6042121ee3fc05ce109105ddb3f73c73cf47aedec3f73c73cf47aedecbfc05ce109105ddb3fafaf6a22dfb5e73fa0ec8c34697de53fa0ec8c34697de5bfafaf6a22dfb5e73f14d80df1651fa93f7e6d79e321f6ef3f7e6d79e321f6efbf14d80df1651fa93f0dcd846088fdef3f7e66a3f75521993f7e66a3f7552199bf0dcd846088fdef3fdf2c1d55b710e63f96ffef37082de73f96ffef37082de7bfdf2c1d55b710e63f3ac94dd13441ed3f8aeda84379efd93f8aeda84379efd9bf3ac94dd13441ed3f9f45fa308508d73f3cc2ccb613dbed3f3cc2ccb613dbedbf9f45fa308508d73f89e564acf338ef3f634f7e6a820bcc3f634f7e6a820bccbf89e564acf338ef3f234b1b54b31ee13f000215580a09eb3f000215580a09ebbf234b1b54b31ee13f822746a0a729ea3fdf12dd4c056de23fdf12dd4c056de2bf822746a0a729ea3fc63f8b4414e2c53fa94b71fa6487ef3fa94b71fa6487efbfc63f8b4414e2c53fd39fe17064c2ef3f0e73a9564e56bf3f0e73a9564e56bfbfd39fe17064c2ef3fb9502029faafe33ffb639249223ae93ffb639249223ae9bfb9502029faafe33f2a956facc0d7eb3fba9af8dba48bdf3fba9af8dba48bdfbf2a956facc0d7eb3f77f6b162d211d13f634968e740d7ee3f634968e740d7eebf77f6b162d211d13f12e148ec8862ee3f016617945c13d43f016617945c13d4bf12e148ec8862ee3f5ec431996ec6dc3ff51134214b95ec3ff51134214b95ecbf5ec431996ec6dc3f6e97ff0b0e3be83fe9e5e3bbcae6e43fe9e5e3bbcae6e4bf6e97ff0b0e3be83ff619ce9220d5b23f3a8801adcde9ef3f3a8801adcde9efbff619ce9220d5b23f3a8801adcde9ef3ff619ce9220d5b23ff619ce9220d5b2bf3a8801adcde9ef3fe9e5e3bbcae6e43f6e97ff0b0e3be83f6e97ff0b0e3be8bfe9e5e3bbcae6e43ff51134214b95ec3f5ec431996ec6dc3f5ec431996ec6dcbff51134214b95ec3f016617945c13d43f12e148ec8862ee3f12e148ec8862eebf016617945c13d43f634968e740d7ee3f77f6b162d211d13f77f6b162d211d1bf634968e740d7ee3fba9af8dba48bdf3f2a956facc0d7eb3f2a956facc0d7ebbfba9af8dba48bdf3ffb639249223ae93fb9502029faafe33fb9502029faafe3bffb639249223ae93f0e73a9564e56bf3fd39fe17064c2ef3fd39fe17064c2efbf0e73a9564e56bf3fa94b71fa6487ef3fc63f8b4414e2c53fc63f8b4414e2c5bfa94b71fa6487ef3fdf12dd4c056de23f822746a0a729ea3f822746a0a729eabfdf12dd4c056de23f000215580a09eb3f234b1b54b31ee13f234b1b54b31ee1bf000215580a09eb3f634f7e6a820bcc3f89e564acf338ef3f89e564acf338efbf634f7e6a820bcc3f3cc2ccb613dbed3f9f45fa308508d73f9f45fa308508d7bf3cc2ccb613dbed3f8aeda84379efd93f3ac94dd13441ed3f3ac94dd13441edbf8aeda84379efd93f96ffef37082de73fdf2c1d55b710e63fdf2c1d55b710e6bf96ffef37082de73f7e66a3f75521993f0dcd846088fdef3f0dcd846088fdefbf7e66a3f75521993fdb929b1662ffef3f84c7defcd121893f84c7defcd12189bfdb929b1662ffef3f3d78f0251959e63fafa8ea5444e7e63fafa8ea5444e7e6bf3d78f0251959e63f8be6c9736169ed3fd793bc632a37d93fd793bc632a37d9bf8be6c9736169ed3fe7cc1d31a9c3d73f9ba0386252b6ed3f9ba0386252b6edbfe7cc1d31a9c3d73f2d2f0b3b604eef3f5104b025a082ca3f5104b025a082cabf2d2f0b3b604eef3f49dbde634d73e13f11d5219ebcd2ea3f11d5219ebcd2eabf49dbde634d73e13fe2fa021b0963ea3f59eb3399791ae23f59eb3399791ae2bfe2fa021b0963ea3f31bf50ded96dc73f7720a1a39975ef3f7720a1a39975efbf31bf50ded96dc73f7ba66dfd15ceef3fd5c29ec78537bc3fd5c29ec78537bcbf7ba66dfd15ceef3fd4564553d9fee33f0d94efa3ccfbe83f0d94efa3ccfbe8bfd4564553d9fee33f49557226c408ec3fd678ef5219dcde3fd678ef5219dcdebf49557226c408ec3f3edb4c3f44d3d13f740bdfc8d8bbee3f740bdfc8d8bbeebf3edb4c3f44d3d13f0dd14cab7b81ee3f5281e1c21054d33f5281e1c21054d3bf0dd14cab7b81ee3f89e3865b7779dd3f9b7388348b67ec3f9b7388348b67ecbf89e3865b7779dd3fbf2eba0f407ce83f39099b9b449ae43f39099b9b449ae4bfbf2eba0f407ce83f19a49a0ad0f6b53f095bbdfccae1ef3f095bbdfccae1efbf19a49a0ad0f6b53fad718e6595f0ef3fe020f8796e65af3fe020f8796e65afbfad718e6595f0ef3f9655a3928232e53f711757e3ecf8e73f711757e3ecf8e7bf9655a3928232e53f5cfcfcf3f0c1ec3fe71e01d84912dc3fe71e01d84912dcbf5cfcfcf3f0c1ec3f6ae77842e2d1d43f7ec12b4b6a42ee3f7ec12b4b6a42eebf6ae77842e2d1d43fc273e4a378f1ee3faefd370eb84fd03faefd370eb84fd0bfc273e4a378f1ee3fb73e4c87fc1ce03fd2903567aaa5eb3fd2903567aaa5ebbfb73e4c87fc1ce03f42d7c7f47e77e93ff35906b15860e33ff35906b15860e3bf42d7c7f47e77e93f77f5dacef039c13f41d7957179b5ef3f41d7957179b5efbf77f5dacef039c13f9b09c924f997ef3f5a3e29b17655c43f5a3e29b17655c4bf9b09c924f997ef3feaf3fa25dbbee23f94af29ef43efe93f94af29ef43efe9bfeaf3fa25dbbee23f1257f53e4d3eeb3f8f895d4d70c9e03f8f895d4d70c9e0bf1257f53e4d3eeb3f114345e54f93cd3fda3a76f75222ef3fda3a76f75222efbf114345e54f93cd3f2bbe2d62aefeed3fc6273fdd7d4cd63fc6273fdd7d4cd6bf2bbe2d62aefeed3fca3f6d2bc8a6da3fdc353e74e717ed3fdc353e74e717edbfca3f6d2bc8a6da3f6172035fe771e73f8c0165be7bc7e53f8c0165be7bc7e5bf6172035fe771e73fcd55947565d8a23f5df7feef72faef3f5df7feef72faefbfcd55947565d8a23f5df7feef72faef3fcd55947565d8a23fcd55947565d8a2bf5df7feef72faef3f8c0165be7bc7e53f6172035fe771e73f6172035fe771e7bf8c0165be7bc7e53fdc353e74e717ed3fca3f6d2bc8a6da3fca3f6d2bc8a6dabfdc353e74e717ed3fc6273fdd7d4cd63f2bbe2d62aefeed3f2bbe2d62aefeedbfc6273fdd7d4cd63fda3a76f75222ef3f114345e54f93cd3f114345e54f93cdbfda3a76f75222ef3f8f895d4d70c9e03f1257f53e4d3eeb3f1257f53e4d3eebbf8f895d4d70c9e03f94af29ef43efe93feaf3fa25dbbee23feaf3fa25dbbee2bf94af29ef43efe93f5a3e29b17655c43f9b09c924f997ef3f9b09c924f997efbf5a3e29b17655c43f41d7957179b5ef3f77f5dacef039c13f77f5dacef039c1bf41d7957179b5ef3ff35906b15860e33f42d7c7f47e77e93f42d7c7f47e77e9bff35906b15860e33fd2903567aaa5eb3fb73e4c87fc1ce03fb73e4c87fc1ce0bfd2903567aaa5eb3faefd370eb84fd03fc273e4a378f1ee3fc273e4a378f1eebfaefd370eb84fd03f7ec12b4b6a42ee3f6ae77842e2d1d43f6ae77842e2d1d4bf7ec12b4b6a42ee3fe71e01d84912dc3f5cfcfcf3f0c1ec3f5cfcfcf3f0c1ecbfe71e01d84912dc3f711757e3ecf8e73f9655a3928232e53f9655a3928232e5bf711757e3ecf8e73fe020f8796e65af3fad718e6595f0ef3fad718e6595f0efbfe020f8796e65af3f095bbdfccae1ef3f19a49a0ad0f6b53f19a49a0ad0f6b5bf095bbdfccae1ef3f39099b9b449ae43fbf2eba0f407ce83fbf2eba0f407ce8bf39099b9b449ae43f9b7388348b67ec3f89e3865b7779dd3f89e3865b7779ddbf9b7388348b67ec3f5281e1c21054d33f0dd14cab7b81ee3f0dd14cab7b81eebf5281e1c21054d33f740bdfc8d8bbee3f3edb4c3f44d3d13f3edb4c3f44d3d1bf740bdfc8d8bbee3fd678ef5219dcde3f49557226c408ec3f49557226c408ecbfd678ef5219dcde3f0d94efa3ccfbe83fd4564553d9fee33fd4564553d9fee3bf0d94efa3ccfbe83fd5c29ec78537bc3f7ba66dfd15ceef3f7ba66dfd15ceefbfd5c29ec78537bc3f7720a1a39975ef3f31bf50ded96dc73f31bf50ded96dc7bf7720a1a39975ef3f59eb3399791ae23fe2fa021b0963ea3fe2fa021b0963eabf59eb3399791ae23f11d5219ebcd2ea3f49dbde634d73e13f49dbde634d73e1bf11d5219ebcd2ea3f5104b025a082ca3f2d2f0b3b604eef3f2d2f0b3b604eefbf5104b025a082ca3f9ba0386252b6ed3fe7cc1d31a9c3d73fe7cc1d31a9c3d7bf9ba0386252b6ed3fd793bc632a37d93f8be6c9736169ed3f8be6c9736169edbfd793bc632a37d93fafa8ea5444e7e63f3d78f0251959e63f3d78f0251959e6bfafa8ea5444e7e63f84c7defcd121893fdb929b1662ffef3fdb929b1662ffefbf84c7defcd121893f928a8e85d8ffef3f710067fef021793f710067fef02179bf928a8e85d8ffef3f10af9184f77ce63f7582c1730dc4e63f7582c1730dc4e6bf10af9184f77ce63ff9ecb8020b7ded3fb0a4c82ea5dad83fb0a4c82ea5dad8bff9ecb8020b7ded3fc4aa4eb0e320d83f888966a983a3ed3f888966a983a3edbfc4aa4eb0e320d83f849e78b1a258ef3f6643dcf2cbbdc93f6643dcf2cbbdc9bf849e78b1a258ef3fb8b9f2095a9de13fd4c0165932b7ea3fd4c0165932b7eabfb8b9f2095a9de13f9de69f52587fea3f1b86bc8bf0f0e13f1b86bc8bf0f0e1bf9de69f52587fea3fc6649ce86633c83fb7bbf57d3f6cef3fb7bbf57d3f6cefbfc6649ce86633c83f840b221479d3ef3f035c4924b7a7ba3f035c4924b7a7babf840b221479d3ef3fb16b8e17ff25e43fcc98163345dce83fcc98163345dce8bfb16b8e17ff25e43fb071a93fde20ec3f1451f8eae083de3f1451f8eae083debfb071a93fde20ec3f71bbc3abbb33d23f8ea8e7e8b2adee3f8ea8e7e8b2adeebf71bbc3abbb33d23ff2f71d368490ee3f8703ecda22f4d23f8703ecda22f4d2bff2f71d368490ee3f58cc81148fd2dd3f07692b014250ec3f07692b014250ecbf58cc81148fd2dd3faad44d9a7e9ce83f4773981bb573e43f4773981bb573e4bfaad44d9a7e9ce83f215b5d6a5887b73f56f4f19f53ddef3f56f4f19f53ddefbf215b5d6a5887b73f5c578d0f83f3ef3fe3d7c0128d42ac3fe3d7c0128d42acbf5c578d0f83f3ef3f375197381058e53fb23dc36c83d7e73fb23dc36c83d7e7bf375197381058e53ff6328b89d9d7ec3f01bd0423cfb7db3f01bd0423cfb7dbbff6328b89d9d7ec3f243caf80d830d53f25ce70e8ea31ee3f25ce70e8ea31eebf243caf80d830d53fec950b0c22feee3ff9eddf1adcdccf3ff9eddf1adcdccfbfec950b0c22feee3f1a22ae265648e03fe90475d2388ceb3fe90475d2388cebbf1a22ae265648e03f220dd82ecf95e93f578e0c0d4038e33f578e0c0d4038e3bf220dd82ecf95e93fcf7becd41601c23fbbcf468e8eaeef3fbbcf468e8eaeefbfcf7becd41601c23fc8b2ad55ce9fef3f148dcdb0db8ec33f148dcdb0db8ec3bfc8b2ad55ce9fef3f17eae8e380e7e23fd580eaf5b1d1e93fd580eaf5b1d1e9bf17eae8e380e7e23f051492fe8958eb3fe1c51774909ee03fe1c51774909ee0bf051492fe8958eb3f1b1a101eca56ce3f5d20f7538f16ef3f5d20f7538f16efbf1b1a101eca56ce3fac8029ca0c10ee3f93a69e3727eed53f93a69e3727eed5bfac8029ca0c10ee3f09407f6c0d02db3f92bdb2fed402ed3f92bdb2fed402edbf09407f6c0d02db3fe5554f570094e73f50725d2a8da2e53f50725d2a8da2e5bfe5554f570094e73f43cd90d200fca53fdf81dbda71f8ef3fdf81dbda71f8efbf43cd90d200fca53ff8d3f11d25fcef3f01cfd13137699f3f01cfd13137699fbff8d3f11d25fcef3f7470839534ece53f8dd2a88d944fe73f8dd2a88d944fe7bf7470839534ece53f9fefe020b22ced3fe5a1de27414bda3fe5a1de27414bdabf9fefe020b22ced3f177ec77d9daad63fda47def705eded3fda47def705ededbf177ec77d9daad63f9d9a08c9c92def3f86b212b38ccfcc3f86b212b38ccfccbf9d9a08c9c92def3f7e8e2abb26f4e03fb4130047cd23eb3fb4130047cd23ebbf7e8e2abb26f4e03f37f9baea950cea3fa89c62270796e23fa89c62270796e2bf37f9baea950cea3ff2c59785df1bc53fdb41aeffd58fef3fdb41aeffd58fefbff2c59785df1bc53f8641e41716bcef3f1d83ba47a072c03f1d83ba47a072c0bf8641e41716bcef3f22ebdf854188e33fd76d8ee4ef58e93fd76d8ee4ef58e9bf22ebdf854188e33fea8093c4d7beeb3f1012e74bf6e2df3f1012e74bf6e2dfbfea8093c4d7beeb3f90dbdbcfd9b0d03fbc9d5ae282e4ee3fbc9d5ae282e4eebf90dbdbcfd9b0d03ffc9f72049f52ee3f541057a5b872d43f541057a5b872d4bffc9f72049f52ee3f0b0097497f6cdc3f00b9a069c1abec3f00b9a069c1abecbf0b0097497f6cdc3fcc7ab5331b1ae83f9ba0599fc00ce53f9ba0599fc00ce5bfcc7ab5331b1ae83fb309d7340144b13fc473b6ec58edef3fc473b6ec58edefbfb309d7340144b13f40392eaff3e5ef3f962027791166b43f962027791166b4bf40392eaff3e5ef3f0400ec45a1c0e43fcc58e91ac55be83fcc58e91ac55be8bf0400ec45a1c0e43ff33c23528e7eec3f5bdbe9e81620dd3f5bdbe9e81620ddbff33c23528e7eec3fb71404faceb3d33f44976adb2772ee3f44976adb2772eebfb71404faceb3d33f84bfc3d3b2c9ee3f775176d7a072d13f775176d7a072d1bf84bfc3d3b2c9ee3f67d03f960534df3fdd7753e164f0eb3fdd7753e164f0ebbf67d03f960534df3fa29dd46f161be93f4483c53882d7e33f4483c53882d7e3bfa29dd46f161be93fc99faecb0ec7bd3f21b7fe6c64c8ef3f21b7fe6c64c8efbfc99faecb0ec7bd3f6e3de629a67eef3fb24af60413a8c63fb24af60413a8c6bf6e3de629a67eef3f1fac98fbd543e23fc89a11c87846ea3fc89a11c87846eabf1fac98fbd543e23f74143cb404eeea3feb6c33af1549e13feb6c33af1549e1bf74143cb404eeea3f22673def3247cb3fdd92ff85d043ef3fdd92ff85d043efbf22673def3247cb3f600241cbd7c8ed3ff618240f3466d73ff618240f3466d7bf600241cbd7c8ed3fffbd41617193d93fb13ee9526f55ed3fb13ee9526f55edbfffbd41617193d93f7a6d17b3420ae73fe91b1ca30335e63fe91b1ca30335e6bf7a6d17b3420ae73ffd0ee3bb36d9923fa1514bb49cfeef3fa1514bb49cfeefbffd0ee3bb36d9923fa1514bb49cfeef3ffd0ee3bb36d9923ffd0ee3bb36d992bfa1514bb49cfeef3fe91b1ca30335e63f7a6d17b3420ae73f7a6d17b3420ae7bfe91b1ca30335e63fb13ee9526f55ed3fffbd41617193d93fffbd41617193d9bfb13ee9526f55ed3ff618240f3466d73f600241cbd7c8ed3f600241cbd7c8edbff618240f3466d73fdd92ff85d043ef3f22673def3247cb3f22673def3247cbbfdd92ff85d043ef3feb6c33af1549e13f74143cb404eeea3f74143cb404eeeabfeb6c33af1549e13fc89a11c87846ea3f1fac98fbd543e23f1fac98fbd543e2bfc89a11c87846ea3fb24af60413a8c63f6e3de629a67eef3f6e3de629a67eefbfb24af60413a8c63f21b7fe6c64c8ef3fc99faecb0ec7bd3fc99faecb0ec7bdbf21b7fe6c64c8ef3f4483c53882d7e33fa29dd46f161be93fa29dd46f161be9bf4483c53882d7e33fdd7753e164f0eb3f67d03f960534df3f67d03f960534dfbfdd7753e164f0eb3f775176d7a072d13f84bfc3d3b2c9ee3f84bfc3d3b2c9eebf775176d7a072d13f44976adb2772ee3fb71404faceb3d33fb71404faceb3d3bf44976adb2772ee3f5bdbe9e81620dd3ff33c23528e7eec3ff33c23528e7eecbf5bdbe9e81620dd3fcc58e91ac55be83f0400ec45a1c0e43f0400ec45a1c0e4bfcc58e91ac55be83f962027791166b43f40392eaff3e5ef3f40392eaff3e5efbf962027791166b43fc473b6ec58edef3fb309d7340144b13fb309d7340144b1bfc473b6ec58edef3f9ba0599fc00ce53fcc7ab5331b1ae83fcc7ab5331b1ae8bf9ba0599fc00ce53f00b9a069c1abec3f0b0097497f6cdc3f0b0097497f6cdcbf00b9a069c1abec3f541057a5b872d43ffc9f72049f52ee3ffc9f72049f52eebf541057a5b872d43fbc9d5ae282e4ee3f90dbdbcfd9b0d03f90dbdbcfd9b0d0bfbc9d5ae282e4ee3f1012e74bf6e2df3fea8093c4d7beeb3fea8093c4d7beebbf1012e74bf6e2df3fd76d8ee4ef58e93f22ebdf854188e33f22ebdf854188e3bfd76d8ee4ef58e93f1d83ba47a072c03f8641e41716bcef3f8641e41716bcefbf1d83ba47a072c03fdb41aeffd58fef3ff2c59785df1bc53ff2c59785df1bc5bfdb41aeffd58fef3fa89c62270796e23f37f9baea950cea3f37f9baea950ceabfa89c62270796e23fb4130047cd23eb3f7e8e2abb26f4e03f7e8e2abb26f4e0bfb4130047cd23eb3f86b212b38ccfcc3f9d9a08c9c92def3f9d9a08c9c92defbf86b212b38ccfcc3fda47def705eded3f177ec77d9daad63f177ec77d9daad6bfda47def705eded3fe5a1de27414bda3f9fefe020b22ced3f9fefe020b22cedbfe5a1de27414bda3f8dd2a88d944fe73f7470839534ece53f7470839534ece5bf8dd2a88d944fe73f01cfd13137699f3ff8d3f11d25fcef3ff8d3f11d25fcefbf01cfd13137699f3fdf81dbda71f8ef3f43cd90d200fca53f43cd90d200fca5bfdf81dbda71f8ef3f50725d2a8da2e53fe5554f570094e73fe5554f570094e7bf50725d2a8da2e53f92bdb2fed402ed3f09407f6c0d02db3f09407f6c0d02dbbf92bdb2fed402ed3f93a69e3727eed53fac8029ca0c10ee3fac8029ca0c10eebf93a69e3727eed53f5d20f7538f16ef3f1b1a101eca56ce3f1b1a101eca56cebf5d20f7538f16ef3fe1c51774909ee03f051492fe8958eb3f051492fe8958ebbfe1c51774909ee03fd580eaf5b1d1e93f17eae8e380e7e23f17eae8e380e7e2bfd580eaf5b1d1e93f148dcdb0db8ec33fc8b2ad55ce9fef3fc8b2ad55ce9fefbf148dcdb0db8ec33fbbcf468e8eaeef3fcf7becd41601c23fcf7becd41601c2bfbbcf468e8eaeef3f578e0c0d4038e33f220dd82ecf95e93f220dd82ecf95e9bf578e0c0d4038e33fe90475d2388ceb3f1a22ae265648e03f1a22ae265648e0bfe90475d2388ceb3ff9eddf1adcdccf3fec950b0c22feee3fec950b0c22feeebff9eddf1adcdccf3f25ce70e8ea31ee3f243caf80d830d53f243caf80d830d5bf25ce70e8ea31ee3f01bd0423cfb7db3ff6328b89d9d7ec3ff6328b89d9d7ecbf01bd0423cfb7db3fb23dc36c83d7e73f375197381058e53f375197381058e5bfb23dc36c83d7e73fe3d7c0128d42ac3f5c578d0f83f3ef3f5c578d0f83f3efbfe3d7c0128d42ac3f56f4f19f53ddef3f215b5d6a5887b73f215b5d6a5887b7bf56f4f19f53ddef3f4773981bb573e43faad44d9a7e9ce83faad44d9a7e9ce8bf4773981bb573e43f07692b014250ec3f58cc81148fd2dd3f58cc81148fd2ddbf07692b014250ec3f8703ecda22f4d23ff2f71d368490ee3ff2f71d368490eebf8703ecda22f4d23f8ea8e7e8b2adee3f71bbc3abbb33d23f71bbc3abbb33d2bf8ea8e7e8b2adee3f1451f8eae083de3fb071a93fde20ec3fb071a93fde20ecbf1451f8eae083de3fcc98163345dce83fb16b8e17ff25e43fb16b8e17ff25e4bfcc98163345dce83f035c4924b7a7ba3f840b221479d3ef3f840b221479d3efbf035c4924b7a7ba3fb7bbf57d3f6cef3fc6649ce86633c83fc6649ce86633c8bfb7bbf57d3f6cef3f1b86bc8bf0f0e13f9de69f52587fea3f9de69f52587feabf1b86bc8bf0f0e13fd4c0165932b7ea3fb8b9f2095a9de13fb8b9f2095a9de1bfd4c0165932b7ea3f6643dcf2cbbdc93f849e78b1a258ef3f849e78b1a258efbf6643dcf2cbbdc93f888966a983a3ed3fc4aa4eb0e320d83fc4aa4eb0e320d8bf888966a983a3ed3fb0a4c82ea5dad83ff9ecb8020b7ded3ff9ecb8020b7dedbfb0a4c82ea5dad83f7582c1730dc4e63f10af9184f77ce63f10af9184f77ce6bf7582c1730dc4e63f710067fef021793f928a8e85d8ffef3f928a8e85d8ffefbf710067fef021793f021d6221f6ffef3fbaa4ccbef821693fbaa4ccbef82169bf021d6221f6ffef3f719ca1ead18ee63f9ce22fed5cb2e63f9ce22fed5cb2e6bf719ca1ead18ee63f4fa44584c486ed3f44edd5864bacd83f44edd5864bacd8bf4fa44584c486ed3f3f90f3aa6a4fd83f463d8bdd009aed3f463d8bdd009aedbf3f90f3aa6a4fd83f5d6843eda65def3ffa2ab6e9495bc93ffa2ab6e9495bc9bf5d6843eda65def3fbf73131750b2e13f8eb92c7a54a9ea3f8eb92c7a54a9eabfbf73131750b2e13fd25a546e678dea3f7248dc641bdce13f7248dc641bdce1bfd25a546e678dea3f0418c4271796c83fee3c88567567ef3fee3c88567567efbf0418c4271796c83f9e5ca72d0dd6ef3f5ca824ebb6dfb93f5ca824ebb6dfb9bf9e5ca72d0dd6ef3f80432a5b7f39e43f554618756acce83f554618756acce8bf80432a5b7f39e43ff1e33149d12cec3f25d83c6da857de3f25d83c6da857debff1e33149d12cec3fba545599e663d23f0058e69383a6ee3f0058e69383a6eebfba545599e663d23f306b0136ec97ee3f2045954e1ac4d23f2045954e1ac4d2bf306b0136ec97ee3fde41a966fffedd3f04c041318344ec3f04c041318344ecbfde41a966fffedd3f881dde1e87ace83fa2322b695a60e43fa2322b695a60e4bf881dde1e87ace83fa130c112874fb83f8c531475fadaef3f8c531475fadaefbfa130c112874fb83fd3beb154dcf4ef3f17835fbd01b1aa3f17835fbd01b1aabfd3beb154dcf4ef3f9f649751c36ae53f33d3e29cb8c6e73f33d3e29cb8c6e7bf9f649751c36ae53f60a09927b3e2ec3f9356fd14788adb3f9356fd14788adbbf60a09927b3e2ec3fb467f4124060d53f7a1939448f29ee3f7a1939448f29eebfb467f4124060d53f8c73cf145a04ef3f0238bd80747bcf3f0238bd80747bcfbf8c73cf145a04ef3fb7b831ecf35de03fe992e786667feb3fe992e786667febbfb7b831ecf35de03fb2062ba4dfa4e93f1fa649ec2124e33f1fa649ec2124e3bfb2062ba4dfa4e93f0934fd4d9964c23fdcfd0ccbfbaaef3fdcfd0ccbfbaaefbf0934fd4d9964c23f91177aac9ba3ef3fa71645f97b2bc33fa71645f97b2bc3bf91177aac9ba3ef3f1510444bc2fbe23fc275f010d1c2e93fc275f010d1c2e9bf1510444bc2fbe23f47bcfd148f65eb3f8cb032201189e03f8cb032201189e0bf47bcfd148f65eb3f48e32d466bb8ce3f5f8f89bc9010ef3f5f8f89bc9010efbf48e32d466bb8ce3fd966dc2fa018ee3fb6b39d8be7bed53fb6b39d8be7bed5bfd966dc2fa018ee3f7219b31d972fdb3f7b46cee830f8ec3f7b46cee830f8ecbf7219b31d972fdb3fd297bf07f7a4e73fdf23f7d50190e53fdf23f7d50190e5bfd297bf07f7a4e73f864687a5ba8da73f64911bbb53f7ef3f64911bbb53f7efbf864687a5ba8da73f79a6e29ce0fcef3f1d3be54c4f459c3f1d3be54c4f459cbf79a6e29ce0fcef3f106ae5bd7cfee53f4299078e553ee73f4299078e553ee7bf106ae5bd7cfee53fdcfbcb7bfc36ed3fc00ab543651dda3fc00ab543651ddabfdcfbcb7bfc36ed3fb60c8a6398d9d63f818d6d0f16e4ed3f818d6d0f16e4edbfb60c8a6398d9d63ff0ae3a5a6833ef3fdd745d53906dcc3fdd745d53906dccbff0ae3a5a6833ef3f57a9d0487209e13ff5a24c2a7416eb3ff5a24c2a7416ebbf57a9d0487209e13f5ea7c0d2261bea3fba3c4def8b81e23fba3c4def8b81e2bf5ea7c0d2261bea3fdecb5486007fc53f784bcb37a78bef3f784bcb37a78befbfdecb5486007fc53f888d0a0f47bfef3f5bb86fade80ec03f5bb86fade80ec0bf888d0a0f47bfef3f2930d6e3239ce33f6c4aace39049e93f6c4aace39049e9bf2930d6e3239ce33f27230dcb54cbeb3fded2245c57b7df3fded2245c57b7dfbf27230dcb54cbeb3fce49174e5be1d03f5186076aebddee3f5186076aebddeebfce49174e5be1d03fd36704559d5aee3ff03689dc1043d43ff03689dc1043d4bfd36704559d5aee3f895386c37f99dc3f49c4b9198fa0ec3f49c4b9198fa0ecbf895386c37f99dc3fff45f5139c2ae83f86a4cc25ccf9e43f86a4cc25ccf9e4bfff45f5139c2ae83f4d44ed74960cb23f0f4130259debef3f0f4130259debefbf4d44ed74960cb23f602d4885eae7ef3f99a2c5129f9db33f99a2c5129f9db3bf602d4885eae7ef3f7f9f586dbcd3e43ffa83af11714be83ffa83af11714be8bf7f9f586dbcd3e43f139c0287f589ec3f21cde1ae4bf3dc3f21cde1ae4bf3dcbf139c0287f589ec3f71c26ee99be3d33fa7535dc5616aee3fa7535dc5616aeebf71c26ee99be3d33f0990995e83d0ee3f7893c6ef3e42d13f7893c6ef3e42d1bf0990995e83d0ee3fa3cd56e6de5fdf3fc15411611be4eb3fc15411611be4ebbfa3cd56e6de5fdf3f15a8c51fa42ae93f18c58149c4c3e33f18c58149c4c3e3bf15a8c51fa42ae93f3faae4fdb78ebe3ff69a7d3b6ec5ef3ff69a7d3b6ec5efbf3faae4fdb78ebe3f0cc6404a0f83ef3f0d831d831a45c63f0d831d831a45c6bf0cc6404a0f83ef3f1071bb4c7358e23fc63b594a1838ea3fc63b594a1838eabf1071bb4c7358e23fb6579fd88ffbea3f4f25eecfe933e13f4f25eecfe933e1bfb6579fd88ffbea3fad5df13463a9cb3f65bc1bbc6b3eef3f65bc1bbc6b3eefbfad5df13463a9cb3f5a918af3fed1ed3f921026c96337d73f921026c96337d7bf5a918af3fed1ed3ff2f90d447dc1d93f2475181b5b4bed3f2475181b5b4bedbff2f90d447dc1d93fbf410e96ac1be73fff22ec4fe422e63fff22ec4fe422e6bfbf410e96ac1be73f26b2fa214dfd953f77cb70681cfeef3f77cb70681cfeefbf26b2fa214dfd953fd13bc54309ffef3fcb97b96a296a8f3fcb97b96a296a8fbfd13bc54309ffef3f5b537f431547e63f755bc999caf8e63f755bc999caf8e6bf5b537f431547e63f7f8a8872715fed3f8f94abb75565d93f8f94abb75565d9bf7f8a8872715fed3faedf13e6f594d73f9a7595439ebfed3f9a7595439ebfedbfaedf13e6f594d73fb4abbc062249ef3fabb9f3d5f1e4ca3fabb9f3d5f1e4cabfb4abbc062249ef3fbce2dbe4365ee13fefec45f368e0ea3fefec45f368e0eabfbce2dbe4365ee13f23f59010c954ea3fe2132c662d2fe23fe2132c662d2fe2bf23f59010c954ea3fffc4088dfd0ac73f2a321a9c297aef3f2a321a9c297aefbfffc4088dfd0ac73f5443910347cbef3fc17d303b53ffbc3fc17d303b53ffbcbf5443910347cbef3f8006beea33ebe33ffe5e5743790be93ffe5e5743790be9bf8006beea33ebe33f47b1a1259dfceb3ffef7bf061908df3ffef7bf061908dfbf47b1a1259dfceb3f43f2e8fbf7a2d13fb2f61a4bcfc2ee3fb2f61a4bcfc2eebf43f2e8fbf7a2d13f5a16a529db79ee3fabb653e3f583d33fabb653e3f583d3bf5a16a529db79ee3f9d60a82bd04cdd3fd7aa9e891573ec3fd7aa9e891573ecbf9d60a82bd04cdd3f95a19a1d0a6ce83ff122675179ade43ff122675179ade4bf95a19a1d0a6ce83f0a4d4d4a772eb53f86d8e92be9e3ef3f86d8e92be9e3efbf0a4d4d4a772eb53f9161820201efef3f6430464e617bb03f6430464e617bb0bf9161820201efef3fa69ad91ca81fe53ffa526e758b09e83ffa526e758b09e8bfa69ad91ca81fe53f99da000ae2b6ec3f293126476d3fdc3f293126476d3fdcbf99da000ae2b6ec3ff3821bd153a2d43f5ece81ff8d4aee3f5ece81ff8d4aeebff3821bd153a2d43f44a5504c07ebee3f1e66eb054e80d03f1e66eb054e80d0bf44a5504c07ebee3fe1822bc84007e03f0dc4b6a049b2eb3f0dc4b6a049b2ebbfe1822bc84007e03fe17fbd423f68e93f8d7f811b5374e33f8d7f811b5374e3bfe17fbd423f68e93f8667b2bc4dd6c03fb7ad668dd1b8ef3fb7ad668dd1b8efbf8667b2bc4dd6c03f08ac854ff193ef3f88fa797fb1b8c43f88fa797fb1b8c4bf08ac854ff193ef3f58eb7ae876aae23fde4931f1f4fde93fde4931f1f4fde9bf58eb7ae876aae23ff37bf3a51531eb3fb6c44bb8d0dee03fb6c44bb8d0dee0bff37bf3a51531eb3feebd2c4d7731cd3fce0946fc1728ef3fce0946fc1728efbfeebd2c4d7731cd3f9ca59b6ae3f5ed3fcb63ad9c947bd63fcb63ad9c947bd6bf9ca59b6ae3f5ed3f1bf3dbd30c79da3fe1a4e5c65522ed3fe1a4e5c65522edbf1bf3dbd30c79da3f6447302cc560e73f5c343ee7ded9e53f5c343ee7ded9e5bf6447302cc560e73f7fc142db8546a13faefd25e455fbef3faefd25e455fbefbf7fc142db8546a13f14c008427cf9ef3f7961f86f396aa43f7961f86f396aa4bf14c008427cf9ef3f48744f260bb5e53f5bb3901bfb82e73f5bb3901bfb82e7bf48744f260bb5e53fb9d2592f670ded3f09dc5c1273d4da3f09dc5c1273d4dabfb9d2592f670ded3f02c2885c591dd63f540f28d96607ee3f540f28d96607eebf02c2885c591dd63f084728be7a1cef3f9a09013f16f5cd3f9a09013f16f5cdbf084728be7a1cef3fec858f8705b4e03f2579de09744beb3f2579de09744bebbfec858f8705b4e03f7224b4ed82e0e93fb89b4ed333d3e23fb89b4ed333d3e2bf7224b4ed82e0e93f9348db572ff2c33f29defb7ced9bef3f29defb7ced9befbf9348db572ff2c33f4dd581c60db2ef3fe724be40899dc13fe724be40899dc1bf4dd581c60db2ef3fe14dc152524ce33f947545f1ae86e93f947545f1ae86e9bfe14dc152524ce33f5e15d91ffa98eb3f96bded55ae32e03f96bded55ae32e0bf5e15d91ffa98eb3fd2fdb906181fd03fc0a31ce5d6f7ee3fc0a31ce5d6f7eebfd2fdb906181fd03f85ce75ec333aee3f487019dc6301d53f487019dc6301d5bf85ce75ec333aee3fd9c0ff1715e5db3fa0dec220eeccec3fa0dec220eeccecbfd9c0ff1715e5db3f8636b0873fe8e73ffc9d15f54f45e53ffc9d15f54f45e5bf8636b0873fe8e73fc98e80f906d4ad3fed31e11416f2ef3fed31e11416f2efbfc98e80f906d4ad3f0733f72299dfef3f29b1793e1bbfb63f29b1793e1bbfb6bf0733f72299dfef3fff9160300387e43fa11b48e7668ce83fa11b48e7668ce8bfff9160300387e43f5af8fe59ef5bec3fd910fa5c0ca6dd3fd910fa5c0ca6ddbf5af8fe59ef5bec3fafba38b61f24d33f2560ad5b0989ee3f2560ad5b0989eebfafba38b61f24d33f11885b51cfb4ee3fbe27d7838503d23fbe27d7838503d2bf11885b51cfb4ee3f2056f29506b0de3f575e46dcd914ec3f575e46dcd914ecbf2056f29506b0de3f496c489b10ece83f8c103d667212e43f8c103d667212e4bf496c489b10ece83f4cf638eca66fbb3f8760d858d1d0ef3f8760d858d1d0efbf4cf638eca66fbb3fb77e4b43f670ef3f1ccbd2bba7d0c73f1ccbd2bba7d0c7bfb77e4b43f670ef3fd66075a1ba05e23ff5609dde3871ea3ff5609dde3871eabfd66075a1ba05e23fc8fa3ebdffc4ea3fe5463a1f5988e13fe5463a1f5988e1bfc8fa3ebdffc4ea3fda31181b3e20ca3f072daf1f8b53ef3f072daf1f8b53efbfda31181b3e20ca3fb98ae62cf4aced3fe44173d34df2d73fe44173d34df2d7bfb98ae62cf4aced3fd17bef81ef08d93fff0d8c503f73ed3fff0d8c503f73edbfd17bef81ef08d93fcdaf4aefafd5e63f86b3523f0f6be63f86b3523f0f6be6bfcdaf4aefafd5e63f0397500e6bd9823f4f8c972ca7ffef3f4f8c972ca7ffefbf0397500e6bd9823f4f8c972ca7ffef3f0397500e6bd9823f0397500e6bd982bf4f8c972ca7ffef3f86b3523f0f6be63fcdaf4aefafd5e63fcdaf4aefafd5e6bf86b3523f0f6be63fff0d8c503f73ed3fd17bef81ef08d93fd17bef81ef08d9bfff0d8c503f73ed3fe44173d34df2d73fb98ae62cf4aced3fb98ae62cf4acedbfe44173d34df2d73f072daf1f8b53ef3fda31181b3e20ca3fda31181b3e20cabf072daf1f8b53ef3fe5463a1f5988e13fc8fa3ebdffc4ea3fc8fa3ebdffc4eabfe5463a1f5988e13ff5609dde3871ea3fd66075a1ba05e23fd66075a1ba05e2bff5609dde3871ea3f1ccbd2bba7d0c73fb77e4b43f670ef3fb77e4b43f670efbf1ccbd2bba7d0c73f8760d858d1d0ef3f4cf638eca66fbb3f4cf638eca66fbbbf8760d858d1d0ef3f8c103d667212e43f496c489b10ece83f496c489b10ece8bf8c103d667212e43f575e46dcd914ec3f2056f29506b0de3f2056f29506b0debf575e46dcd914ec3fbe27d7838503d23f11885b51cfb4ee3f11885b51cfb4eebfbe27d7838503d23f2560ad5b0989ee3fafba38b61f24d33fafba38b61f24d3bf2560ad5b0989ee3fd910fa5c0ca6dd3f5af8fe59ef5bec3f5af8fe59ef5becbfd910fa5c0ca6dd3fa11b48e7668ce83fff9160300387e43fff9160300387e4bfa11b48e7668ce83f29b1793e1bbfb63f0733f72299dfef3f0733f72299dfefbf29b1793e1bbfb63fed31e11416f2ef3fc98e80f906d4ad3fc98e80f906d4adbfed31e11416f2ef3ffc9d15f54f45e53f8636b0873fe8e73f8636b0873fe8e7bffc9d15f54f45e53fa0dec220eeccec3fd9c0ff1715e5db3fd9c0ff1715e5dbbfa0dec220eeccec3f487019dc6301d53f85ce75ec333aee3f85ce75ec333aeebf487019dc6301d53fc0a31ce5d6f7ee3fd2fdb906181fd03fd2fdb906181fd0bfc0a31ce5d6f7ee3f96bded55ae32e03f5e15d91ffa98eb3f5e15d91ffa98ebbf96bded55ae32e03f947545f1ae86e93fe14dc152524ce33fe14dc152524ce3bf947545f1ae86e93fe724be40899dc13f4dd581c60db2ef3f4dd581c60db2efbfe724be40899dc13f29defb7ced9bef3f9348db572ff2c33f9348db572ff2c3bf29defb7ced9bef3fb89b4ed333d3e23f7224b4ed82e0e93f7224b4ed82e0e9bfb89b4ed333d3e23f2579de09744beb3fec858f8705b4e03fec858f8705b4e0bf2579de09744beb3f9a09013f16f5cd3f084728be7a1cef3f084728be7a1cefbf9a09013f16f5cd3f540f28d96607ee3f02c2885c591dd63f02c2885c591dd6bf540f28d96607ee3f09dc5c1273d4da3fb9d2592f670ded3fb9d2592f670dedbf09dc5c1273d4da3f5bb3901bfb82e73f48744f260bb5e53f48744f260bb5e5bf5bb3901bfb82e73f7961f86f396aa43f14c008427cf9ef3f14c008427cf9efbf7961f86f396aa43faefd25e455fbef3f7fc142db8546a13f7fc142db8546a1bfaefd25e455fbef3f5c343ee7ded9e53f6447302cc560e73f6447302cc560e7bf5c343ee7ded9e53fe1a4e5c65522ed3f1bf3dbd30c79da3f1bf3dbd30c79dabfe1a4e5c65522ed3fcb63ad9c947bd63f9ca59b6ae3f5ed3f9ca59b6ae3f5edbfcb63ad9c947bd63fce0946fc1728ef3feebd2c4d7731cd3feebd2c4d7731cdbfce0946fc1728ef3fb6c44bb8d0dee03ff37bf3a51531eb3ff37bf3a51531ebbfb6c44bb8d0dee03fde4931f1f4fde93f58eb7ae876aae23f58eb7ae876aae2bfde4931f1f4fde93f88fa797fb1b8c43f08ac854ff193ef3f08ac854ff193efbf88fa797fb1b8c43fb7ad668dd1b8ef3f8667b2bc4dd6c03f8667b2bc4dd6c0bfb7ad668dd1b8ef3f8d7f811b5374e33fe17fbd423f68e93fe17fbd423f68e9bf8d7f811b5374e33f0dc4b6a049b2eb3fe1822bc84007e03fe1822bc84007e0bf0dc4b6a049b2eb3f1e66eb054e80d03f44a5504c07ebee3f44a5504c07ebeebf1e66eb054e80d03f5ece81ff8d4aee3ff3821bd153a2d43ff3821bd153a2d4bf5ece81ff8d4aee3f293126476d3fdc3f99da000ae2b6ec3f99da000ae2b6ecbf293126476d3fdc3ffa526e758b09e83fa69ad91ca81fe53fa69ad91ca81fe5bffa526e758b09e83f6430464e617bb03f9161820201efef3f9161820201efefbf6430464e617bb03f86d8e92be9e3ef3f0a4d4d4a772eb53f0a4d4d4a772eb5bf86d8e92be9e3ef3ff122675179ade43f95a19a1d0a6ce83f95a19a1d0a6ce8bff122675179ade43fd7aa9e891573ec3f9d60a82bd04cdd3f9d60a82bd04cddbfd7aa9e891573ec3fabb653e3f583d33f5a16a529db79ee3f5a16a529db79eebfabb653e3f583d33fb2f61a4bcfc2ee3f43f2e8fbf7a2d13f43f2e8fbf7a2d1bfb2f61a4bcfc2ee3ffef7bf061908df3f47b1a1259dfceb3f47b1a1259dfcebbffef7bf061908df3ffe5e5743790be93f8006beea33ebe33f8006beea33ebe3bffe5e5743790be93fc17d303b53ffbc3f5443910347cbef3f5443910347cbefbfc17d303b53ffbc3f2a321a9c297aef3fffc4088dfd0ac73fffc4088dfd0ac7bf2a321a9c297aef3fe2132c662d2fe23f23f59010c954ea3f23f59010c954eabfe2132c662d2fe23fefec45f368e0ea3fbce2dbe4365ee13fbce2dbe4365ee1bfefec45f368e0ea3fabb9f3d5f1e4ca3fb4abbc062249ef3fb4abbc062249efbfabb9f3d5f1e4ca3f9a7595439ebfed3faedf13e6f594d73faedf13e6f594d7bf9a7595439ebfed3f8f94abb75565d93f7f8a8872715fed3f7f8a8872715fedbf8f94abb75565d93f755bc999caf8e63f5b537f431547e63f5b537f431547e6bf755bc999caf8e63fcb97b96a296a8f3fd13bc54309ffef3fd13bc54309ffefbfcb97b96a296a8f3f77cb70681cfeef3f26b2fa214dfd953f26b2fa214dfd95bf77cb70681cfeef3fff22ec4fe422e63fbf410e96ac1be73fbf410e96ac1be7bfff22ec4fe422e63f2475181b5b4bed3ff2f90d447dc1d93ff2f90d447dc1d9bf2475181b5b4bed3f921026c96337d73f5a918af3fed1ed3f5a918af3fed1edbf921026c96337d73f65bc1bbc6b3eef3fad5df13463a9cb3fad5df13463a9cbbf65bc1bbc6b3eef3f4f25eecfe933e13fb6579fd88ffbea3fb6579fd88ffbeabf4f25eecfe933e13fc63b594a1838ea3f1071bb4c7358e23f1071bb4c7358e2bfc63b594a1838ea3f0d831d831a45c63f0cc6404a0f83ef3f0cc6404a0f83efbf0d831d831a45c63ff69a7d3b6ec5ef3f3faae4fdb78ebe3f3faae4fdb78ebebff69a7d3b6ec5ef3f18c58149c4c3e33f15a8c51fa42ae93f15a8c51fa42ae9bf18c58149c4c3e33fc15411611be4eb3fa3cd56e6de5fdf3fa3cd56e6de5fdfbfc15411611be4eb3f7893c6ef3e42d13f0990995e83d0ee3f0990995e83d0eebf7893c6ef3e42d13fa7535dc5616aee3f71c26ee99be3d33f71c26ee99be3d3bfa7535dc5616aee3f21cde1ae4bf3dc3f139c0287f589ec3f139c0287f589ecbf21cde1ae4bf3dc3ffa83af11714be83f7f9f586dbcd3e43f7f9f586dbcd3e4bffa83af11714be83f99a2c5129f9db33f602d4885eae7ef3f602d4885eae7efbf99a2c5129f9db33f0f4130259debef3f4d44ed74960cb23f4d44ed74960cb2bf0f4130259debef3f86a4cc25ccf9e43fff45f5139c2ae83fff45f5139c2ae8bf86a4cc25ccf9e43f49c4b9198fa0ec3f895386c37f99dc3f895386c37f99dcbf49c4b9198fa0ec3ff03689dc1043d43fd36704559d5aee3fd36704559d5aeebff03689dc1043d43f5186076aebddee3fce49174e5be1d03fce49174e5be1d0bf5186076aebddee3fded2245c57b7df3f27230dcb54cbeb3f27230dcb54cbebbfded2245c57b7df3f6c4aace39049e93f2930d6e3239ce33f2930d6e3239ce3bf6c4aace39049e93f5bb86fade80ec03f888d0a0f47bfef3f888d0a0f47bfefbf5bb86fade80ec03f784bcb37a78bef3fdecb5486007fc53fdecb5486007fc5bf784bcb37a78bef3fba3c4def8b81e23f5ea7c0d2261bea3f5ea7c0d2261beabfba3c4def8b81e23ff5a24c2a7416eb3f57a9d0487209e13f57a9d0487209e1bff5a24c2a7416eb3fdd745d53906dcc3ff0ae3a5a6833ef3ff0ae3a5a6833efbfdd745d53906dcc3f818d6d0f16e4ed3fb60c8a6398d9d63fb60c8a6398d9d6bf818d6d0f16e4ed3fc00ab543651dda3fdcfbcb7bfc36ed3fdcfbcb7bfc36edbfc00ab543651dda3f4299078e553ee73f106ae5bd7cfee53f106ae5bd7cfee5bf4299078e553ee73f1d3be54c4f459c3f79a6e29ce0fcef3f79a6e29ce0fcefbf1d3be54c4f459c3f64911bbb53f7ef3f864687a5ba8da73f864687a5ba8da7bf64911bbb53f7ef3fdf23f7d50190e53fd297bf07f7a4e73fd297bf07f7a4e7bfdf23f7d50190e53f7b46cee830f8ec3f7219b31d972fdb3f7219b31d972fdbbf7b46cee830f8ec3fb6b39d8be7bed53fd966dc2fa018ee3fd966dc2fa018eebfb6b39d8be7bed53f5f8f89bc9010ef3f48e32d466bb8ce3f48e32d466bb8cebf5f8f89bc9010ef3f8cb032201189e03f47bcfd148f65eb3f47bcfd148f65ebbf8cb032201189e03fc275f010d1c2e93f1510444bc2fbe23f1510444bc2fbe2bfc275f010d1c2e93fa71645f97b2bc33f91177aac9ba3ef3f91177aac9ba3efbfa71645f97b2bc33fdcfd0ccbfbaaef3f0934fd4d9964c23f0934fd4d9964c2bfdcfd0ccbfbaaef3f1fa649ec2124e33fb2062ba4dfa4e93fb2062ba4dfa4e9bf1fa649ec2124e33fe992e786667feb3fb7b831ecf35de03fb7b831ecf35de0bfe992e786667feb3f0238bd80747bcf3f8c73cf145a04ef3f8c73cf145a04efbf0238bd80747bcf3f7a1939448f29ee3fb467f4124060d53fb467f4124060d5bf7a1939448f29ee3f9356fd14788adb3f60a09927b3e2ec3f60a09927b3e2ecbf9356fd14788adb3f33d3e29cb8c6e73f9f649751c36ae53f9f649751c36ae5bf33d3e29cb8c6e73f17835fbd01b1aa3fd3beb154dcf4ef3fd3beb154dcf4efbf17835fbd01b1aa3f8c531475fadaef3fa130c112874fb83fa130c112874fb8bf8c531475fadaef3fa2322b695a60e43f881dde1e87ace83f881dde1e87ace8bfa2322b695a60e43f04c041318344ec3fde41a966fffedd3fde41a966fffeddbf04c041318344ec3f2045954e1ac4d23f306b0136ec97ee3f306b0136ec97eebf2045954e1ac4d23f0058e69383a6ee3fba545599e663d23fba545599e663d2bf0058e69383a6ee3f25d83c6da857de3ff1e33149d12cec3ff1e33149d12cecbf25d83c6da857de3f554618756acce83f80432a5b7f39e43f80432a5b7f39e4bf554618756acce83f5ca824ebb6dfb93f9e5ca72d0dd6ef3f9e5ca72d0dd6efbf5ca824ebb6dfb93fee3c88567567ef3f0418c4271796c83f0418c4271796c8bfee3c88567567ef3f7248dc641bdce13fd25a546e678dea3fd25a546e678deabf7248dc641bdce13f8eb92c7a54a9ea3fbf73131750b2e13fbf73131750b2e1bf8eb92c7a54a9ea3ffa2ab6e9495bc93f5d6843eda65def3f5d6843eda65defbffa2ab6e9495bc93f463d8bdd009aed3f3f90f3aa6a4fd83f3f90f3aa6a4fd8bf463d8bdd009aed3f44edd5864bacd83f4fa44584c486ed3f4fa44584c486edbf44edd5864bacd83f9ce22fed5cb2e63f719ca1ead18ee63f719ca1ead18ee6bf9ce22fed5cb2e63fbaa4ccbef821693f021d6221f6ffef3f021d6221f6ffefbfbaa4ccbef821693f"));
  const rootBytes = u8f(baswap64If(Float64Array.from(roots)));
  if (bytesToHex(shake256(rootBytes)) !== "f45a496cf56ccc6e3e3395a20209206d81d71a7905a661447bd5bc0e24e0af1e") {
    throw new Error("COMPLEX_ROOTS mismatch");
  }
  return roots;
})();
var intField = {
  mul(x, y) {
    let z = Math.imul(x, y);
    let w = Math.imul(Q2, Math.imul(z, Q0I) & 65535);
    z = (z + w >>> 16) - Q2;
    z += Q2 & z >> 31;
    return z >>> 0;
  },
  inv(y) {
    if (y === 0)
      throw new Error("divison by zero");
    const e00 = this.mul(y, R2);
    const e01 = this.mul(e00, e00);
    const e02 = this.mul(e01, e00);
    const e03 = this.mul(e02, e01);
    const e04 = this.mul(e03, e03);
    const e05 = this.mul(e04, e04);
    const e06 = this.mul(e05, e05);
    const e07 = this.mul(e06, e06);
    const e08 = this.mul(e07, e07);
    const e09 = this.mul(e08, e02);
    const e10 = this.mul(e09, e08);
    const e11 = this.mul(e10, e10);
    const e12 = this.mul(e11, e11);
    const e13 = this.mul(e12, e09);
    const e14 = this.mul(e13, e13);
    const e15 = this.mul(e14, e14);
    const e16 = this.mul(e15, e10);
    const e17 = this.mul(e16, e16);
    const e18 = this.mul(e17, e00);
    return e18;
  },
  div: (x, y) => intField.mul(x, intField.inv(y))
};
function getIntPoly(logn) {
  const n = 1 << logn;
  const newPoly2 = (n2) => new Uint16Array(n2);
  const F2 = Number(invert(BigInt(n), QBig));
  const { mod: mod2, smod, NTT } = genCrystals({
    N: n,
    Q: Q2,
    F: F2,
    ROOT_OF_UNITY: 7,
    newPoly: newPoly2,
    isKyber: false,
    brvBits: 10
  });
  const ntt = (r) => NTT.encode(r);
  const intt = (r) => NTT.decode(r);
  const signedCoder = {
    encode: (p) => Int16Array.from(p, (x) => smod(x)),
    decode: (p) => Uint16Array.from(p, (x) => mod2(x))
  };
  const intPoly = {
    create: newPoly2,
    smallSqnorm(f) {
      let s = 0;
      let ng = 0;
      for (let u = 0; u < n; u++) {
        const z = f[u];
        s = s + z * z >>> 0;
        ng |= s;
      }
      return (s | -(ng >>> 31)) >>> 0;
    },
    isShort(s1, s2) {
      let s = 0 >>> 0;
      let ng = 0 >>> 0;
      for (let u = 0; u < n; u++) {
        let z1 = s1[u] << 16 >> 16;
        s = s + (z1 * z1 >>> 0) >>> 0;
        ng |= s;
        let z2 = s2[u] << 16 >> 16;
        s = s + (z2 * z2 >>> 0) >>> 0;
        ng |= s;
      }
      if (ng & 2147483648)
        s = 4294967295;
      return s <= L2BOUND[logn];
    },
    sub(a, b) {
      for (let i = 0; i < n; i++)
        a[i] = mod2(a[i] - b[i]);
      return a;
    },
    ntt,
    intt,
    toMontgomery(d) {
      for (let i = 0; i < n; i++)
        d[i] = intField.mul(d[i], R2);
      return d;
    },
    mul(f, d) {
      for (let i = 0; i < n; i++)
        f[i] = intField.mul(f[i], d[i]);
      return f;
    },
    div(f, d) {
      for (let i = 0; i < n; i++)
        f[i] = intField.div(f[i], d[i]);
      this.intt(f);
      return f;
    }
  };
  return { newPoly: newPoly2, intPoly, signedCoder };
}
var fComplex = getComplex({
  ZERO: 0,
  ONE: 1,
  add: (x, y) => x + y,
  sub: (x, y) => x - y,
  mul: (x, y) => x * y,
  div: (x, y) => x / y,
  eql: (x, y) => x === y,
  inv: (x) => 1 / x,
  neg: (x) => -x
});
var COMPLEX_ROOTS_O = ComplexArrInterleaved.decode(COMPLEX_ROOTS);
var FFTCoreRoots = {};
var FFTCoreRootsConj = {};
for (let logn = 0; logn < 10; logn++) {
  const out = new Array(1 << logn);
  const outC = new Array(1 << logn);
  for (let i = 0, g1 = 1, g2 = 1; i < logn; i++) {
    const ng = 1 << i;
    for (let k = 0; k < ng; k++)
      out[g1++] = COMPLEX_ROOTS_O[(ng << 1) + k];
    const ng2 = 1 << logn - i;
    for (let k = 0; k < ng2 >> 1; k++)
      outC[out.length - g2++] = fComplex.neg(fComplex.conj(COMPLEX_ROOTS_O[ng2 + k]));
  }
  FFTCoreRoots[logn] = out;
  FFTCoreRootsConj[logn] = outC;
}
function getFloatPoly(logn) {
  const n = 1 << logn;
  const N_COMPLEX = n >> 1;
  const hn = Math.log2(N_COMPLEX);
  const fftOpts = { N: N_COMPLEX, invertButterflies: true, skipStages: 0, brp: false };
  const inv = 1 / N_COMPLEX;
  return {
    to: (f) => ComplexArr.decode(Array.from(f)),
    from: (f) => new Float64Array(ComplexArr.encode(f)),
    // Runtime callers also pass HashToPoint's Uint16Array output here;
    // the implementation only needs a numeric typed-array shape,
    // even though the local type is narrower.
    convSmall: (f) => ComplexArr.decode(Array.from(f)),
    add: (a, b) => a.map((i, j) => fComplex.add(i, b[j])),
    sub: (a, b) => a.map((i, j) => fComplex.sub(i, b[j])),
    neg: (a) => a.map((i) => fComplex.neg(i)),
    mul: (a, b) => a.map((i, j) => fComplex.mul(i, b[j])),
    conj: (a) => a.map((i) => fComplex.conj(i)),
    mulConst: (a, x) => a.map((i) => fComplex.scale(i, x)),
    scaleNorm: (a, b) => a.map((i, j) => fComplex.scale(i, b[j])),
    invNorm: (a, b) => new Float64Array(a.map((i, j) => 1 / fComplex.magSqSum(i, b[j]))),
    FFT: (f) => FFTCore(fComplex, { ...fftOpts, dit: false, roots: FFTCoreRoots[hn] })(f),
    iFFT(f) {
      FFTCore(fComplex, { ...fftOpts, dit: true, roots: FFTCoreRootsConj[hn] })(f);
      for (let i = 0; i < f.length; i++)
        f[i] = fComplex.scale(f[i], inv);
      return f;
    }
  };
}
function ApproxExp(x, ccs) {
  const ev = [
    0.9999999999999949,
    0.5000000000000192,
    0.16666666666698401,
    0.04166666666611049,
    0.008333333327800835,
    0.001388888894063187,
    1984127392773119e-19,
    2480156683358538e-20,
    27555863502191225e-22,
    2756073561604778e-22,
    2529950637944207e-23,
    2073772366009083e-24
  ];
  const y = -x;
  let z = ev[ev.length - 1];
  for (let i = ev.length - 2; i >= 0; i--)
    z = z * y + ev[i];
  return ccs * (1 + z * y);
}
function genFalcon(opts) {
  const { N: N2 } = opts;
  const logn = Math.log2(N2);
  const id2 = (n) => n;
  const { newPoly: newPoly2, intPoly, signedCoder } = getIntPoly(logn);
  const floatPoly = getFloatPoly(logn);
  class NTRU {
    logn;
    shake;
    constructor(logn2, seed) {
      this.logn = logn2;
      this.shake = shake256.create().update(seed);
    }
    gaussSingle() {
      const g = 1 << 10 - this.logn;
      let val = 0;
      for (let i = 0; i < g; i++) {
        const r128 = bytesToNumberLE(this.shake.xof(16));
        const r1 = r128 & 0x7fffffffffffffffn;
        const r2 = r128 >> 64n & 0x7fffffffffffffffn;
        const sign2 = Number(r128 >> 63n & 1n);
        let f = r1 < gauss_1024_12289[0] ? 1 : 0;
        let v = 0;
        for (let k = 1; k < gauss_1024_12289.length; k++) {
          const tBit = r2 >= gauss_1024_12289[k] ? 1 : 0;
          v |= k & -(tBit & (f ^ 1));
          f |= tBit;
        }
        val += sign2 === 1 ? -v : v;
      }
      return val;
    }
    polyGauss() {
      const n = 1 << this.logn;
      let mod2 = 0;
      const f = new Int8Array(n);
      for (let u = 0; u < n; u++) {
        let s;
        while (true) {
          s = this.gaussSingle();
          if (s < -127 || s > 127)
            continue;
          if (u === n - 1) {
            if ((mod2 ^ s & 1) === 0)
              continue;
          }
          break;
        }
        if (u < n - 1)
          mod2 ^= s & 1;
        f[u] = s;
      }
      return f;
    }
    galoisNorm(logn2, a) {
      const n = 1 << logn2;
      const d = new Array(n >> 1);
      for (let k = 0; k < n; k += 2) {
        let s = 0n;
        for (let i = 0; i <= k; i += 2)
          s += a[i] * a[k - i];
        for (let i = k + 2; i < n; i += 2)
          s -= a[i] * a[k + n - i];
        d[k >>> 1] = s;
      }
      for (let k = 0; k < n; k += 2) {
        let s = 0n;
        for (let i = 1; i < k; i += 2)
          s += a[i] * a[k - i];
        for (let i = k + 1; i < n; i += 2)
          s -= a[i] * a[k + n - i];
        d[k >>> 1] -= s;
      }
      return d;
    }
    mulConjD(logn2, d, a, b) {
      const n = 1 << logn2;
      for (let k = 0; k < n; k++) {
        let s = 0n;
        for (let i = 0; i <= k; i += 2)
          s += b[i >>> 1] * a[k - i];
        for (let i = k + 2 - (k & 1); i < n; i += 2)
          s -= b[i >>> 1] * a[k + n - i];
        if ((k & 1) === 0)
          d[k] = s;
        else
          d[k] = -s;
      }
      return d;
    }
    subMul(logn2, a, b, c, e) {
      const n = 1 << logn2;
      for (let k = 0; k < n; k++) {
        let s = 0n;
        for (let i = 0; i <= k; i++)
          s += b[i] * c[k - i];
        for (let i = k + 1; i < n; i++)
          s -= b[i] * c[k + n - i];
        a[k] -= s << e;
      }
      return a;
    }
    reduce(logn2, f, g, F2, G, logn_top) {
      const n = 1 << logn2;
      const depth = logn_top - logn2;
      const floatPoly2 = getFloatPoly(logn2);
      const slen = MAX_BL_SMALL[depth];
      const llen = MAX_BL_LARGE[depth];
      let maxFGBits = BigInt(31 * llen);
      let FGlen = BigInt(llen);
      const scalefg = BigInt(31 * (slen - 10));
      const fgMaxBits = BITLENGTH[depth].avg + 6 * BITLENGTH[depth].std;
      const fgMinBits = BITLENGTH[depth].avg - 6 * BITLENGTH[depth].std;
      let scaleK = BigInt(Math.round(31 * llen - fgMinBits));
      let fx = new Float64Array(n);
      let gx = new Float64Array(n);
      for (let i = 0; i < n; i++) {
        fx[i] = Number(f[i] >> scalefg);
        gx[i] = Number(g[i] >> scalefg);
      }
      const rt3 = floatPoly2.conj(floatPoly2.FFT(floatPoly2.to(fx)));
      const rt4 = floatPoly2.conj(floatPoly2.FFT(floatPoly2.to(gx)));
      const rt5 = floatPoly2.invNorm(rt3, rt4);
      const Fx = new Float64Array(n);
      const Gx = new Float64Array(n);
      const k = new Array(n);
      while (true) {
        let scaleFG = 31n * (FGlen - 10n);
        for (let i = 0; i < n; i++) {
          Fx[i] = Number(F2[i] >> scaleFG);
          Gx[i] = Number(G[i] >> scaleFG);
        }
        const rt2 = floatPoly2.mul(floatPoly2.FFT(floatPoly2.to(Gx)), rt4);
        const rt1 = floatPoly2.mul(floatPoly2.FFT(floatPoly2.to(Fx)), rt3);
        const rt2f = floatPoly2.from(floatPoly2.iFFT(floatPoly2.scaleNorm(floatPoly2.add(rt2, rt1), rt5)));
        const pdc = 2 ** Number(scaleFG - scalefg - scaleK);
        for (let i = 0; i < n; i++) {
          const BOUND = 2147483647;
          const val = rt2f[i] * pdc;
          if (val <= -BOUND || val >= BOUND)
            return false;
          k[i] = BigInt(Math.round(val));
        }
        F2 = this.subMul(logn2, F2, f, k, scaleK);
        G = this.subMul(logn2, G, g, k, scaleK);
        const maxfgNew = scaleK + BigInt(Math.round(fgMaxBits)) + 10n;
        if (maxfgNew < maxFGBits)
          maxFGBits = maxfgNew;
        if (FGlen > 1n && FGlen * 31n >= maxFGBits + 31n)
          FGlen--;
        if (scaleK <= 0n)
          break;
        scaleK -= 25n;
        if (scaleK < 0n)
          scaleK = 0n;
      }
      return true;
    }
    // This is recursive thing that goes from logn to 0
    solveBranch(logn2, f, g, F2, G, logn_top) {
      if (logn2 === 0) {
        const xf = f[0];
        const xg = g[0];
        if (xf <= 0n || xg <= 0n)
          return false;
        try {
          const u1 = invert(xf, xg);
          const v1 = (1n - u1 * xf) / xg;
          F2[0] = -v1 * QBig;
          G[0] = u1 * QBig;
          return true;
        } catch (e) {
          return false;
        }
      }
      if (logn_top === void 0)
        logn_top = logn2;
      const n = 1 << logn2;
      const hn = n >>> 1;
      if (!f || f.length < n || !g || g.length < n)
        return false;
      const fp = this.galoisNorm(logn2, f);
      const gp = this.galoisNorm(logn2, g);
      const Fp = new Array(hn);
      const Gp = new Array(hn);
      if (!this.solveBranch(logn2 - 1, fp, gp, Fp, Gp, logn_top))
        return false;
      F2 = this.mulConjD(logn2, F2, g, Fp);
      G = this.mulConjD(logn2, G, f, Gp);
      return this.reduce(logn2, f, g, F2, G, logn_top);
    }
    solve(f, g) {
      const n = 1 << logn;
      const bf = Array.from(f).map(BigInt);
      const bg = Array.from(g).map(BigInt);
      const bF = new Array(n);
      const bG = new Array(n);
      if (!this.solveBranch(logn, bf, bg, bF, bG))
        return false;
      const F2 = new Int8Array(n);
      const G = new Int8Array(n);
      for (let i = 0; i < n; i++) {
        const x = bF[i];
        const y = bG[i];
        if (x < -127 || x > 127 || y < -127 || y > 127)
          return false;
        F2[i] = Number(x);
        G[i] = Number(y);
      }
      return [F2, G];
    }
    generate() {
      let max = 1e6;
      let curr = 0;
      while (true) {
        if (curr++ === max)
          throw new Error("can't generate key");
        const f = this.polyGauss();
        const g = this.polyGauss();
        let lim = 1 << opts.fgBits - 1;
        for (let u = 0; u < N2; u++) {
          if (f[u] >= lim || f[u] <= -lim || g[u] >= lim || g[u] <= -lim) {
            lim = -1;
            break;
          }
        }
        if (lim < 0)
          continue;
        const normf = intPoly.smallSqnorm(f);
        const normg = intPoly.smallSqnorm(g);
        const norm = normf + normg | -((normf | normg) >>> 31);
        if (norm >= 16823)
          continue;
        let rt1 = floatPoly.FFT(floatPoly.convSmall(f));
        let rt2 = floatPoly.FFT(floatPoly.convSmall(g));
        const rt3 = floatPoly.invNorm(rt1, rt2);
        rt1 = floatPoly.iFFT(floatPoly.scaleNorm(floatPoly.mulConst(floatPoly.conj(rt1), Q2), rt3));
        rt2 = floatPoly.iFFT(floatPoly.scaleNorm(floatPoly.mulConst(floatPoly.conj(rt2), Q2), rt3));
        let bnorm = 0;
        for (let u = 0; u < rt1.length; u++) {
          bnorm += rt1[u].re * rt1[u].re;
          bnorm += rt2[u].re * rt2[u].re;
        }
        for (let u = 0; u < rt1.length; u++) {
          bnorm += rt1[u].im * rt1[u].im;
          bnorm += rt2[u].im * rt2[u].im;
        }
        if (!(bnorm < BNORM_MAX))
          continue;
        let pub;
        try {
          pub = computePublic(f, g);
        } catch (_) {
          continue;
        }
        const solved = this.solve(f, g);
        if (solved === false)
          continue;
        return [f, g, solved[0], solved[1], pub];
      }
    }
  }
  const modqCoder = () => {
    const coder = bitsCoderMSB(newPoly2, N2, 14, {
      encode: id2,
      decode: id2
    });
    return {
      bytesLen: coder.bytesLen,
      encode(poly) {
        for (let i = 0; i < poly.length; i++)
          if (poly[i] >= 12289)
            throw new Error("public key coeff out of range");
        return coder.encode(poly);
      },
      decode(bytes) {
        if (bytes.length !== coder.bytesLen)
          throw new Error("wrong public key length");
        const poly = coder.decode(bytes);
        for (let i = 0; i < poly.length; i++)
          if (poly[i] >= 12289)
            throw new Error("public key coeff out of range");
        const normalized = coder.encode(poly);
        if (normalized.length !== bytes.length)
          throw new Error("wrong public key length");
        for (let i = 0; i < bytes.length; i++)
          if (bytes[i] !== normalized[i])
            throw new Error("wrong public key encoding");
        return poly;
      }
    };
  };
  const trimI8Coder = (bits) => {
    const shift = 32 - bits;
    const coder = bitsCoderMSB((len) => new Int8Array(len), N2, bits, {
      encode: (v) => v & (1 << bits) - 1,
      decode: (w) => (w & getMask(bits)) << shift >> shift
    });
    return {
      bytesLen: coder.bytesLen,
      encode(poly) {
        const max = (1 << bits - 1) - 1;
        const min = -max;
        for (let i = 0; i < poly.length; i++)
          if (poly[i] < min || poly[i] > max)
            throw new Error("private key coeff out of range");
        return coder.encode(poly);
      },
      decode(bytes) {
        const poly = coder.decode(bytes);
        const min = -(1 << bits - 1);
        for (let i = 0; i < poly.length; i++)
          if (poly[i] === min)
            throw new Error("forbidden private key coeff");
        return poly;
      }
    };
  };
  const fgCoder = trimI8Coder(opts.fgBits);
  const FGCoder = trimI8Coder(opts.FGBits);
  const secretKeyCoder = headerCoder(80 + logn, splitCoder("falcon.secretKey", fgCoder, fgCoder, FGCoder));
  const publicKeyCoder = headerCoder(0 + logn, modqCoder());
  const decodePaddedSig = (s2) => {
    const normalized = compCoder(N2).encode(compCoder(N2).decode(s2));
    for (let i = normalized.length; i < s2.length; i++)
      if (s2[i] !== 0)
        throw new Error("non-zero padding");
    return normalized;
  };
  const decodeUnpaddedSig = (s2) => {
    const normalized = compCoder(N2).encode(compCoder(N2).decode(s2));
    if (normalized.length !== s2.length)
      throw new Error("wrong signature length");
    return s2;
  };
  const decodeSig = opts.padded ? decodePaddedSig : decodeUnpaddedSig;
  const SignatureCoderBasic = (logn2) => {
    const TYPE_BYTE = 32 + logn2;
    return {
      encode({ msg, nonce, s2 }) {
        let compressed = s2;
        const payloadLen = 1 + compressed.length;
        const totalLen = 2 + NONCELEN + msg.length + payloadLen;
        const out = new Uint8Array(totalLen);
        let i = 0;
        out[i++] = payloadLen >> 8 & 255;
        out[i++] = payloadLen & 255;
        out.set(nonce, i);
        i += NONCELEN;
        out.set(msg, i);
        i += msg.length;
        out[i++] = TYPE_BYTE;
        out.set(compressed, i);
        return out;
      },
      decode(data) {
        if (!data || data.length < NONCELEN + 3)
          throw new Error("signature coder: wrong length");
        const len = data[0] << 8 | data[1];
        const s2Len = len - 1;
        const msgLen = data.length - NONCELEN - 3 - s2Len;
        if (msgLen < 0)
          throw new Error("signature coder: wrong msg length");
        const typeByte = data[2 + NONCELEN + msgLen];
        if (typeByte !== TYPE_BYTE)
          throw new Error("signature coder: wrong type byte");
        const nonce = data.subarray(2, 2 + NONCELEN);
        const msg = data.subarray(2 + NONCELEN, 2 + NONCELEN + msgLen);
        const s2 = decodeUnpaddedSig(data.subarray(2 + NONCELEN + msgLen + 1));
        if (s2.length !== s2Len)
          throw new Error("signature coder: wrong s2 length");
        return { msg, nonce, s2 };
      }
    };
  };
  const SignatureCoderPadded = (logn2) => {
    const sigLen = opts.paddedLen;
    return {
      encode({ msg, nonce, s2 }) {
        return headerCoder(48 + logn2, splitCoder("falcon.signature", NONCELEN, sigLen, msg.length)).encode([nonce, pad(sigLen).encode(s2), msg]);
      },
      decode(data) {
        const msgLen = data.length - NONCELEN - sigLen - 1;
        const [nonce, s2, msg] = headerCoder(48 + logn2, splitCoder("falcon.signature", NONCELEN, sigLen, msgLen)).decode(data);
        return { nonce, s2: decodeSig(s2), msg };
      }
    };
  };
  const SignatureCoderDetached = (logn2) => {
    const sigLen = opts.padded ? opts.sigLen - 1 - NONCELEN : opts.detachedLen;
    const getSigLen = (s2) => opts.padded ? sigLen : s2.length;
    return {
      encode({ nonce, s2 }) {
        return headerCoder(48 + logn2, splitCoder("falcon.detachedSignature", NONCELEN, getSigLen(s2))).encode([nonce, opts.padded ? pad(sigLen).encode(s2) : s2]);
      },
      decode(data) {
        const [nonce, raw] = headerCoder(48 + logn2, splitCoder("falcon.detachedSignature", NONCELEN, data.length - NONCELEN - 1)).decode(data);
        const s2 = decodeSig(raw);
        return { nonce, s2 };
      }
    };
  };
  const SignatureCoder = (opts.padded ? SignatureCoderPadded : SignatureCoderBasic)(logn);
  const invertF = (f) => {
    const tt = intPoly.ntt(signedCoder.decode(f));
    for (let u = 0; u < N2; u++)
      if (tt[u] === 0)
        throw new Error("invalid secretKey: non-invertible f");
    return tt;
  };
  function computePublic(f, g) {
    const tt = invertF(f);
    const h = intPoly.ntt(signedCoder.decode(g));
    const res2 = intPoly.div(h, tt);
    cleanBytes(tt);
    return res2;
  }
  function completePrivate(f, g, F2) {
    let t1 = intPoly.toMontgomery(intPoly.ntt(signedCoder.decode(g)));
    const t2 = intPoly.ntt(signedCoder.decode(F2));
    const tt = invertF(f);
    t1 = intPoly.div(intPoly.mul(t1, t2), tt);
    const G = new Int8Array(N2);
    for (let u = 0; u < N2; u++) {
      let w = t1[u];
      w -= Q2 & ~-(w - Qhalf >>> 31);
      const gi = w | 0;
      if (gi < -127 || gi > 127) {
        cleanBytes(t1, t2, tt, G);
        throw new Error("Coefficient out of bounds");
      }
      G[u] = gi;
    }
    cleanBytes(t1, t2, tt);
    return G;
  }
  function HashToPoint(nonce, msg) {
    const h = shake256.create().update(nonce).update(msg);
    const c = new Uint16Array(N2);
    const kQ = 5 * Q2;
    for (let i = 0; i < N2; ) {
      const tmp = h.xof(2);
      let w = tmp[0] << 8 | tmp[1];
      if (w < kQ)
        c[i++] = w % Q2;
    }
    return c;
  }
  class FFSampler {
    logn;
    // Shake
    shake;
    shakeBuf;
    ctrView;
    // ChaCha
    ctr = 0n;
    buf;
    buf32;
    pos;
    key;
    nonce32;
    curBlock;
    curBlock32;
    view;
    // Sampler
    b01;
    b11;
    g00;
    g01;
    g11;
    constructor(logn2, seed, b00, b01, b10, b11) {
      this.logn = logn2;
      this.shake = shake256.create().update(seed);
      this.shakeBuf = new Uint8Array(56);
      this.key = this.shakeBuf.subarray(0, 32);
      this.nonce32 = u32(this.shakeBuf.subarray(32, 48));
      this.ctrView = createView(this.shakeBuf.subarray(48, 56));
      this.curBlock = new Uint8Array(64);
      this.curBlock32 = u32(this.curBlock);
      this.buf = new Uint8Array(8 * this.curBlock.length);
      this.buf32 = u32(this.buf);
      this.pos = this.buf.length;
      this.view = createView(this.buf);
      this.b01 = b01;
      this.b11 = b11;
      const { g00, g01, g11 } = this.gramFFT(b00, b10);
      this.g00 = g00;
      this.g01 = g01;
      this.g11 = g11;
    }
    destroy() {
      this.shake.destroy();
      cleanBytes(this.shakeBuf, this.curBlock, this.buf);
      cleanCPoly(this.b01, this.b11, this.g00, this.g01, this.g11);
    }
    refill(minBytes) {
      if (this.buf.length - this.pos >= minBytes)
        return;
      const out32 = swap32IfBE(this.buf32);
      for (let i = 0; i < 8; i++, this.ctr++) {
        const n = swap32IfBE(this.nonce32.slice());
        n[2] ^= Number(this.ctr & 0xffffffffn);
        n[3] ^= Number(this.ctr >> 32n);
        swap32IfBE(n.subarray(1));
        chacha20(this.key, u8(n.subarray(1)), EMPTY_CHACHA20_BLOCK, this.curBlock, n[0]);
        const block32 = swap32IfBE(this.curBlock32);
        for (let j = 0; j < 16; j++)
          out32[i + j * 8] = block32[j];
        swap32IfBE(block32);
      }
      swap32IfBE(out32);
      this.pos = 0;
    }
    // Sampler
    gaussian0() {
      this.refill(9);
      const t0 = this.view.getUint32(this.pos, true);
      const t1 = this.view.getUint32(this.pos + 4, true);
      const t2 = this.buf[this.pos + 8];
      this.pos += 9;
      const v0 = t0 & 16777215;
      const v1 = t0 >>> 24 & 255 | (t1 & 65535) << 8;
      const v2 = t1 >>> 16 & 65535 | t2 << 16;
      let z = 0;
      for (let i = 0; i < GAUSS0.length; i += 3) {
        let cc = v0 - GAUSS0[i + 2] >>> 31;
        cc = (v1 - GAUSS0[i + 1] | 0) - cc >>> 31;
        cc = (v2 - GAUSS0[i + 0] | 0) - cc >>> 31;
        z += cc;
      }
      return z;
    }
    berExp(x, ccs) {
      let s = Math.trunc(x * 1.4426950408889634);
      const r = x - s * 0.6931471805599453;
      let e = ApproxExp(r, ccs);
      e *= 2147483648;
      let z1 = e | 0;
      e = (e - z1) * 4294967296;
      let z0 = e | 0;
      z1 = z1 << 1 | z0 >>> 31;
      z0 <<= 1;
      s = (s | 63 - s >>> 26) & 63;
      const sm = -(s >>> 5) | 0;
      z0 ^= sm & (z0 ^ z1);
      z1 &= ~sm;
      s &= 31;
      z0 = z0 >>> s | z1 << 31 - s << 1;
      z1 >>>= s;
      for (let j = 0; j < 2; j++) {
        for (let i = 24; i >= 0; i -= 8) {
          this.refill(1);
          const w = this.buf[this.pos++];
          const bz = z1 >>> i & 255;
          if (w !== bz)
            return w < bz;
        }
        z1 = z0;
      }
      return false;
    }
    samplerZ(mu, isigma) {
      const s = Math.floor(mu);
      const r = mu - s;
      const dss = isigma * isigma * 0.5;
      const ccs = isigma * SIGMA_MIN[this.logn];
      for (; ; ) {
        const z0 = this.gaussian0();
        this.refill(1);
        const b = this.buf[this.pos++] & 1;
        const z = ((z0 << 1) + 1 & -b) - z0;
        let x = z - r;
        x = x * x * dss - z0 * z0 * 0.15086504887537272;
        if (this.berExp(x, ccs))
          return s + z;
      }
    }
    ldlFFT(logn2, g00t, g01t, g11t) {
      g00t = g00t.slice();
      const hn = 1 << logn2 - 1;
      for (let i = 0; i < hn; i++) {
        const g01 = g01t[i];
        const g11 = g11t[i];
        const mu = fComplex.scale(g01, 1 / g00t[i].re);
        g11t[i] = { re: g11.re - (mu.re * g01.re + mu.im * g01.im), im: g11.im };
        g01t[i] = fComplex.conj(mu);
      }
      return { g00: g00t, g01: g01t, g11: g11t };
    }
    splitFFT(logn2, f) {
      const hn = 1 << logn2 - 1;
      const qn = hn >> 1;
      if (logn2 === 1)
        return { f0: [{ re: f[0].re, im: 0 }], f1: [{ re: f[0].im, im: 0 }] };
      const f0t = new Array(qn);
      const f1t = new Array(qn);
      const ft = f;
      for (let i = 0; i < qn; i++) {
        const a = ft[(i << 1) + 0];
        const b = ft[(i << 1) + 1];
        f0t[i] = fComplex.scale(fComplex.add(a, b), 0.5);
        f1t[i] = fComplex.scale(fComplex.mul(fComplex.sub(a, b), fComplex.conj(COMPLEX_ROOTS_O[i + hn])), 0.5);
      }
      return { f0: f0t, f1: f1t };
    }
    splitSelfAdjFFT(logn2, f) {
      const hn = 1 << logn2 - 1;
      const qn = hn >> 1;
      if (logn2 === 1)
        return { f0: [{ re: f[0].re, im: 0 }], f1: [{ re: 0, im: 0 }] };
      const f0t = new Array(qn);
      const f1t = new Array(qn);
      const ft = f;
      for (let i = 0; i < qn; i++) {
        const a = ft[(i << 1) + 0];
        const b = ft[(i << 1) + 1];
        f0t[i] = fComplex.scale(fComplex.add(a, b), 0.5);
        f1t[i] = fComplex.scale(fComplex.scale(fComplex.conj(COMPLEX_ROOTS_O[i + hn]), fComplex.sub(a, b).re), 0.5);
      }
      return { f0: f0t, f1: f1t };
    }
    mergeFFT(logn2, f0, f1) {
      const hn = 1 << logn2 - 1;
      const qn = hn >> 1;
      if (logn2 === 1)
        return [{ re: f0[0].re, im: f1[0].re }];
      const ft = new Array(2 * qn);
      for (let i = 0; i < qn; i++) {
        const a = f0[i];
        const c = fComplex.mul(f1[i], COMPLEX_ROOTS_O[i + hn]);
        ft[(i << 1) + 0] = fComplex.add(a, c);
        ft[(i << 1) + 1] = fComplex.sub(a, c);
      }
      return ft;
    }
    gramFFT(b00, b10) {
      const { b01, b11 } = this;
      const hn = 1 << this.logn >> 1;
      const g00 = new Array(hn);
      const g01 = new Array(hn);
      const g11 = new Array(hn);
      for (let i = 0; i < hn; i++) {
        const b00t = b00[i];
        const b01t = b01[i];
        const b10t = b10[i];
        const b11t = b11[i];
        const u = fComplex.mul(b00t, fComplex.conj(b10t));
        const v = fComplex.mul(b01t, fComplex.conj(b11t));
        g00[i] = { re: fComplex.magSqSum(b00t, b01t), im: 0 };
        g01[i] = fComplex.add(u, v);
        g11[i] = { re: fComplex.magSqSum(b10t, b11t), im: 0 };
      }
      return { g00, g01, g11 };
    }
    ffsampRec(logn2, t0, t1, g00i, g01i, g11i) {
      if (logn2 === 0) {
        const leaf = Math.sqrt(g00i[0].re) * INV_SIGMA[this.logn];
        const t0re = this.samplerZ(t0[0].re, leaf);
        const t1re = this.samplerZ(t1[0].re, leaf);
        return { t0: [{ re: t0re, im: 0 }], t1: [{ re: t1re, im: 0 }] };
      }
      const { g00, g01, g11 } = this.ldlFFT(logn2, g00i, g01i, g11i);
      const { f0: g00f0, f1: g00f1 } = this.splitSelfAdjFFT(logn2, g00);
      const { f0: g11f0, f1: g11f1 } = this.splitSelfAdjFFT(logn2, g11);
      const { f0: t1f0in, f1: t1f1in } = this.splitFFT(logn2, t1);
      const { t0: t1f0out, t1: t1f1out } = this.ffsampRec(logn2 - 1, t1f0in, t1f1in, g11f0, g11f1, g11f0);
      const t1new = this.mergeFFT(logn2, t1f0out, t1f1out);
      const t0tmp = floatPoly.add(t0, floatPoly.mul(g01, floatPoly.sub(t1, t1new)));
      const { f0: t0f0in, f1: t0f1in } = this.splitFFT(logn2, t0tmp);
      const { t0: t0f0out, t1: t0f1out } = this.ffsampRec(logn2 - 1, t0f0in, t0f1in, g00f0, g00f1, g00f0);
      const z1 = this.mergeFFT(logn2, t0f0out, t0f1out);
      return { t0: z1, t1: t1new };
    }
    // sampling a preimage in FFT domain
    sample(hm) {
      const t0t = floatPoly.FFT(floatPoly.convSmall(hm));
      const t0f = floatPoly.mulConst(floatPoly.mul(t0t, this.b11), F_INV_Q);
      const t1f = floatPoly.mulConst(floatPoly.mul(t0t, this.b01), F_MINUS_INV_Q);
      this.shake.xofInto(this.shakeBuf);
      this.ctr = this.ctrView.getBigUint64(0, true);
      return this.ffsampRec(this.logn, t0f, t1f, this.g00, this.g01, this.g11);
    }
  }
  const signRaw = (sk, msg, maxLen, rnd = randomBytes) => {
    abytes(msg);
    const nonce = rnd(40);
    abytes(nonce, 40, "nonce");
    const hm = HashToPoint(nonce, msg);
    const seed = rnd(48);
    abytes(seed, 48, "seed");
    try {
      const [f, g, F2] = secretKeyCoder.decode(sk);
      try {
        const G = completePrivate(f, g, F2);
        const b00 = floatPoly.FFT(floatPoly.convSmall(g));
        const b01 = floatPoly.FFT(floatPoly.neg(floatPoly.convSmall(f)));
        const b10 = floatPoly.FFT(floatPoly.convSmall(G));
        const b11 = floatPoly.FFT(floatPoly.neg(floatPoly.convSmall(F2)));
        const sampler = new FFSampler(logn, seed, b00, b01, b10, b11);
        const s2 = new Int16Array(N2);
        try {
          while (true) {
            const { t0, t1 } = sampler.sample(hm);
            const t2 = floatPoly.add(floatPoly.mul(t0, b00), floatPoly.mul(t1, b10));
            const t3 = floatPoly.mul(t0, b01);
            const t4 = floatPoly.iFFT(t2);
            const t5 = floatPoly.iFFT(floatPoly.add(floatPoly.mul(t1, b11), t3));
            const hn = N2 >> 1;
            let sqn = 0;
            for (let i = 0; i < hn; i++) {
              sqn += (hm[i] - (Math.round(t4[i].re) | 0)) ** 2;
              sqn += (hm[hn + i] - (Math.round(t4[i].im) | 0)) ** 2;
              const z = -Math.round(t5[i].re);
              sqn += z * z;
              s2[i] = z & 65535;
              const z2 = -Math.round(t5[i].im);
              sqn += z2 * z2;
              s2[i + hn] = z2 & 65535;
            }
            cleanCPoly(t0, t1, t2, t3, t4, t5);
            if (!(sqn <= L2BOUND[logn]))
              continue;
            const s2comp = compCoder(N2).encode(s2);
            if (s2comp.length > maxLen) {
              cleanBytes(s2comp);
              continue;
            }
            return { s2: s2comp, nonce, msg };
          }
        } finally {
          cleanBytes(s2);
          sampler.destroy();
          cleanCPoly(b00, b01, b10, b11);
          cleanBytes(G);
        }
      } finally {
        cleanBytes(f, g, F2);
      }
    } finally {
      cleanBytes(seed);
    }
  };
  const verifyRaw = (pk, s2comp, nonce, msg) => {
    const s2 = compCoder(N2).decode(s2comp);
    const c0 = HashToPoint(nonce, msg);
    const h = intPoly.toMontgomery(intPoly.ntt(publicKeyCoder.decode(pk)));
    const s1 = intPoly.intt(intPoly.mul(intPoly.ntt(signedCoder.decode(s2)), h));
    intPoly.sub(s1, c0);
    return intPoly.isShort(signedCoder.encode(s1), s2);
  };
  const info = Object.freeze({ type: "falcon" });
  const keyLengths = Object.freeze({
    seed: 48,
    publicKey: publicKeyCoder.bytesLen,
    secretKey: secretKeyCoder.bytesLen
  });
  const getRnd = (opts2 = {}) => {
    validateSigOpts(opts2);
    if (opts2.context !== void 0)
      throw new Error("context is not supported");
    if (opts2.random !== void 0)
      return opts2.random;
    if (opts2.extraEntropy === void 0)
      return randomBytes;
    const seed = opts2.extraEntropy === false ? new Uint8Array(48) : opts2.extraEntropy;
    abytes(seed, 48, "opts.extraEntropy");
    const drbg = rngAesCtrDrbg256(seed);
    return (len = 0) => drbg.randomBytes(len);
  };
  const checkVerOpts = (opts2 = {}) => {
    validateVerOpts(opts2);
    if (opts2.context !== void 0)
      throw new Error("context is not supported");
  };
  const tests = Object.freeze({
    publicKeyCoder: Object.freeze(publicKeyCoder),
    privateKeyCoder: Object.freeze(secretKeyCoder),
    maxS2Len: opts.maxS2Len
  });
  const attachedLengths = Object.freeze({ ...keyLengths, signRand: 48 });
  const lengths = opts.padded ? Object.freeze({ ...attachedLengths, signature: opts.sigLen }) : attachedLengths;
  const keygen = (seed) => {
    const randSeed = seed === void 0;
    if (randSeed)
      seed = randomBytes(48);
    abytes(seed, 48, "seed");
    const [f, g, F2, _G, pub] = new NTRU(logn, seed).generate();
    const sk = secretKeyCoder.encode([f, g, F2]);
    const pk = publicKeyCoder.encode(pub);
    if (randSeed)
      cleanBytes(seed);
    cleanBytes(f, g, F2, _G);
    return { publicKey: pk, secretKey: sk };
  };
  const getPublicKey = (sk) => {
    const [f, g, F2] = secretKeyCoder.decode(sk);
    try {
      const h = computePublic(f, g);
      cleanBytes(f, g, F2);
      return publicKeyCoder.encode(h);
    } catch (e) {
      cleanBytes(f, g, F2);
      throw e;
    }
  };
  const sign = (msg, sk, sigOpts = {}) => {
    const { s2, nonce } = signRaw(sk, msg, opts.maxS2Len, getRnd(sigOpts));
    return SignatureCoderDetached(logn).encode({ nonce, s2 });
  };
  const verify = (sig, msg, pk, verOpts = {}) => {
    checkVerOpts(verOpts);
    abytes(sig);
    abytes(msg);
    abytes(pk);
    try {
      const { s2, nonce } = SignatureCoderDetached(logn).decode(sig);
      return verifyRaw(pk, s2, nonce, msg);
    } catch {
      return false;
    }
  };
  const attached = Object.freeze({
    info,
    lengths: attachedLengths,
    keygen,
    getPublicKey,
    seal(msg, sk, sigOpts = {}) {
      const { s2, nonce } = signRaw(sk, msg, opts.maxS2Len, getRnd(sigOpts));
      return SignatureCoder.encode({ msg, nonce, s2 });
    },
    open(sig, pk, verOpts = {}) {
      checkVerOpts(verOpts);
      const { s2, nonce, msg } = SignatureCoder.decode(sig);
      if (verifyRaw(pk, s2, nonce, msg))
        return msg;
      throw new Error("invalid signature");
    }
  });
  const res = {
    info,
    lengths,
    attached,
    keygen,
    getPublicKey,
    sign,
    verify
  };
  res.__test = tests;
  return Object.freeze(res);
}
var falcon1024opts = {
  N: 1024,
  // Table 3.3 fixed padded detached bytes, including the detached header byte and 40-byte nonce.
  sigLen: 1280,
  fgBits: 5,
  FGBits: 8,
  // Compressed-s payload bytes only, excluding the detached header byte and 40-byte nonce.
  paddedLen: 1239,
  // Payload-only budget: genFalcon() adds the detached header byte and 40-byte nonce around it.
  detachedLen: 1280
};
var falcon1024 = /* @__PURE__ */ (() => genFalcon({
  ...falcon1024opts,
  maxS2Len: 1421
}))();

// lib/provenance-bridge.ts
var BRIDGE_ARTIFACT_CONTEXT = "apex-jarvis/APEX-PQC-v1/artifact";
var enc = new TextEncoder();
function b64ToBytes(b64) {
  if (typeof atob === "function") {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
    return out;
  }
  return Uint8Array.from(Buffer.from(b64, "base64"));
}
function bridgeMessageBytes(answer) {
  return enc.encode(JSON.stringify({ text: answer }));
}
function bridgeSignedBytes(answer, context = BRIDGE_ARTIFACT_CONTEXT) {
  const ctx = enc.encode(context);
  const msg = bridgeMessageBytes(answer);
  const out = new Uint8Array(ctx.length + 1 + msg.length);
  out.set(ctx, 0);
  out[ctx.length] = 0;
  out.set(msg, ctx.length + 1);
  return out;
}
function verifyBridgePrimary(answer, sigB64, pubKeyB64, context = BRIDGE_ARTIFACT_CONTEXT) {
  try {
    const signed = bridgeSignedBytes(answer, context);
    return ml_dsa87.verify(b64ToBytes(sigB64), signed, b64ToBytes(pubKeyB64));
  } catch {
    return false;
  }
}
function verifyBridgeSecondary(answer, sigB64, pubKeyB64, context = BRIDGE_ARTIFACT_CONTEXT) {
  try {
    const signed = bridgeSignedBytes(answer, context);
    return falcon1024.verify(b64ToBytes(sigB64), signed, b64ToBytes(pubKeyB64));
  } catch {
    return false;
  }
}

// lib/provenance-bundle.ts
var PROOF_KIND = "throndar-proof";
var PROOF_VERSION = 1;
function verifyProofBundle(b) {
  const verdict = { overallOk: false, checks: 0 };
  let allOk = true;
  if (b.receipt && b.receiptKey) {
    verdict.checks += 1;
    const r = b.receipt;
    let answerHashOk = false;
    let sigOk = false;
    try {
      answerHashOk = sha256HexUtf8(b.answer) === r.answer_sha256;
      const core = {
        v: r.v,
        model: r.model,
        answer_sha256: r.answer_sha256,
        governance_flag: r.governance_flag,
        ts: r.ts
      };
      if (r.council_grounded === false) core.council_grounded = false;
      sigOk = ml_dsa87.verify(hexToBytes(r.sig), canonicalBytes(core), hexToBytes(b.receiptKey.public_key_hex), {
        context: contextBytes(PROVENANCE_CONTEXT)
      });
    } catch {
    }
    verdict.receipt = {
      present: true,
      answerHashOk,
      sigOk,
      keyId: receiptKeyIdOf(b.receiptKey.public_key_hex),
      // Surface the SIGNED council-grounding flag (true ⇒ full council, false ⇒
      // single-model fallback). Bound into the signature, so it is only meaningful
      // when sigOk — the UI gates the fallback badge on that.
      councilGrounded: r.council_grounded !== false
    };
    allOk = allOk && answerHashOk && sigOk;
  }
  if (b.attestation?.sig_primary && b.bridgeKeys?.length) {
    verdict.checks += 1;
    const a = b.attestation;
    const pk = b.bridgeKeys.find((k) => k.role === "primary" && k.alg === "ML-DSA-87");
    const sk = b.bridgeKeys.find((k) => k.role === "secondary" && k.alg === "Falcon-1024");
    const primaryOk = Boolean(
      pk && a.sig_primary && verifyBridgePrimary(b.answer, a.sig_primary, pk.public_key_b64)
    );
    const secondaryOk = Boolean(
      sk && a.sig_secondary && verifyBridgeSecondary(b.answer, a.sig_secondary, sk.public_key_b64)
    );
    verdict.bridge = { present: true, primaryOk, secondaryOk, keyId: a.key_id_primary ?? void 0 };
    allOk = allOk && primaryOk;
  }
  verdict.overallOk = verdict.checks > 0 && allOk;
  return verdict;
}
var TRANSCRIPT_KIND = "throndar-transcript";
function verifyTranscriptBundle(b) {
  const turns = (b.turns ?? []).map((t, index) => {
    const pb = {
      v: PROOF_VERSION,
      kind: PROOF_KIND,
      created: b.created,
      answer: t.answer,
      receipt: t.receipt,
      receiptKey: t.receipt ? (b.receiptKeys ?? []).find((k) => k.key_id === t.receipt.key_id) : void 0,
      attestation: t.attestation,
      bridgeKeys: b.bridgeKeys
    };
    return { index, verdict: verifyProofBundle(pb) };
  });
  const authentic = turns.filter((t) => t.verdict.overallOk).length;
  const unsigned = turns.filter((t) => t.verdict.checks === 0).length;
  return {
    turns,
    total: turns.length,
    authentic,
    unsigned,
    overallOk: turns.length > 0 && authentic === turns.length
  };
}
function receiptKeyIdOf(publicKeyHex) {
  try {
    return bytesToHex(sha256(hexToBytes(publicKeyHex))).slice(0, 16);
  } catch {
    return "";
  }
}
function originRecognized(b, v, anchors) {
  if (!v.overallOk) return false;
  const ids = new Set(anchors.receiptKeyIds);
  for (const p of anchors.receiptPins ?? []) if (p.keyId) ids.add(p.keyId);
  const bridgeKeys = /* @__PURE__ */ new Set();
  if (anchors.bridgePrimaryB64) bridgeKeys.add(anchors.bridgePrimaryB64.trim());
  for (const p of anchors.bridgePins ?? []) {
    const k = (p.pubkeyB64 || "").trim();
    if (k) bridgeKeys.add(k);
  }
  let any = false;
  if (v.receipt?.present) {
    const id2 = receiptKeyIdOf(b.receiptKey?.public_key_hex || "");
    if (!id2 || !ids.has(id2)) return false;
    any = true;
  }
  if (v.bridge?.present) {
    const embedded = (b.bridgeKeys?.find((k) => k.role === "primary" && k.alg === "ML-DSA-87")?.public_key_b64 || "").trim();
    if (bridgeKeys.size === 0 || !bridgeKeys.has(embedded)) return false;
    any = true;
  }
  return any;
}
function transcriptOriginRecognized(b, v, anchors) {
  if (!v.overallOk || v.turns.length === 0) return false;
  return v.turns.every((t) => {
    const turn = b.turns[t.index];
    if (!turn) return false;
    const pb = {
      v: PROOF_VERSION,
      kind: PROOF_KIND,
      created: b.created,
      answer: turn.answer,
      receipt: turn.receipt,
      receiptKey: turn.receipt ? (b.receiptKeys ?? []).find((k) => k.key_id === turn.receipt.key_id) : void 0,
      attestation: turn.attestation,
      bridgeKeys: b.bridgeKeys
    };
    return originRecognized(pb, t.verdict, anchors);
  });
}

// lib/autopilot/run-canonical.ts
function runCore(run) {
  return {
    id: run.id,
    goal_sha256: sha256HexUtf8(run.goal),
    status: run.status,
    stop_reason: run.stopReason || "",
    budget_credits: run.budgetCredits,
    spent_credits: run.spentCredits,
    max_steps: run.maxSteps,
    steps: run.steps.map((s) => ({
      i: s.index,
      title: s.title,
      output_sha256: sha256HexUtf8(s.output),
      verified: s.verified,
      verify_mode: s.verifyMode || "",
      verify_reason_sha256: sha256HexUtf8(s.verifyReason || ""),
      council_grounded: s.councilGrounded,
      cost_credits: s.costCredits
    })),
    summary_sha256: sha256HexUtf8(run.summary)
  };
}
function runCanonicalString(run) {
  return JSON.stringify(runCore(run));
}

// lib/autopilot/run-bundle.ts
var RUN_PROOF_KIND = "throndar-autopilot-run";
function verifyRunBundle(b) {
  const steps = Array.isArray(b.run?.steps) ? b.run.steps : [];
  const verdict = {
    present: Boolean(b.receipt && b.receiptKey),
    integrityOk: false,
    sigOk: false,
    keyId: b.receiptKey ? receiptKeyIdOf(b.receiptKey.public_key_hex) : "",
    councilGrounded: b.receipt?.council_grounded !== false,
    stepsTotal: steps.length,
    stepsVerified: steps.filter((s) => s?.verified).length,
    overallOk: false
  };
  if (!b.receipt || !b.receiptKey) return verdict;
  const r = b.receipt;
  try {
    verdict.integrityOk = sha256HexUtf8(runCanonicalString(b.run)) === r.answer_sha256;
    const core = {
      v: r.v,
      model: r.model,
      answer_sha256: r.answer_sha256,
      governance_flag: r.governance_flag || "",
      ts: r.ts
    };
    if (r.council_grounded === false) core.council_grounded = false;
    verdict.sigOk = ml_dsa87.verify(hexToBytes(r.sig), canonicalBytes(core), hexToBytes(b.receiptKey.public_key_hex), {
      context: contextBytes(AUTOPILOT_CONTEXT)
    });
  } catch {
  }
  verdict.overallOk = verdict.present && verdict.integrityOk && verdict.sigOk;
  return verdict;
}
function runOriginRecognized(b, v, anchors) {
  if (!v.overallOk) return false;
  const ids = new Set(anchors.receiptKeyIds);
  for (const p of anchors.receiptPins ?? []) if (p.keyId) ids.add(p.keyId);
  const id2 = receiptKeyIdOf(b.receiptKey?.public_key_hex || "");
  return Boolean(id2) && ids.has(id2);
}

// lib/provenance-export.ts
var EXPORT_PROOF_KIND = "throndar-export";
function isExportArchive(obj) {
  const a = obj;
  return Boolean(
    a && typeof a === "object" && a.proof && a.proof.kind === EXPORT_PROOF_KIND && Array.isArray(a.conversations)
  );
}
function verifyExportArchive(a) {
  const proof = a?.proof;
  const r = proof?.receipt;
  const key = proof?.receiptKey;
  const verdict = {
    present: Boolean(proof && r && key && Array.isArray(a?.conversations) && typeof proof?.manifest === "string"),
    manifestIntegrityOk: false,
    payloadOk: false,
    sigOk: false,
    keyId: key ? receiptKeyIdOf(key.public_key_hex) : "",
    conversations: 0,
    messages: 0,
    overallOk: false
  };
  if (!verdict.present || !proof || !r || !key) return verdict;
  try {
    verdict.manifestIntegrityOk = sha256HexUtf8(proof.manifest) === r.answer_sha256;
    const m = JSON.parse(proof.manifest);
    const recomputed = sha256HexUtf8(JSON.stringify(a.conversations ?? []));
    const hashOk = typeof m.payload_sha256 === "string" && m.payload_sha256 === recomputed;
    const countOk = typeof m.conversations !== "number" || m.conversations === (a.conversations?.length ?? 0);
    verdict.payloadOk = hashOk && countOk;
    if (typeof m.conversations === "number") verdict.conversations = m.conversations;
    if (typeof m.messages === "number") verdict.messages = m.messages;
    const core = {
      v: r.v,
      model: r.model,
      answer_sha256: r.answer_sha256,
      governance_flag: r.governance_flag || "",
      ts: r.ts
    };
    if (r.council_grounded === false) core.council_grounded = false;
    verdict.sigOk = ml_dsa87.verify(hexToBytes(r.sig), canonicalBytes(core), hexToBytes(key.public_key_hex), {
      context: contextBytes(EXPORT_CONTEXT)
    });
  } catch {
  }
  verdict.overallOk = verdict.present && verdict.manifestIntegrityOk && verdict.payloadOk && verdict.sigOk;
  return verdict;
}
function exportOriginRecognized(a, v, anchors) {
  if (!v.overallOk) return false;
  const ids = new Set(anchors.receiptKeyIds);
  for (const p of anchors.receiptPins ?? []) if (p.keyId) ids.add(p.keyId);
  const id2 = receiptKeyIdOf(a.proof?.receiptKey?.public_key_hex || "");
  return Boolean(id2) && ids.has(id2);
}

// lib/provenance-sth.ts
var STH_KIND = "throndar-sth";
var THRONDAR_ANSWER_LOG = "throndar-answers-v1";
function asSth(obj) {
  const o = obj;
  if (o && typeof o === "object" && o.signed_tree_head && typeof o.signed_tree_head === "object") {
    return o.signed_tree_head;
  }
  if (o && typeof o === "object" && typeof o.signed === "string") return o;
  return null;
}
function isSthBundle(obj) {
  const sth = asSth(obj);
  if (!sth || typeof sth.signed !== "string" || !sth.receipt || !sth.key) return false;
  try {
    const m = JSON.parse(sth.signed);
    return typeof m.tree_size === "number" && typeof m.root_hash === "string";
  } catch {
    return false;
  }
}
function verifySthBundle(obj) {
  const sth = asSth(obj);
  const r = sth?.receipt;
  const key = sth?.key;
  const verdict = {
    present: Boolean(sth && typeof sth.signed === "string" && r && key),
    integrityOk: false,
    sigOk: false,
    logOk: false,
    keyId: key ? receiptKeyIdOf(key.public_key_hex) : "",
    log: "",
    treeSize: 0,
    rootHash: "",
    timestamp: 0,
    overallOk: false
  };
  if (!verdict.present || !sth || !r || !key) return verdict;
  try {
    verdict.integrityOk = sha256HexUtf8(sth.signed) === r.answer_sha256;
    const m = JSON.parse(sth.signed);
    if (typeof m.log === "string") verdict.log = m.log;
    if (typeof m.tree_size === "number") verdict.treeSize = m.tree_size;
    if (typeof m.root_hash === "string") verdict.rootHash = m.root_hash;
    if (typeof m.timestamp === "number") verdict.timestamp = m.timestamp;
    verdict.logOk = m.log === THRONDAR_ANSWER_LOG;
    const core = {
      v: r.v,
      model: r.model,
      answer_sha256: r.answer_sha256,
      governance_flag: r.governance_flag || "",
      ts: r.ts
    };
    if (r.council_grounded === false) core.council_grounded = false;
    verdict.sigOk = ml_dsa87.verify(hexToBytes(r.sig), canonicalBytes(core), hexToBytes(key.public_key_hex), {
      context: contextBytes(STH_CONTEXT)
    });
  } catch {
  }
  verdict.overallOk = verdict.present && verdict.integrityOk && verdict.sigOk && verdict.logOk;
  return verdict;
}
function sthOriginRecognized(obj, v, anchors) {
  if (!v.overallOk) return false;
  const sth = asSth(obj);
  const ids = new Set(anchors.receiptKeyIds);
  for (const p of anchors.receiptPins ?? []) if (p.keyId) ids.add(p.keyId);
  const id2 = receiptKeyIdOf(sth?.key?.public_key_hex || "");
  return Boolean(id2) && ids.has(id2);
}

// lib/transparency.ts
var LEAF = Uint8Array.of(0);
var NODE = Uint8Array.of(1);
function nodeHash(l, r) {
  return sha256(concatBytes(NODE, l, r));
}
function verifyConsistency(m, n, oldRoot, newRoot, proof) {
  const eq = (a, b) => bytesToHex(a) === bytesToHex(b);
  if (m > n || m < 0) return false;
  if (m === n) return proof.length === 0 && eq(oldRoot, newRoot);
  if (m === 0) return proof.length === 0;
  let path2 = proof;
  if ((m & m - 1) === 0) path2 = [oldRoot, ...proof];
  if (path2.length === 0) return false;
  let fn = m - 1;
  let sn = n - 1;
  while (fn & 1) {
    fn >>= 1;
    sn >>= 1;
  }
  let fr = path2[0];
  let sr = path2[0];
  for (let i = 1; i < path2.length; i += 1) {
    const c = path2[i];
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      while (fn !== 0 && (fn & 1) === 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else {
      sr = nodeHash(sr, c);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return eq(fr, oldRoot) && eq(sr, newRoot) && sn === 0;
}
function verifyConsistencyHex(m, n, oldRootHex, newRootHex, proofHex) {
  try {
    return verifyConsistency(m, n, hexToBytes(oldRootHex), hexToBytes(newRootHex), proofHex.map(hexToBytes));
  } catch {
    return false;
  }
}

// lib/provenance-consistency.ts
var CONSISTENCY_KIND = "throndar-consistency";
function isConsistencyBundle(obj) {
  const b = obj;
  return Boolean(
    b && typeof b === "object" && b.kind === CONSISTENCY_KIND && b.old && typeof b.old === "object" && b.new && typeof b.new === "object" && Array.isArray(b.proof)
  );
}
function verifyConsistencyBundle(b) {
  const oldV = verifySthBundle(b?.old);
  const newV = verifySthBundle(b?.new);
  const verdict = {
    present: Boolean(b?.old && b?.new && Array.isArray(b?.proof)),
    oldSthOk: oldV.overallOk,
    newSthOk: newV.overallOk,
    consistencyOk: false,
    oldSize: oldV.treeSize,
    newSize: newV.treeSize,
    oldKeyId: oldV.keyId,
    newKeyId: newV.keyId,
    overallOk: false
  };
  if (!verdict.present) return verdict;
  if (oldV.overallOk && newV.overallOk && oldV.treeSize <= newV.treeSize) {
    verdict.consistencyOk = verifyConsistencyHex(
      oldV.treeSize,
      newV.treeSize,
      oldV.rootHash,
      newV.rootHash,
      b.proof ?? []
    );
  }
  verdict.overallOk = verdict.oldSthOk && verdict.newSthOk && verdict.consistencyOk;
  return verdict;
}
function consistencyOriginRecognized(b, v, anchors) {
  if (!v.overallOk) return false;
  return sthOriginRecognized(b?.old, verifySthBundle(b?.old), anchors) && sthOriginRecognized(b?.new, verifySthBundle(b?.new), anchors);
}

// lib/verify-any.ts
var DEFAULT_CAPS = { maxTurns: 200, maxRunSteps: 100 };
function wireKind(r) {
  switch (r.kind) {
    case "proof":
      return PROOF_KIND;
    case "transcript":
      return TRANSCRIPT_KIND;
    case "autopilot":
      return RUN_PROOF_KIND;
    case "export":
      return EXPORT_PROOF_KIND;
    case "sth":
      return STH_KIND;
    case "consistency":
      return CONSISTENCY_KIND;
    default:
      return "";
  }
}
function verifyAny(obj, anchors, caps = {}) {
  const maxTurns = caps.maxTurns ?? DEFAULT_CAPS.maxTurns;
  const maxRunSteps = caps.maxRunSteps ?? DEFAULT_CAPS.maxRunSteps;
  const rec = obj;
  const kind = rec && typeof rec.kind === "string" ? rec.kind : "";
  try {
    if (isExportArchive(obj)) {
      const bundle = obj;
      const verdict = verifyExportArchive(bundle);
      return { kind: "export", bundle, verdict, ok: verdict.overallOk, signerRecognized: exportOriginRecognized(bundle, verdict, anchors) };
    }
    if (isSthBundle(obj)) {
      const verdict = verifySthBundle(obj);
      const bundle = obj.signed_tree_head ?? obj;
      return { kind: "sth", bundle, verdict, ok: verdict.overallOk, signerRecognized: sthOriginRecognized(obj, verdict, anchors) };
    }
    if (isConsistencyBundle(obj)) {
      const bundle = obj;
      const verdict = verifyConsistencyBundle(bundle);
      return { kind: "consistency", bundle, verdict, ok: verdict.overallOk, signerRecognized: consistencyOriginRecognized(bundle, verdict, anchors) };
    }
    if (kind === TRANSCRIPT_KIND && Array.isArray(rec?.turns)) {
      if (rec.turns.length > maxTurns) return { kind: "unknown", error: `too many turns (max ${maxTurns})` };
      const bundle = obj;
      const verdict = verifyTranscriptBundle(bundle);
      return { kind: "transcript", bundle, verdict, ok: verdict.overallOk, signerRecognized: transcriptOriginRecognized(bundle, verdict, anchors) };
    }
    if (kind === PROOF_KIND && typeof rec?.answer === "string") {
      const bundle = obj;
      const verdict = verifyProofBundle(bundle);
      return { kind: "proof", bundle, verdict, ok: verdict.overallOk, signerRecognized: originRecognized(bundle, verdict, anchors) };
    }
    if (kind === RUN_PROOF_KIND && typeof rec?.run === "object") {
      const bundle = obj;
      if ((bundle.run?.steps?.length ?? 0) > maxRunSteps) return { kind: "unknown", error: `too many steps (max ${maxRunSteps})` };
      const verdict = verifyRunBundle(bundle);
      return { kind: "autopilot", bundle, verdict, ok: verdict.overallOk, signerRecognized: runOriginRecognized(bundle, verdict, anchors) };
    }
  } catch (e) {
    return { kind: "unknown", error: e instanceof Error ? e.message : String(e) };
  }
  return {
    kind: "unknown",
    error: `not a Throndar proof bundle (expected kind '${PROOF_KIND}' with an 'answer', '${TRANSCRIPT_KIND}' with 'turns', '${RUN_PROOF_KIND}' with a 'run', a signed export whose proof.kind is '${EXPORT_PROOF_KIND}', a signed tree head, or a '${CONSISTENCY_KIND}' bundle)`
  };
}

// lib/trust-anchors.ts
var PINNED_BRIDGE_PRIMARY_B64 = "bPZlFFROysdVRXmWhSKUbup6U38FMJLOjH/kKeBN5ZMST2LAR5iz3YZoU5z6ExKwkoMLeNIsSmXwV0lBZWhKmF5O/kT4x9tTZDZrHCLkhAkzdDQyxIDKrC9uz2HLDe9zY4+xxmukcbiXnqxvtc+f7Fqy6IB60WmqZ+kAygY16XGDARhWcFBhWBNYJVZsjm6+nX8pT57r5PhIX0idpRjWE5nvYnuWWJ5sjqvr3Hz+Kem/557gxSKOh4xLdwvGnE/6YV4km0Um4wSZAVpPG+4eRiNKPznGDma1D9HebSzGQCPx5m+83sHiFCtS5Unn2tdHz9+Qx0CIGdXohBM//V/QU2GwwZKJRFjncnWW3FVUKRemtB/f121jI+uP9f6oX1ZIKmehUAXSp0QSKEKlHDL414c9IEzGGUm8mtCOpV0ixGHp2kXl1Kn/stNAWm05S8bAe9ncm0lpBp4Big7//eWl0IobxdjhIRUFMLYWYARc/Gx5/dVTxF/HnrYiQTZ4nAmXsiutqo/v8i31PZQDYFxhVFGJeJoDO+bdA8Nc9lC89LwLamXQ3OWmo6R36g5WylWs1xdr4Y4etjwhkmLD3iXQi25eq+NwSM4nmuoyz2uYoF8ToAWpIIYRrIAfMqWDleHDJe6DXo+Q6UsJvytAJfywQJVmL1XqfRlyZX5QxtNa4onzj+nHveODert4a+o4xDgXPGB5nU/OtJM08xqp5DAnv7hafWUo0QVZPx/ZV+8uosu9QPByKyh15bULbLkZbwYVniR+rddZAQdzucbjZK+i8sYbuF/NNYaDfB0zB5PnpKNLCwLelepYUnpdG2jYtli0e2ouTMab4DVG/zK9EfSC6+3h90cgo8OftZeknUwenqrGsZ+f64qNqBJhXxxGKRMHjspakZcCNjiSfmq7Xdf6TcPSMtEs3HPEVLQy/g7PaN3GGA5LNn78Vg8leoESi/3aNaQXXNVaqUbTNK97peyYPOE+MdMG14n+Je+cwr0KkjH0OCoejHuOlXQ/oIxa+zv/JE2/V5Zd+6PJz+fljKuqXkTNDQdW6MVTbBqqiJTvSmPz09TM8Fx6QjF69nF/4LIfXA0K7cQm5fBsoUfohfhyUdOVpO7rctZNDyA1zZgeu1EAo4KxOtJAD97eb3JJhjt4SAI/5zyYFO3r/FVjQU9oM+jxd0e361Wsq5IvS72fhBmmlaHL8ke6fdeyl1izn1FExqd5oli3d7BusftXHYhvUso0sxvEej4X969XthU/zhJwcGZvHZePJnURSttOQWqq269GYQnZqzP8uJ2gSggPMUBZ6uO68RUgkDzXyxsZcx7xslkcm4qMXDgYzXH54+2s0L7cZbrTTedaXv8wu5YqYszEYIaG77ntxoClp8yBLHX5QI/OQnRLxza+d+lxfOcSo1ITT5mDMylcyo+ZaXQD3VUJhEEy71oo/n7BJ74B8pVwwqHOygBaNznFfQKjgesx+ymqfnLlK/G5HhRf6LvSwcFifjLRQY2w7Rn5UQQuJAXLOh+lNvhfDniNsDRAu6MGPr6/96lGwbc0eP/g3EiWLFvBWQDdBdvF8bwidS2oc1BoMAFOUOfDncb1acfN83CeYDMhOdNI0Y8gXm/paOXga7mmoS4tOc/d6iUoZJdV03e4kjvgCbufvg9HQ/VxjYMc4eYRjkwErjGcBKFZ4hFsmFxndYowYQDEu8j4kxVO44KcMp+15n0hkr+Bn1qRVJdHQ1R4DppM0T9L5Sd9auUzd7jK3A29bWjlNgHjAk91W8A6rJyMNx6wwep9QCWlaKg4PdWfgqcr2fVUGiMihxuL+AZHNrvLOEnCkEJjhHwQ4dNA2u0oRxr4jRZkhAPfrQ1iKd7PIQZz+OFs/OJorcKJrxUvw7ps77tkC0HMymbElfxnyixrWCAyJCT30GSfFv+Ap/vyJwtE3gjZ+XTdOV8BgjiTVwZ+l77M/pPMJ22/MedSRdy4mkVBi/a70t/co9hwawrPbriLQ1D8/KiD996q2QCKbGQE99BnN3GH6Y7EJljr829qf7YYmG8DpW4LOkTxGI02skLBbk7ByaopUiQr9a7aKUGMtukIJViyWY3Y5dHwc5vM1/VZhYZiQX2rVl7RC0Xc+lC7Die2wrJVQyvdvltb3dUJM6QO/dzUUHJdeXfQaIw4W5QR0xm24mhePEuAg6V7xl/vE0EWk4TKwYfCU+/Ouz+aSrMxmuJ6AOj05yvF/6vyv8El91UxFhqAjTbbLLBb8Mu964cOTT0gzUR0iJVejS+rQK8cnPHhzDpvLzDLttbyztgrwGIqqVzuYqxRvE0KaRKVpygp9BKynOPZdu/CevFAkbECZXL54UvWIzSSbLEpPrSJvE1RkPPCd5wgkPqe/w1KqdcmAOM4YnnnvZZw5b0y+Q/DE++KgciU2lgfZb7Flo7zgkTwuy4Upys8815v4VoXp2R/NAt/cNts+5Vvj5iMjd2uO624iyLFmamqv+vAxsdwXAsfN6PkfbWm+cub/8z0+HUv9mp3pe7KmyUSDXdVJjeFyPDYQ2tL5gPYIETXpIQn1m8CrOwF04mdQyfuhQOXEppufBkJOUZqdoA8Ybi9VhnZd1IQgyMrlJwyuGtt0SckMm5b1dcqKZP9RHg+7wyKzvZg0ezYf7emLlDcRDAugapV8cFx8nvy5QaQP4HSyv6w0cXQoKPCAEFttTVje83DXtqsMRDWBAYyLT6kaM/ORljNKCQ1/wYtb3i3OorlBmjGQcoL9QfYLle7Lb+ayrTCzzCYX4Lbn3VFcJoQNjCvz1Nhbr73CKg2MM+xHUBRyHNOz6YyMjS2dYkHhPnV+FQ8rqPEKZr+DXeEcOT1azAiAljASuQWwaZYIXDM0IJ24yF74cEnJ08CWqFIvvWP4LKf/t/RUUO7P/8xUDpcWJHV5bwBqREPT+OLSDucppRDpACPG5PvBS3Z/34+jb9nlcYiW3ybLIxZqOz9NNn7U9HKcOpw6sR7vjZnPOLD5/M66Tn5y4ZTdM0EyZOdxodzrNeA3h1HgSj557kLB7G0LW62fPkDIu98jW5Kh8eMFIx/Owo+eije9+ndTYIY75hyR/zX4HVnpO6zDkD26wMITzF5LQp1qmJGAUmEhVMawi/n2TJr2TeEefqiEErbHPq90LcibyqoKOKuLjZz28d7MD5Oy1MlqrJWMBxUwu49a+bgfqJqqnDmQKPWvmjT8AmQ6JS/5s1ai64I9bmSRwMU+Lq7gNz5ZRqpz9TR90DfgRTTR5xAu5+1tPEye98i+ZCVZ7KBvkvSziUdvPy7PllS7CXaqXqxDHpBnz2++KaCTSXSW1qizECeUhAzJKBZQd2H77PBA0HuBN0bZ/b6sC6Adh66edUbbwtejiFl2CzhyqIE28+2K8vX4c8lU/Fc9qLswAgC4BWwOfseQ9kD0Ua1rvgJ+ea4R2mo5lNEbw3KmzmxDmeNh9NkKn/7HP2F";
var PINNED_RECEIPT_KEY_IDS = ["0986d89fa3c74566"];
var PINNED_BRIDGE_PINS = [];
var PINNED_RECEIPT_PINS = [];

// tools/verify-cli/core.ts
var PINNED_ANCHORS = {
  receiptKeyIds: PINNED_RECEIPT_KEY_IDS,
  bridgePrimaryB64: PINNED_BRIDGE_PRIMARY_B64,
  bridgePins: PINNED_BRIDGE_PINS,
  receiptPins: PINNED_RECEIPT_PINS
};
function verifyBundleObject(obj, anchors = PINNED_ANCHORS) {
  const r = verifyAny(obj, anchors);
  if (r.kind === "unknown") return { ok: false, signerRecognized: false, kind: "", verdict: null, error: r.error };
  return { ok: r.ok, signerRecognized: r.signerRecognized, kind: wireKind(r), verdict: r.verdict };
}
function passes(v, requireOrigin) {
  return v.ok && (!requireOrigin || v.signerRecognized);
}

// tools/verify-cli/cli.ts
var HELP = `throndar-verify \u2014 verify Throndar proof bundles entirely offline.

USAGE
  throndar-verify [options] <bundle.json>          verify one file
  throndar-verify [options] a.json b.json ...       verify several files
  throndar-verify [options] ./proofs/               verify every *.json in a directory
  cat bundle.json | throndar-verify [options]        verify from stdin

OPTIONS
  --require-origin   fail unless the signer is a PINNED Throndar key (not just
                     internally-valid signatures). Use this in CI to reject a
                     self-signed / non-Throndar bundle.
  --json             emit a JSON report instead of human-readable lines.
  -h, --help         show this help.

EXIT CODES
  0  every bundle verified (with --require-origin, each is also Throndar-origin).
  1  at least one bundle did NOT verify, or could not be read/parsed.
  2  usage error (before any bundle was read).

SCOPE
  A pass proves ORIGIN + INTEGRITY (this exact answer, signed by the key holder,
  unaltered) \u2014 NOT that the answer's content is correct.
`;
function usage(msg) {
  process.stderr.write((msg.endsWith("\n") ? msg : msg + "\n") + "\n" + HELP);
  process.exit(2);
}
var MAX_BYTES = 4e6;
function verifyText(source, text, requireOrigin) {
  if (text.length > MAX_BYTES) return { source, read: false, pass: false, error: "input too large (> 4 MB)" };
  let obj;
  try {
    obj = JSON.parse(text);
  } catch {
    return { source, read: false, pass: false, error: "not valid JSON" };
  }
  const verdict = verifyBundleObject(obj);
  return { source, read: !verdict.error, pass: passes(verdict, requireOrigin), verdict };
}
function expand(arg) {
  let st;
  try {
    st = statSync(arg);
  } catch {
    return [arg];
  }
  if (!st.isDirectory()) return [arg];
  return readdirSync(arg).filter((f) => f.toLowerCase().endsWith(".json")).sort().map((f) => path.join(arg, f));
}
function readFile(file, requireOrigin) {
  let text;
  try {
    text = readFileSync(file, "utf8");
  } catch (e) {
    return { source: file, read: false, pass: false, error: `cannot read: ${e instanceof Error ? e.message : String(e)}` };
  }
  return verifyText(file, text, requireOrigin);
}
function line(r) {
  if (!r.read) return `\u2717 ${r.source}: ${r.error}`;
  const v = r.verdict;
  const origin = v.signerRecognized ? "Throndar-origin" : "integrity-only";
  return `${r.pass ? "\u2713" : "\u2717"} ${r.source}: ${v.ok ? "signatures verified" : "signatures FAILED"} (${v.kind}, ${origin}) \u2192 ${r.pass ? "PASS" : "FAIL"}`;
}
function main(argv) {
  let requireOrigin = false;
  let json = false;
  const paths = [];
  for (const a of argv.slice(2)) {
    if (a === "--require-origin") requireOrigin = true;
    else if (a === "--json") json = true;
    else if (a === "-h" || a === "--help") {
      process.stdout.write(HELP);
      process.exit(2);
    } else if (a.startsWith("-")) usage(`unknown option: ${a}`);
    else paths.push(a);
  }
  const results = [];
  if (paths.length === 0) {
    let text;
    try {
      text = readFileSync(0, "utf8");
    } catch (e) {
      usage(`cannot read stdin: ${e instanceof Error ? e.message : String(e)}`);
    }
    results.push(verifyText("(stdin)", text, requireOrigin));
  } else {
    const files = paths.flatMap(expand);
    if (files.length === 0) usage("no .json bundles found in the given path(s)");
    for (const f of files) results.push(readFile(f, requireOrigin));
  }
  const allPass = results.every((r) => r.read && r.pass);
  if (json) {
    const report = {
      pass: allPass,
      total: results.length,
      passed: results.filter((r) => r.read && r.pass).length,
      results: results.map((r) => ({
        source: r.source,
        pass: r.read && r.pass,
        ok: r.verdict?.ok ?? false,
        signerRecognized: r.verdict?.signerRecognized ?? false,
        kind: r.verdict?.kind || null,
        error: r.error ?? r.verdict?.error ?? null
      }))
    };
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  } else {
    for (const r of results) process.stdout.write(line(r) + "\n");
    if (results.length > 1) {
      const passed = results.filter((r) => r.read && r.pass).length;
      process.stdout.write(`
${passed}/${results.length} verified \u2014 ${allPass ? "PASS" : "FAIL"}
`);
    }
  }
  process.exit(allPass ? 0 : 1);
}
main(process.argv);
