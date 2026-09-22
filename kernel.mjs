// ShardVeil — k-of-n threshold secret sharing over GF(256) (AES field, poly 0x11b).
//
// Pure and total: no I/O, no hidden randomness — entropy is an explicit input.
// Bad input returns {ok:false, why} — never throws.
// Joining with fewer than k shares is REFUSED, never estimated: below the
// quorum the secret is information-theoretically absent (any value of the
// secret is equally consistent with the shares held), so there is nothing
// to approximate. The refusal is the mathematics, not a policy.

const POLY = 0x11b; // x^8 + x^4 + x^3 + x + 1

function isByte(v) {
  return Number.isInteger(v) && v >= 0 && v <= 255;
}
function isByteArray(a) {
  return Array.isArray(a) && a.every(isByte);
}

// internal field ops — assume valid bytes
function mul(a, b) {
  let r = 0;
  while (b) {
    if (b & 1) r ^= a;
    a <<= 1;
    if (a & 0x100) a ^= POLY;
    b >>= 1;
  }
  return r;
}
function inv(a) {
  // a^254 = a^-1 in GF(256); caller guarantees a !== 0
  let r = 1;
  for (let i = 0; i < 254; i++) r = mul(r, a);
  return r;
}

/** Total wrapper over field multiply: gfMul(a, b) -> {ok, value|why}. */
export function gfMul(a, b) {
  if (!isByte(a) || !isByte(b)) {
    return { ok: false, why: 'gfMul: operands must be integers 0..255' };
  }
  return { ok: true, value: mul(a, b) };
}

/** Total wrapper over field inverse: 0 has no inverse — refused, not estimated. */
export function gfInv(a) {
  if (!isByte(a)) {
    return { ok: false, why: 'gfInv: operand must be an integer 0..255' };
  }
  if (a === 0) {
    return { ok: false, why: 'gfInv: 0 has no multiplicative inverse' };
  }
  return { ok: true, value: inv(a) };
}

/**
 * split(secret, n, k, entropy) -> {ok, shares|why}
 *
 * secret  : array of bytes (length >= 1)
 * n       : number of shares to produce, 2..255
 * k       : quorum, 2..n
 * entropy : array of exactly (k-1) * secret.length bytes — the random
 *           polynomial coefficients, supplied by the caller so this
 *           function stays pure and reproducible.
 *
 * Layout: coefficient j (1..k-1) of secret byte i is entropy[(k-1)*i + (j-1)].
 * Share x-coordinates are 1..n; each share carries k so join knows the quorum.
 */
export function split(secret, n, k, entropy) {
  if (!isByteArray(secret) || secret.length < 1) {
    return { ok: false, why: 'split: secret must be a non-empty array of bytes 0..255' };
  }
  if (!Number.isInteger(n) || n < 2 || n > 255) {
    return { ok: false, why: 'split: n must be an integer 2..255' };
  }
  if (!Number.isInteger(k) || k < 2 || k > n) {
    return { ok: false, why: 'split: k must be an integer 2..n (a quorum of one is no quorum)' };
  }
  const need = (k - 1) * secret.length;
  if (!isByteArray(entropy) || entropy.length !== need) {
    return {
      ok: false,
      why: `split: entropy must be exactly ${need} byte(s) ((k-1) * secret.length); got ${
        Array.isArray(entropy) ? entropy.length : typeof entropy
      }`,
    };
  }

  const shares = [];
  for (let x = 1; x <= n; x++) {
    const bytes = new Array(secret.length);
    for (let i = 0; i < secret.length; i++) {
      // Horner from the top coefficient down to c0 = secret[i]
      let y = 0;
      for (let j = k - 1; j >= 1; j--) {
        y = mul(y, x) ^ entropy[(k - 1) * i + (j - 1)];
      }
      y = mul(y, x) ^ secret[i];
      bytes[i] = y;
    }
    shares.push({ x, k, bytes });
  }
  return { ok: true, shares };
}

/**
 * join(shares) -> {ok, secret|why}
 *
 * Requires at least k mutually consistent shares (same k, same length,
 * distinct x). With fewer than k it REFUSES — below threshold every candidate
 * secret is equally likely, so estimation is meaningless and dishonest.
 * With k or more, the first k shares (in given order) reconstruct via
 * Lagrange interpolation at x = 0.
 */
export function join(shares) {
  if (!Array.isArray(shares) || shares.length < 1) {
    return { ok: false, why: 'join: shares must be a non-empty array' };
  }
  for (const s of shares) {
    if (
      typeof s !== 'object' || s === null ||
      !isByte(s.x) || s.x < 1 ||
      !Number.isInteger(s.k) || s.k < 2 ||
      !isByteArray(s.bytes) || s.bytes.length < 1
    ) {
      return { ok: false, why: 'join: each share must be {x:1..255, k:int>=2, bytes:[bytes]}' };
    }
  }
  const k = shares[0].k;
  const len = shares[0].bytes.length;
  if (!shares.every((s) => s.k === k)) {
    return { ok: false, why: 'join: shares disagree on quorum k — refused' };
  }
  if (!shares.every((s) => s.bytes.length === len)) {
    return { ok: false, why: 'join: shares disagree on secret length — refused' };
  }
  const xs = new Set(shares.map((s) => s.x));
  if (xs.size !== shares.length) {
    return { ok: false, why: 'join: duplicate share x-coordinates — refused' };
  }
  if (shares.length < k) {
    return {
      ok: false,
      why: `join: REFUSED — ${shares.length} share(s) held, quorum is k=${k}; below threshold the secret is information-theoretically absent, not estimable`,
    };
  }

  const use = shares.slice(0, k);
  const secret = new Array(len).fill(0);
  for (let b = 0; b < len; b++) {
    let acc = 0;
    for (let i = 0; i < k; i++) {
      let num = 1;
      let den = 1;
      for (let j = 0; j < k; j++) {
        if (j === i) continue;
        num = mul(num, use[j].x);
        den = mul(den, use[j].x ^ use[i].x); // nonzero: x's are distinct
      }
      acc ^= mul(use[i].bytes[b], mul(num, inv(den)));
    }
    secret[b] = acc;
  }
  return { ok: true, secret };
}
