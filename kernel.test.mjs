import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as K from './kernel.mjs';

test('field ops pinned: FIPS-197 example 0x57*0x83 = 0xC1, inv(3) = 246, inv(0) refused', () => {
  assert.equal(K.gfMul(0x57, 0x83).value, 193); // 0xC1
  assert.equal(K.gfInv(3).value, 246); // 0xF6
  assert.equal(K.gfInv(0).ok, false);
  assert.equal(K.gfMul(256, 1).ok, false);
});

test('byte boundaries pinned: 0 and 255 ARE bytes — gfMul accepts them, and they round-trip as secret bytes', () => {
  // kills line 13 `>= -> >` (0 must be in) and `<= -> <` (255 must be in)
  assert.deepEqual(K.gfMul(0, 1), { ok: true, value: 0 });
  assert.deepEqual(K.gfMul(255, 1), { ok: true, value: 255 });
  const r = K.split([0, 255], 2, 2, [1, 1]); // f0(x) = 0 XOR x, f1(x) = 255 XOR x
  assert.equal(r.ok, true);
  assert.deepEqual(r.shares[0].bytes, [1, 254]);
  assert.deepEqual(r.shares[1].bytes, [2, 253]);
  assert.deepEqual(K.join(r.shares).secret, [0, 255]);
});

test('n boundary pinned: n=255 accepted (255 shares, share x=255 -> 248, joins back), 256 and 2.5 refused, n=1 refused BY NAME', () => {
  // kills line 73 `> -> >=` (255 must be in) and both line-73 `|| -> &&` mutants
  const r = K.split([7], 255, 2, [1]); // f(x) = 7 XOR x
  assert.equal(r.ok, true);
  assert.equal(r.shares.length, 255);
  assert.deepEqual(r.shares[254], { x: 255, k: 2, bytes: [248] });
  assert.deepEqual(K.join([r.shares[253], r.shares[254]]).secret, [7]);
  assert.equal(K.split([7], 256, 2, [1]).ok, false);
  assert.equal(K.split([7], 2.5, 2, [1]).ok, false); // non-integer n must die at the n-check
  const low = K.split([7], 1, 2, [1]);
  assert.equal(low.ok, false);
  assert.match(low.why, /n must be an integer 2\.\.255/); // the n-check refuses it, not the k-check
});

test('k guard pinned: k=1 refused by name, non-integer k refused, k>n refused', () => {
  // kills line 76 `|| -> &&` mutants (either operand)
  const one = K.split([5], 3, 1, []);
  assert.equal(one.ok, false);
  assert.match(one.why, /k must be an integer 2\.\.n/);
  assert.equal(K.split([1, 2], 3, 2.5, [9, 9, 9]).ok, false); // (k-1)*len = 3 would slip past entropy check
  assert.equal(K.split([5], 2, 3, [1, 1]).ok, false); // quorum larger than the share count
});

test('empty secret refused by name — never silently split into empty shares', () => {
  // kills line 70 `|| -> &&`: [] is a valid byte-array, so only the length arm catches it
  const r = K.split([], 3, 2, []);
  assert.equal(r.ok, false);
  assert.match(r.why, /secret must be a non-empty array/);
});

test('share shape || chains: EACH arm must fire alone — null, non-object, x=0, k=1, empty bytes all refused BY NAME, never joined, never thrown', () => {
  const SHAPE = /each share must be \{x:1\.\.255, k:int>=2, bytes:\[bytes\]\}/;

  // line 121 `|| -> &&`, null arm: typeof null === 'object', so ONLY `s === null` catches it.
  // Under the mutant the pair goes false and `null.x` is read next — a throw. Must return, not throw.
  const withNull = K.join([{ x: 1, k: 2, bytes: [45] }, null]);
  assert.equal(withNull.ok, false);
  assert.match(withNull.why, SHAPE);

  // line 121 `|| -> &&`, typeof arm: a FUNCTION carrying valid share fields — s !== null, so ONLY
  // the typeof check catches it. Two of them carry the real 42-shares: the mutant would happily
  // reconstruct 42 from non-object shares.
  const f1 = Object.assign(() => {}, { x: 1, k: 2, bytes: [45] });
  const f2 = Object.assign(() => {}, { x: 2, k: 2, bytes: [36] });
  const funcs = K.join([f1, f2]);
  assert.equal(funcs.ok, false);
  assert.match(funcs.why, SHAPE);

  // line 122 `|| -> &&`: x=0 IS a byte, so ONLY `s.x < 1` catches it — and x=0 is the secret's
  // own evaluation point; a share claiming it must die at the shape check, with a full quorum held.
  const xZero = K.join([{ x: 0, k: 2, bytes: [42] }, { x: 1, k: 2, bytes: [45] }]);
  assert.equal(xZero.ok, false);
  assert.match(xZero.why, SHAPE);

  // line 123 `|| -> &&`: k=1 IS an integer, so ONLY `s.k < 2` catches it. The mutant would sail
  // to the quorum check with k=1, satisfy it with ONE share, and "reconstruct" — a quorum of one.
  const kOne = K.join([{ x: 1, k: 1, bytes: [45] }]);
  assert.equal(kOne.ok, false);
  assert.match(kOne.why, SHAPE);

  // line 124 `|| -> &&`: [] IS a valid byte-array, so ONLY `bytes.length < 1` catches it. The
  // mutant would join two empty shares into an empty "secret" — ok:true over nothing.
  const empty = K.join([{ x: 1, k: 2, bytes: [] }, { x: 2, k: 2, bytes: [] }]);
  assert.equal(empty.ok, false);
  assert.match(empty.why, SHAPE);
});

test('one share held: refused with the QUORUM message, not the array-shape message', () => {
  // kills line 116 `< -> <=`: a single share must pass the shape check and die at the threshold
  const r = K.join([{ x: 1, k: 2, bytes: [45] }]);
  assert.equal(r.ok, false);
  assert.match(r.why, /REFUSED/);
  assert.match(r.why, /quorum is k=2/);
});

test('split pinned: secret [42], 3-of-2 quorum, entropy [7] -> ys 45, 36, 35', () => {
  const r = K.split([42], 3, 2, [7]); // f(x) = 42 XOR 7x
  assert.equal(r.ok, true);
  assert.deepEqual(r.shares.map((s) => s.x), [1, 2, 3]);
  assert.deepEqual(r.shares.map((s) => s.bytes[0]), [45, 36, 35]);
  assert.deepEqual(r.shares.map((s) => s.k), [2, 2, 2]);
});

test('join pinned: any 2 of the 3 shares reconstruct 42', () => {
  const a = K.join([{ x: 1, k: 2, bytes: [45] }, { x: 2, k: 2, bytes: [36] }]);
  const b = K.join([{ x: 2, k: 2, bytes: [36] }, { x: 3, k: 2, bytes: [35] }]);
  assert.deepEqual(a.secret, [42]);
  assert.deepEqual(b.secret, [42]);
});

test('k=3 pinned: secret [200] entropy [1,2] -> ys 203, 194, 193; join all 3 -> 200; 2 shares REFUSED', () => {
  const r = K.split([200], 3, 3, [1, 2]); // f(x) = 200 XOR x XOR 2x^2
  assert.deepEqual(r.shares.map((s) => s.bytes[0]), [203, 194, 193]);
  const full = K.join(r.shares);
  assert.deepEqual(full.secret, [200]);
  const below = K.join(r.shares.slice(0, 2)); // 2 < k=3
  assert.equal(below.ok, false);
  assert.match(below.why, /REFUSED/);
});

test('multi-byte pinned: secret [1,2], 2-of-2, entropy [3,4] -> shares [2,6],[7,10]; round-trip', () => {
  const r = K.split([1, 2], 2, 2, [3, 4]);
  assert.deepEqual(r.shares[0].bytes, [2, 6]);
  assert.deepEqual(r.shares[1].bytes, [7, 10]);
  assert.deepEqual(K.join(r.shares).secret, [1, 2]);
});

test('total on garbage: wrong entropy length, duplicate x, mismatched k all return ok:false, never throw', () => {
  assert.equal(K.split([1, 2], 3, 3, [9]).ok, false); // needs 4 entropy bytes, got 1
  assert.equal(K.split('secret', 3, 2, [1]).ok, false);
  assert.equal(K.join([{ x: 1, k: 2, bytes: [5] }, { x: 1, k: 2, bytes: [6] }]).ok, false); // dup x
  assert.equal(K.join([{ x: 1, k: 2, bytes: [5] }, { x: 2, k: 3, bytes: [6] }]).ok, false); // k mismatch
  assert.equal(K.join([]).ok, false);
});
