import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { signJwt, verifyJwt } from '../src/jwt.js';

const SECRET = 'un-secreto-de-pruebas-suficientemente-largo';

test('firma y verifica un token HS256 con iat y exp', () => {
  const token = signJwt({ sub: 'u1' }, SECRET, { expiresIn: 60, now: 1000 });
  const [header] = token.split('.');
  assert.deepEqual(JSON.parse(Buffer.from(header, 'base64url')), { alg: 'HS256', typ: 'JWT' });

  const claims = verifyJwt(token, SECRET, { now: 1030 });
  assert.deepEqual(claims, { sub: 'u1', iat: 1000, exp: 1060 });
});

test('rechaza tokens expirados', () => {
  const token = signJwt({ sub: 'u1' }, SECRET, { expiresIn: 60, now: 1000 });
  assert.throws(() => verifyJwt(token, SECRET, { now: 1060 }), { code: 'TOKEN_EXPIRED' });
  assert.doesNotThrow(() => verifyJwt(token, SECRET, { now: 1065, clockToleranceSec: 10 }));
});

test('rechaza firma alterada o secreto distinto', () => {
  const token = signJwt({ sub: 'u1', role: 'user' }, SECRET);
  const [h, , s] = token.split('.');
  const tampered = `${h}.${Buffer.from(JSON.stringify({ sub: 'u1', role: 'admin' })).toString('base64url')}.${s}`;
  assert.throws(() => verifyJwt(tampered, SECRET), { code: 'INVALID_SIGNATURE' });
  assert.throws(() => verifyJwt(token, 'otro-secreto-distinto-tambien-largo-xx'), { code: 'INVALID_SIGNATURE' });
});

test('rechaza alg "none" y tokens mal formados', () => {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const none = `${enc({ alg: 'none', typ: 'JWT' })}.${enc({ sub: 'u1' })}.`;
  assert.throws(() => verifyJwt(none, SECRET), { code: 'INVALID_ALGORITHM' });
  assert.throws(() => verifyJwt('a.b', SECRET), { code: 'MALFORMED' });
  assert.throws(() => verifyJwt(undefined, SECRET), { code: 'MALFORMED' });
});

test('es compatible con la especificación (firma calculada externamente)', () => {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const data = `${enc({ alg: 'HS256', typ: 'JWT' })}.${enc({ sub: 'ext', exp: 9999999999 })}`;
  const sig = createHmac('sha256', SECRET).update(data).digest('base64url');
  assert.equal(verifyJwt(`${data}.${sig}`, SECRET).sub, 'ext');
});
