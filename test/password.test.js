import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hashPassword, verifyPassword } from '../src/password.js';

test('hashPassword genera un hash con sal única', async () => {
  const a = await hashPassword('ClaveSegura123');
  const b = await hashPassword('ClaveSegura123');
  assert.match(a, /^scrypt\$32768\$8\$1\$[\w-]+\$[\w-]+$/);
  assert.notEqual(a, b);
});

test('verifyPassword valida la contraseña correcta y rechaza la incorrecta', async () => {
  const hash = await hashPassword('ClaveSegura123');
  assert.equal(await verifyPassword('ClaveSegura123', hash), true);
  assert.equal(await verifyPassword('clavesegura123', hash), false);
});

test('verifyPassword rechaza hashes mal formados', async () => {
  assert.equal(await verifyPassword('x', 'texto-plano'), false);
  assert.equal(await verifyPassword('x', null), false);
});
