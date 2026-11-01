import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.js';

const SECRET = 'secreto-de-pruebas-con-mas-de-32-caracteres';

describe('API de autenticación', () => {
  let server;
  let base;
  let clock = 1_800_000_000; // reloj controlado para probar la expiración

  before(async () => {
    server = createApp({ secret: SECRET, tokenTtl: 900, now: () => clock });
    await new Promise((resolve) => server.listen(0, resolve));
    base = `http://127.0.0.1:${server.address().port}`;
  });

  after(() => new Promise((resolve) => server.close(resolve)));

  const post = (path, body) =>
    fetch(`${base}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const me = (token) => fetch(`${base}/auth/me`, { headers: token ? { Authorization: `Bearer ${token}` } : {} });

  const credentials = { email: 'Angel@Ejemplo.pe', password: 'ClaveSegura123', name: 'Angel' };
  let token;

  test('registra un usuario y devuelve token sin exponer el hash', async () => {
    const res = await post('/auth/register', credentials);
    assert.equal(res.status, 201);
    const body = await res.json();
    assert.equal(body.user.email, 'angel@ejemplo.pe');
    assert.equal(body.user.passwordHash, undefined);
    assert.equal(body.tokenType, 'Bearer');
    assert.equal(body.expiresIn, 900);
  });

  test('valida datos de registro y evita duplicados', async () => {
    const invalid = await post('/auth/register', { email: 'no-es-email', password: '123' });
    assert.equal(invalid.status, 422);
    assert.deepEqual(Object.keys((await invalid.json()).details).sort(), ['email', 'password']);
    assert.equal((await post('/auth/register', credentials)).status, 409);
  });

  test('login con credenciales correctas devuelve un JWT', async () => {
    const res = await post('/auth/login', { email: 'angel@ejemplo.pe', password: credentials.password });
    assert.equal(res.status, 200);
    ({ accessToken: token } = await res.json());
    assert.equal(token.split('.').length, 3);
  });

  test('login falla con contraseña incorrecta o usuario inexistente', async () => {
    const wrong = await post('/auth/login', { email: credentials.email, password: 'otraClave999' });
    const missing = await post('/auth/login', { email: 'nadie@ejemplo.pe', password: 'otraClave999' });
    assert.equal(wrong.status, 401);
    assert.equal(missing.status, 401);
    assert.deepEqual(await wrong.json(), await missing.json());
  });

  test('la ruta protegida exige un token válido', async () => {
    assert.equal((await me()).status, 401);
    assert.equal((await me('token.no.valido')).status, 401);

    const res = await me(token);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.user.name, 'Angel');
    assert.equal(body.tokenExpiresAt, new Date((clock + 900) * 1000).toISOString());
  });

  test('el token expira tras el TTL configurado', async () => {
    clock += 901;
    const res = await me(token);
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error, 'Token expirado');
  });

  test('rechaza un secreto JWT demasiado corto', () => {
    assert.throws(() => createApp({ secret: 'corto' }), /32 caracteres/);
  });
});
