import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(scrypt);

// Parámetros recomendados por OWASP para scrypt (N=2^15, r=8, p=1).
const DEFAULTS = { N: 32768, r: 8, p: 1, keyLength: 64 };
const maxmem = (N, r) => 128 * N * r * 2;

/**
 * Genera un hash con formato: scrypt$N$r$p$salt$hash (base64url).
 * @param {string} password
 */
export async function hashPassword(password, { N, r, p, keyLength } = DEFAULTS) {
  const salt = randomBytes(16);
  const key = await scryptAsync(password, salt, keyLength, { N, r, p, maxmem: maxmem(N, r) });
  return ['scrypt', N, r, p, salt.toString('base64url'), key.toString('base64url')].join('$');
}

/**
 * Verifica una contraseña contra un hash generado por hashPassword.
 * @returns {Promise<boolean>}
 */
export async function verifyPassword(password, stored) {
  const parts = typeof stored === 'string' ? stored.split('$') : [];
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;

  const [, n, r, p, saltB64, hashB64] = parts;
  const N = Number(n);
  const R = Number(r);
  const expected = Buffer.from(hashB64, 'base64url');
  const key = await scryptAsync(password, Buffer.from(saltB64, 'base64url'), expected.length, {
    N,
    r: R,
    p: Number(p),
    maxmem: maxmem(N, R),
  });
  return timingSafeEqual(key, expected);
}
