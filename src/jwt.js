import { createHmac, timingSafeEqual } from 'node:crypto';

export class JwtError extends Error {
  /** @param {'MALFORMED'|'INVALID_ALGORITHM'|'INVALID_SIGNATURE'|'TOKEN_EXPIRED'|'TOKEN_NOT_ACTIVE'} code */
  constructor(code, message) {
    super(message);
    this.name = 'JwtError';
    this.code = code;
  }
}

const encode = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
const nowSeconds = () => Math.floor(Date.now() / 1000);

function hmac(data, secret) {
  return createHmac('sha256', secret).update(data).digest('base64url');
}

/**
 * Firma un JWT con HS256.
 * @param {object} payload claims personalizados (p. ej. { sub, email })
 * @param {string} secret
 * @param {{ expiresIn?: number, now?: number }} [options] expiresIn en segundos
 */
export function signJwt(payload, secret, { expiresIn = 3600, now = nowSeconds() } = {}) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const claims = { ...payload, iat: now, exp: now + expiresIn };
  const data = `${encode(header)}.${encode(claims)}`;
  return `${data}.${hmac(data, secret)}`;
}

/**
 * Verifica firma, algoritmo y vigencia de un JWT HS256.
 * @returns {object} claims del token
 * @throws {JwtError}
 */
export function verifyJwt(token, secret, { now = nowSeconds(), clockToleranceSec = 0 } = {}) {
  if (typeof token !== 'string') throw new JwtError('MALFORMED', 'Token ausente');
  const parts = token.split('.');
  if (parts.length !== 3) throw new JwtError('MALFORMED', 'Formato de token inválido');

  const [headerB64, payloadB64, signature] = parts;
  let header;
  let claims;
  try {
    header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));
    claims = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  } catch {
    throw new JwtError('MALFORMED', 'Token no decodificable');
  }

  // Se fija el algoritmo para evitar ataques "alg: none" o confusión de algoritmos.
  if (header?.alg !== 'HS256') throw new JwtError('INVALID_ALGORITHM', 'Algoritmo no soportado');

  const expected = Buffer.from(hmac(`${headerB64}.${payloadB64}`, secret));
  const received = Buffer.from(signature);
  if (expected.length !== received.length || !timingSafeEqual(expected, received)) {
    throw new JwtError('INVALID_SIGNATURE', 'Firma inválida');
  }

  if (typeof claims.exp === 'number' && now >= claims.exp + clockToleranceSec) {
    throw new JwtError('TOKEN_EXPIRED', 'Token expirado');
  }
  if (typeof claims.nbf === 'number' && now + clockToleranceSec < claims.nbf) {
    throw new JwtError('TOKEN_NOT_ACTIVE', 'Token aún no válido');
  }
  return claims;
}
