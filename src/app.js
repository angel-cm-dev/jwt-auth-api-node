import { createServer } from 'node:http';
import { JwtError, signJwt, verifyJwt } from './jwt.js';
import { hashPassword, verifyPassword } from './password.js';
import { toPublicUser, UserStore } from './users.js';

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const MAX_BODY_BYTES = 10 * 1024;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function sendJson(res, status, payload, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  res.end(JSON.stringify(payload));
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new HttpError(413, 'Cuerpo demasiado grande');
    chunks.push(chunk);
  }
  try {
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
    if (typeof body !== 'object' || body === null || Array.isArray(body)) throw new Error();
    return body;
  } catch {
    throw new HttpError(400, 'JSON inválido');
  }
}

function validateCredentials({ email, password }) {
  const errors = {};
  if (typeof email !== 'string' || !EMAIL_PATTERN.test(email)) errors.email = 'Email inválido';
  if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
    errors.password = 'La contraseña debe tener entre 8 y 128 caracteres';
  }
  return errors;
}

/**
 * Crea el servidor de autenticación.
 * @param {{ secret: string, tokenTtl?: number, users?: UserStore, now?: () => number }} options
 */
export function createApp({ secret, tokenTtl = 3600, users = new UserStore(), now }) {
  if (!secret || secret.length < 32) throw new Error('El secreto JWT debe tener al menos 32 caracteres');
  const clock = () => (now ? now() : Math.floor(Date.now() / 1000));

  const issueToken = (user) => ({
    accessToken: signJwt({ sub: user.id, email: user.email }, secret, { expiresIn: tokenTtl, now: clock() }),
    tokenType: 'Bearer',
    expiresIn: tokenTtl,
  });

  /** Middleware: valida el header Authorization y devuelve el usuario autenticado. */
  function authenticate(req) {
    const [scheme, token] = (req.headers.authorization ?? '').split(' ');
    if (scheme !== 'Bearer' || !token) throw new HttpError(401, 'Token requerido');
    try {
      const claims = verifyJwt(token, secret, { now: clock() });
      const user = users.findById(claims.sub);
      if (!user) throw new HttpError(401, 'Usuario no encontrado');
      return { user, claims };
    } catch (err) {
      if (err instanceof JwtError) {
        throw new HttpError(401, err.code === 'TOKEN_EXPIRED' ? 'Token expirado' : 'Token inválido');
      }
      throw err;
    }
  }

  const routes = {
    'POST /auth/register': async (req, res) => {
      const body = await readJson(req);
      const errors = validateCredentials(body);
      if (Object.keys(errors).length) return sendJson(res, 422, { error: 'Datos inválidos', details: errors });
      if (users.findByEmail(body.email)) throw new HttpError(409, 'El email ya está registrado');

      const user = users.create({
        email: body.email,
        name: typeof body.name === 'string' ? body.name.trim().slice(0, 100) : undefined,
        passwordHash: await hashPassword(body.password),
      });
      sendJson(res, 201, { user: toPublicUser(user), ...issueToken(user) });
    },

    'POST /auth/login': async (req, res) => {
      const { email, password } = await readJson(req);
      const user = typeof email === 'string' ? users.findByEmail(email) : null;
      // Mismo mensaje para email inexistente o contraseña incorrecta (evita enumeración de usuarios).
      if (!user || typeof password !== 'string' || !(await verifyPassword(password, user.passwordHash))) {
        throw new HttpError(401, 'Credenciales inválidas');
      }
      sendJson(res, 200, issueToken(user));
    },

    'GET /auth/me': async (req, res) => {
      const { user, claims } = authenticate(req);
      sendJson(res, 200, { user: toPublicUser(user), tokenExpiresAt: new Date(claims.exp * 1000).toISOString() });
    },

    'GET /health': async (_req, res) => sendJson(res, 200, { status: 'ok' }),
  };

  return createServer(async (req, res) => {
    const { pathname } = new URL(req.url, 'http://localhost');
    const handler = routes[`${req.method} ${pathname}`];
    try {
      if (!handler) throw new HttpError(404, 'Ruta no encontrada');
      await handler(req, res);
    } catch (err) {
      const status = err instanceof HttpError ? err.status : 500;
      if (status === 500) console.error(err);
      const headers = status === 401 ? { 'WWW-Authenticate': 'Bearer' } : {};
      sendJson(res, status, { error: status === 500 ? 'Error interno' : err.message }, headers);
    }
  });
}
