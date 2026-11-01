# jwt-auth-api-node

API de autenticación en Node.js **sin dependencias**: registro, login con `crypto.scrypt` y JWT HS256 implementado desde cero con `node:crypto`.

![Node.js](https://img.shields.io/badge/Node.js-%3E%3D20.12-339933?logo=node.js&logoColor=white)
![Dependencias](https://img.shields.io/badge/dependencias-0-brightgreen)
![Licencia MIT](https://img.shields.io/badge/licencia-MIT-blue.svg)
[![CI](https://github.com/angel-cm-dev/jwt-auth-api-node/actions/workflows/ci.yml/badge.svg)](https://github.com/angel-cm-dev/jwt-auth-api-node/actions/workflows/ci.yml)

## Características

- Registro y login con validación de email y longitud de contraseña.
- Hash de contraseñas con **scrypt** (N=2^15, r=8, p=1), sal aleatoria por usuario y comparación en tiempo constante.
- **JWT HS256** propio: firma HMAC-SHA256, claims `iat`/`exp`, tolerancia de reloj opcional y algoritmo fijado (bloquea `alg: none`).
- Ruta protegida `GET /auth/me` con `Authorization: Bearer <token>`.
- Expiración configurable (`JWT_TTL_SECONDS`) y mensaje explícito de token expirado.
- Mismo error para usuario inexistente y contraseña incorrecta (evita enumeración de cuentas).
- Nunca expone `passwordHash`; exige secreto JWT de al menos 32 caracteres.

## Requisitos

- Node.js 20.12 o superior (probado con Node 24).

## Instalación y uso

```bash
git clone https://github.com/angel-cm-dev/jwt-auth-api-node.git
cd jwt-auth-api-node
cp .env.example .env
# genera un secreto y pégalo en JWT_SECRET
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
npm start
```

### Endpoints

| Método | Ruta             | Auth   | Descripción                              |
|--------|------------------|--------|------------------------------------------|
| `POST` | `/auth/register` | —      | `{ email, password, name? }` → usuario + token |
| `POST` | `/auth/login`    | —      | `{ email, password }` → token            |
| `GET`  | `/auth/me`       | Bearer | Perfil del usuario autenticado           |
| `GET`  | `/health`        | —      | Estado del servicio                      |

> Los usuarios se guardan en memoria (`UserStore`); para producción basta con implementar la misma interfaz sobre una base de datos.

## Ejemplo

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"angel@ejemplo.pe","password":"ClaveSegura123"}'
```

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI...",
  "tokenType": "Bearer",
  "expiresIn": 3600
}
```

```bash
curl http://localhost:3000/auth/me -H "Authorization: Bearer <accessToken>"
```

```json
{
  "user": { "id": "4f1c...", "email": "angel@ejemplo.pe", "name": "Angel", "createdAt": "2026-11-01T15:20:00.000Z" },
  "tokenExpiresAt": "2026-11-01T16:20:00.000Z"
}
```

Con un token vencido la respuesta es `401 {"error":"Token expirado"}`.

## Estructura del proyecto

```
jwt-auth-api-node/
├── src/
│   ├── app.js        # Rutas, validación y middleware de autenticación
│   ├── jwt.js        # signJwt / verifyJwt (HS256)
│   ├── password.js   # hashPassword / verifyPassword (scrypt)
│   ├── users.js      # Repositorio de usuarios en memoria
│   └── index.js      # Punto de entrada
├── test/             # Pruebas node:test
├── .env.example
└── .github/workflows/ci.yml
```

## Pruebas

```bash
npm test
```

Incluye pruebas de manipulación de payload, `alg: none`, secreto incorrecto, expiración con reloj controlado y flujo completo registro → login → ruta protegida.

## Roadmap

- [ ] Refresh tokens con rotación y revocación.
- [ ] Rate limiting en `/auth/login`.
- [ ] Persistencia en SQLite/PostgreSQL.

## Licencia y autor

Distribuido bajo licencia [MIT](LICENSE).

Desarrollado por **Angel Castañeda Meza** — Ingeniero de Sistemas, Lima, Perú · [github.com/angel-cm-dev](https://github.com/angel-cm-dev)
