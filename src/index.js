import { createApp } from './app.js';

try {
  process.loadEnvFile('.env');
} catch (err) {
  if (err.code !== 'ENOENT') throw err;
}

const PORT = Number(process.env.PORT ?? 3000);
const server = createApp({
  secret: process.env.JWT_SECRET,
  tokenTtl: Number(process.env.JWT_TTL_SECONDS ?? 3600),
});

server.listen(PORT, () => console.log(`API de autenticación en http://localhost:${PORT}`));

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
