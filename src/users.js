import { randomUUID } from 'node:crypto';

/** Repositorio de usuarios en memoria (reemplazable por una base de datos). */
export class UserStore {
  #byEmail = new Map();

  findByEmail(email) {
    return this.#byEmail.get(email.toLowerCase()) ?? null;
  }

  findById(id) {
    for (const user of this.#byEmail.values()) if (user.id === id) return user;
    return null;
  }

  create({ email, name, passwordHash }) {
    const user = { id: randomUUID(), email: email.toLowerCase(), name, passwordHash, createdAt: new Date().toISOString() };
    this.#byEmail.set(user.email, user);
    return user;
  }
}

/** Devuelve el usuario sin campos sensibles. */
export const toPublicUser = ({ passwordHash, ...rest }) => rest;
