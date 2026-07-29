// Injection benchmark fixture — SQL injection (VULNERABLE).
// Each `EXPECT` comment marks a line the taint layer must flag (injection_risk).
// Stack shapes: postgres `.unsafe`, Prisma raw, Drizzle `.raw`, knex.raw, and a
// request-source → raw-query taint flow.

import { sql } from "./db";
import { prisma } from "./prisma";
import knex from "./knex";

// case: postgres template-literal interpolation into an unsafe query
export async function getUser(id: string) {
  return sql.unsafe(`SELECT * FROM users WHERE id = ${id}`); // EXPECT sqli
}

// case: string concatenation into an unsafe query
export async function search(term: string) {
  return sql.unsafe("SELECT * FROM items WHERE name LIKE '%" + term + "%'"); // EXPECT sqli
}

// case: Prisma raw-unsafe with interpolation
export async function prismaLookup(email: string) {
  return prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${email}'`); // EXPECT sqli
}

// case: knex.raw with interpolation
export async function knexLookup(role: string) {
  return knex.raw(`SELECT * FROM users WHERE role = '${role}'`); // EXPECT sqli
}

// case: request source (searchParams) flows into a raw query (taint)
export async function handler(req: Request) {
  const url = new URL(req.url);
  const name = url.searchParams.get("name");
  return sql.unsafe(`SELECT * FROM accounts WHERE name = '${name}'`); // EXPECT sqli
}
