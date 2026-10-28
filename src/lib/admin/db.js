// Admin storage adapter (admin design §11): the ONLY door to the
// dedicated AuditCanvas Neon database.
//
// - Server-side code only. No client component imports this module.
// - One narrow interface: query(text, params) and tx([...]) with
//   $1, $2, ... placeholders for every value. Application code never
//   builds SQL by embedding values in template strings; the only
//   dynamic SQL anywhere in src/lib/admin comes from fixed fragments
//   selected through server-side allowlists.
// - The connection string is read only from
//   AUDITCANVAS_DATABASE_URL, only at call time.
// - Driver errors are wrapped in typed errors whose messages are
//   fixed strings. A driver error can embed the database host, SQL
//   text, or parameter values; none of that may reach a response, an
//   audit event, or a log line produced by this app, so the original
//   error is deliberately dropped after classification.
import { neon } from '@neondatabase/serverless';

export class AdminStoreUnavailable extends Error {
  constructor(message = 'Admin storage unavailable.') {
    super(message);
    this.name = 'AdminStoreUnavailable';
    this.code = 'store_unavailable';
  }
}

export class AdminStoreError extends Error {
  constructor(message = 'Admin storage error.') {
    super(message);
    this.name = 'AdminStoreError';
    this.code = 'store_error';
  }
}

function wrapDriverError(err) {
  if (err instanceof AdminStoreUnavailable || err instanceof AdminStoreError) return err;
  // Any failure talking to Neon (network, auth, missing database,
  // cold start) is an availability failure from the caller's point of
  // view: admin paths fail closed with 503, never with a fallback.
  return new AdminStoreUnavailable();
}

function makeDb(sql) {
  return {
    // One parameterized statement; resolves to the rows array
    // (empty for statements without RETURNING).
    async query(text, params = []) {
      try {
        return await sql.query(text, params);
      } catch (err) {
        throw wrapDriverError(err);
      }
    },
    // One non-interactive transaction: items = [{ text, params }].
    // Resolves to one rows array per statement, in order.
    async tx(items) {
      try {
        const built = items.map(({ text, params = [] }) => sql.query(text, params));
        return await sql.transaction(built);
      } catch (err) {
        throw wrapDriverError(err);
      }
    },
  };
}

let testOverride = null;
let cached = null; // { url, db }

export function getAdminDb() {
  if (testOverride) return testOverride;
  const url = process.env.AUDITCANVAS_DATABASE_URL;
  if (typeof url !== 'string' || url.length === 0) {
    throw new AdminStoreUnavailable('Admin storage is not configured.');
  }
  if (!cached || cached.url !== url) {
    cached = { url, db: makeDb(neon(url)) };
  }
  return cached.db;
}

// Test seam (admin design §21): scripts/verify-admin.mjs installs a
// fake adapter that records SQL text, parameters, and transaction
// groupings. Production code never calls this.
export function setAdminDbForTests(db) {
  testOverride = db || null;
}

// Value normalization at the storage boundary (design §11.1): the
// Neon driver returns timestamptz as Date objects and numeric as
// strings; everything downstream (React props, JSON, comparisons)
// works with ISO strings and numbers.
export function toIso(value) {
  if (value == null) return null;
  if (value instanceof Date) return value.toISOString();
  if (typeof value === 'string') {
    const t = Date.parse(value);
    return Number.isNaN(t) ? value : new Date(t).toISOString();
  }
  return null;
}

export function toNum(value) {
  if (value == null) return null;
  const n = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(n) ? n : null;
}

export function toIsoOrNull(value) {
  return value == null ? null : toIso(value);
}
