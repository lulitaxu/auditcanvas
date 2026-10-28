// Admin password credential (admin design §7).
//
// Only a salted scrypt hash is ever configured, in ADMIN_PASSWORD_HASH,
// in exactly this format:
//
//   scrypt$v=1$N=16384$r=8$p=1$<salt-base64url>$<derived-key-base64url>
//
// The parser is strict on purpose: exact field count, exact version,
// exact v1 parameters, strict base64url, exact salt/key lengths. A
// malformed value is a configuration error (fail closed), never an
// invitation to compare strings. Arbitrary scrypt parameters from the
// environment are NOT honored in v1: unbounded N/r/p would turn a
// configuration mistake into a CPU/memory denial-of-service switch.
import { scryptSync, timingSafeEqual } from 'node:crypto';

export const MAX_PASSWORD_LENGTH = 128;

const SCRYPT_PARAMS = Object.freeze({ N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
const SALT_BYTES = 16;
const KEY_BYTES = 64;
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;

// Test observability (design §21.1): the suite proves an oversized
// password is rejected BEFORE scrypt runs, and that a rate-limited
// login never reaches scrypt, by counting derivations here.
export const passwordInternals = { deriveCount: 0 };

function decodeBase64Url(text, expectedBytes) {
  if (typeof text !== 'string' || !BASE64URL_RE.test(text)) return null;
  let buf;
  try {
    buf = Buffer.from(text, 'base64url');
  } catch {
    return null;
  }
  if (buf.length !== expectedBytes) return null;
  // Reject non-canonical encodings (padding bits set): re-encoding
  // the decoded bytes must reproduce the input exactly.
  if (buf.toString('base64url') !== text) return null;
  return buf;
}

// Returns { salt, key } buffers, or null for ANY deviation from the
// v1 format (including changed N/r/p: those are an unsupported
// configuration, not parameters to honor dynamically).
export function parseAdminPasswordHash(value) {
  if (typeof value !== 'string') return null;
  const parts = value.split('$');
  if (parts.length !== 7) return null;
  const [scheme, version, n, r, p, saltText, keyText] = parts;
  if (scheme !== 'scrypt' || version !== 'v=1') return null;
  if (n !== 'N=16384' || r !== 'r=8' || p !== 'p=1') return null;
  const salt = decodeBase64Url(saltText, SALT_BYTES);
  const key = decodeBase64Url(keyText, KEY_BYTES);
  if (!salt || !key) return null;
  return { salt, key };
}

export function isAdminPasswordHashValid(value) {
  return parseAdminPasswordHash(value) !== null;
}

function deriveKey(password, salt) {
  passwordInternals.deriveCount += 1;
  return scryptSync(password, salt, KEY_BYTES, SCRYPT_PARAMS);
}

// Constant-time verification. Returns false — indistinguishably —
// for a wrong password, an over-long password (rejected before any
// hashing, so an oversized body cannot become a hashing DoS), and a
// malformed configured hash.
export function verifyAdminPassword(password, hashValue) {
  if (typeof password !== 'string') return false;
  if (password.length === 0 || password.length > MAX_PASSWORD_LENGTH) return false;
  const parsed = parseAdminPasswordHash(hashValue);
  if (!parsed) return false;
  let candidate;
  try {
    candidate = deriveKey(password, parsed.salt);
  } catch {
    return false;
  }
  if (candidate.length !== parsed.key.length) return false;
  return timingSafeEqual(candidate, parsed.key);
}
