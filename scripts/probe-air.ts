/**
 * Probe AIR's partner-authenticated API.
 *
 * Direct Issuance depends on two calls that this service has never actually
 * made — resolving a holder DID and uploading an encrypted VC — and both are
 * authenticated with a Partner JWT signed by the partner key. The docs and this
 * repo disagree about the host, the path version, and the auth header, so rather
 * than guess, this establishes which combination the sandbox accepts.
 *
 *   npx tsx scripts/probe-air.ts <email>
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { importPKCS8, SignJWT } from 'jose';

// Minimal .env reader — pnpm's strict node_modules layout does not expose
// dotenv to a standalone script, and this needs no more than KEY=value.
for (const line of readFileSync(resolve(__dirname, '..', '.env'), 'utf8').split('\n')) {
  const m = /^([A-Z0-9_]+)=(.*)$/.exec(line.trim());
  if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
}

const email = process.argv[2];
if (!email) {
  console.error('usage: probe-air.ts <email>');
  process.exit(1);
}

const PARTNER_ID = process.env.PARTNER_ID!;
const KID = process.env.PARTNER_PRIVATE_KEY_KID!;
const ALG = process.env.PARTNER_PRIVATE_KEY_ALG ?? 'ES256';
const DER = process.env.PARTNER_PRIVATE_KEY_DER!;
const ISSUER_ORIGIN = process.env.ISSUER_ORIGIN!;

async function partnerJwt(claims: Record<string, unknown>): Promise<string> {
  const key = await importPKCS8(
    `-----BEGIN PRIVATE KEY-----\n${DER}\n-----END PRIVATE KEY-----`,
    ALG,
  );
  return new SignJWT({ ...claims, partnerId: PARTNER_ID })
    .setProtectedHeader({ alg: ALG, kid: KID })
    .setIssuer(ISSUER_ORIGIN)
    .setIssuedAt(new Date())
    .setExpirationTime(new Date(Date.now() + 15 * 60_000))
    .sign(key);
}

/** Every plausible (host, path, header, body) combination, so one run settles it. */
const CANDIDATES = [
  { label: 'mocachain /v1 + x-partner-auth + {email}', url: 'https://api.sandbox.mocachain.org/v1/auth/initialize-user', header: 'x-partner-auth', body: (jwt: string) => ({ email }), authIsJwt: true },
  { label: 'air3 /v2 + x-partner-id + {partnerJwt}', url: 'https://air.api.sandbox.air3.com/v2/auth/initialize-user', header: 'x-partner-id', body: (jwt: string) => ({ partnerJwt: jwt }), authIsJwt: false },
  { label: 'air3 /v1 + x-partner-auth + {email}', url: 'https://air.api.sandbox.air3.com/v1/auth/initialize-user', header: 'x-partner-auth', body: () => ({ email }), authIsJwt: true },
  { label: 'mocachain /v1 + x-partner-id + {partnerJwt}', url: 'https://api.sandbox.mocachain.org/v1/auth/initialize-user', header: 'x-partner-id', body: (jwt: string) => ({ partnerJwt: jwt }), authIsJwt: false },
];

async function main() {
console.log(`partner ${PARTNER_ID}`);
console.log(`kid     ${KID} (${ALG})`);
console.log(`iss     ${ISSUER_ORIGIN}`);
console.log(`email   ${email}\n`);

for (const c of CANDIDATES) {
  // scope: 'issue' is what the docs specify for issuance-scoped partner tokens.
  const jwt = await partnerJwt({ email, scope: 'issue' });
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  headers[c.header] = c.authIsJwt ? jwt : PARTNER_ID;
  // Send both when the primary header carries only the id, mirroring the runner.
  if (!c.authIsJwt) headers['x-partner-auth'] = jwt;

  try {
    const res = await fetch(c.url, {
      method: 'POST',
      headers,
      body: JSON.stringify(c.body(jwt)),
      signal: AbortSignal.timeout(15_000),
    });
    const text = await res.text();
    console.log(`${res.ok ? 'OK  ' : 'FAIL'} ${res.status}  ${c.label}`);
    console.log(`       ${text.slice(0, 240)}`);
  } catch (err) {
    console.log(`ERR       ${c.label}`);
    console.log(`       ${err instanceof Error ? err.message : err}`);
  }
}
}

void main();
