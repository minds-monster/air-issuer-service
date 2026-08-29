/**
 * Discover a dashboard Schema's metadata from its id.
 *
 * An iden3 credential needs the schema's JSON Schema url, JSON-LD context url
 * and type name. The dashboard shows them, but if the API will hand them over
 * there is no need to copy them by hand — and no chance of a typo in a value
 * that ends up embedded in every credential.
 *
 *   npx tsx scripts/probe-schema.ts <schemaId>
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { importPKCS8, SignJWT } from 'jose';

for (const line of readFileSync(resolve(__dirname, '..', '.env'), 'utf8').split('\n')) {
  const m = /^([A-Z0-9_]+)=(.*)$/.exec(line.trim());
  if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
}

const schemaId = process.argv[2];
if (!schemaId) {
  console.error('usage: probe-schema.ts <schemaId>');
  process.exit(1);
}

const PARTNER_ID = process.env.PARTNER_ID!;

async function partnerJwt(): Promise<string> {
  const key = await importPKCS8(
    `-----BEGIN PRIVATE KEY-----\n${process.env.PARTNER_PRIVATE_KEY_DER}\n-----END PRIVATE KEY-----`,
    process.env.PARTNER_PRIVATE_KEY_ALG ?? 'ES256',
  );
  return new SignJWT({ partnerId: PARTNER_ID, scope: 'issue' })
    .setProtectedHeader({ alg: process.env.PARTNER_PRIVATE_KEY_ALG ?? 'ES256', kid: process.env.PARTNER_PRIVATE_KEY_KID! })
    .setIssuer(process.env.ISSUER_ORIGIN!)
    .setIssuedAt(new Date())
    .setExpirationTime(new Date(Date.now() + 15 * 60_000))
    .sign(key);
}

const HOSTS = [
  'https://credential.api.sandbox.air3.com',
  'https://air.api.sandbox.air3.com',
  'https://api.sandbox.mocachain.org',
];

const PATHS = [
  `/dstorage/download/${schemaId}`,
  `/v1/schemas/${schemaId}`,
  `/v2/schemas/${schemaId}`,
  `/v1/credential-schemas/${schemaId}`,
  `/v1/issuer/schemas/${schemaId}`,
  `/v1/programs/${schemaId}`,
];

async function main() {
  const jwt = await partnerJwt();
  for (const host of HOSTS) {
    for (const path of PATHS) {
      const url = `${host}${path}`;
      try {
        const res = await fetch(url, {
          headers: { 'x-partner-id': PARTNER_ID, 'x-partner-auth': jwt },
          signal: AbortSignal.timeout(10_000),
        });
        const text = await res.text();
        if (res.ok) {
          console.log(`\nOK ${res.status}  ${url}`);
          console.log(text.slice(0, 1200));
        } else if (res.status !== 404) {
          console.log(`-- ${res.status}  ${url}  ${text.slice(0, 120)}`);
        }
      } catch (err) {
        console.log(`ERR       ${url}  ${err instanceof Error ? err.message : err}`);
      }
    }
  }
  console.log('\n(404s suppressed)');
}

void main();
