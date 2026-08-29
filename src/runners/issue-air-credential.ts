/**
 * Issue the dashboard-registered XDataAccess credential to a Mind's AIR account.
 *
 * This is AIR Direct Issuance, end to end: resolve the holder's DID, sign a W3C VC with
 * the issuer's iden3 key, encrypt it to the holder's public key, and upload the envelope
 * to Moca DStorage. Verified working against sandbox.
 *
 * What this credential is FOR: a network-recognised record that a Mind was granted vault
 * access, verifiable by anyone through the AIR verifier widget using Program
 * c29c50g0ltcs48yud0n1a2. It is NOT what the Mind presents at request time — it lands
 * encrypted in DStorage and can only be decrypted and proven inside the AIR browser
 * wallet, which a headless agent cannot run. The runtime credential is the SD-JWT-VC from
 * `POST /admin/issue-sd-jwt`.
 *
 * Usage (from the repo root, after `npm run build`):
 *   RUNNER=true node dist/runners/issue-air-credential.js \
 *     --email <holder email> --mind <mind id> --scopes "tweets.read" [--label "..."] [--dry-run]
 *
 * The npm script routes through the Nest CLI and needs a second `--` to get past it
 * (`npm run issue-air-credential -- -- --email ...`), which also recompiles every run.
 * Running the built output directly is faster and passes args normally.
 */
import { EntityManager } from '@mikro-orm/postgresql';
import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { HttpService } from '@nestjs/axios';

import { AppModule } from '../app.module';
import { AIR_API } from '../common/api-origin-dictionary';
import { encryptText } from '../common/utils/encryption';
import { hexStrToBuffer } from '../common/utils/string';
import { CredentialIssuingService } from '../iden3/services/credential-issuing.service';
import { DStorageAPIService } from '../dstorage/services/dstorage-api.service';
import { PartnerJwtService } from '../services/partner-jwt.service';
import SchemaXDataAccess from '../issuer/schemas/schema-01KZ91Q7HRK18J1M08S1KP';

interface InitializeUserResponse {
  userId?: string;
  did?: string;
  publicKey?: string;
  status?: string;
}

function opt(name: string): string | undefined {
  const argv = process.argv.slice(2);
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : undefined;
}

async function main() {
  const email = opt('email');
  const mindId = opt('mind');
  const scopes = opt('scopes');
  const label = opt('label') ?? mindId;
  const dryRun = process.argv.includes('--dry-run');

  if (!email || !mindId || !scopes) {
    console.error(
      'Usage: --email <holder email> --mind <mind id> --scopes "tweets.read [more]" ' +
        '[--label "..."] [--dry-run]',
    );
    process.exit(2);
  }

  const app = await NestFactory.create(AppModule, { logger: ['error', 'warn'] });
  await app.init();

  const configService = app.get(ConfigService);
  const axiosRef = app.get(HttpService).axiosRef;
  const credentialIssuingService = app.get(CredentialIssuingService);
  const dStorageApiService = app.get(DStorageAPIService);
  const partnerJwtService = app.get(PartnerJwtService);
  const entityManager = app.get(EntityManager);

  const nodeEnv = configService.getOrThrow<string>('NODE_ENV');
  const partnerId = configService.getOrThrow<string>('PARTNER_ID');
  const airApiOrigin = AIR_API[nodeEnv];
  if (!airApiOrigin) throw new Error(`Invalid NODE_ENV: ${nodeEnv}`);

  // 1. Resolve (or create) the holder's AIR account.
  //
  // The shape below is the one the sandbox actually accepts: /v2, the partner JWT in the
  // BODY, and the partner id in the x-partner-id header. The published docs describe /v1
  // with {email} and an x-partner-auth header, which 404s here.
  const partnerJwt = await partnerJwtService.generateJwt({ email }, {});
  const identity = await axiosRef
    .post<InitializeUserResponse>(
      `${airApiOrigin}/v2/auth/initialize-user`,
      { partnerJwt },
      { headers: { 'x-partner-id': partnerId } },
    )
    .then((r) => r.data);

  if (!identity.did || !identity.publicKey) {
    throw new Error(`Could not resolve an AIR account for ${email}: ${JSON.stringify(identity)}`);
  }
  console.log(`holder    ${identity.did}`);
  console.log(`status    ${identity.status ?? 'unknown'}`);

  // 2. Build the credential. Claims live on the schema instance because the iden3
  //    BaseSchema passes only a userId through to generateCredentialData.
  const instance = new SchemaXDataAccess();
  instance.pending = {
    mindId,
    // Space-delimited: the registered JSON-LD context types `scopes` as xsd:string.
    scopes: scopes.trim().split(/[\s,]+/).filter(Boolean).join(' '),
    audience: 'adam-id',
    label: label ?? mindId,
  };

  const { credentialSubject, expiration } = await instance.generateCredentialData(email);
  console.log(`claims    ${JSON.stringify(credentialSubject)}`);
  console.log(`expires   ${new Date(expiration * 1000).toISOString()}`);

  if (dryRun) {
    console.log('\n--dry-run: nothing signed, nothing uploaded.');
    await app.close();
    return;
  }

  // Go through BaseSchema.issue rather than calling the issuing service directly: it
  // also builds the CredentialIssuance row, which is what /admin/issuance-history and
  // the expiry/revocation bookkeeping read. Calling the service alone yields a valid
  // credential with no record that it was ever issued.
  const { credential, credentialIssuance } = await instance.issue(email, {
    holderDID: identity.did,
    issuingService: credentialIssuingService,
  });
  await entityManager.persist(credentialIssuance).flush();

  console.log(`credential ${credential.id}`);
  console.log(`nonce      ${credential.credentialStatus.revocationNonce}`);

  // 3. Encrypt to the holder and hand the envelope to DStorage. The issuer keeps no
  //    plaintext copy — only the holder can open it, which is the point.
  const encrypted = await encryptText(
    JSON.stringify(credential),
    hexStrToBuffer(identity.publicKey),
    { encoding: 'base64' },
  );

  const encryptedStored = await dStorageApiService.createObject(
    {
      holderDid: identity.did,
      schemaId: instance.schemaId,
      expiresAt: new Date(expiration * 1000).toISOString(),
      data: encrypted.encryptedData,
      iv: encrypted.iv,
      authTag: encrypted.authTag,
      encryptedKey: encrypted.dataEncPublicKey,
      externalId: credential.id,
    },
    { 'x-partner-auth': partnerJwt },
  );

  // Record where it landed, so history reflects a completed issuance rather than one
  // that got as far as signing.
  credentialIssuance.dstorageInfo = encryptedStored.data;
  await entityManager.persist(credentialIssuance).flush();

  console.log(`dstorage   ${encryptedStored.data.storagePath}`);
  console.log('\nissued. Verify with AIR Program c29c50g0ltcs48yud0n1a2 in a browser.');

  await app.close();
}

main().catch((err: unknown) => {
  const e = err as { response?: { data?: unknown }; message?: string };
  console.error(`\nfailed: ${e.message ?? String(err)}`);
  if (e.response?.data) console.error(JSON.stringify(e.response.data, null, 2));
  process.exit(1);
});
