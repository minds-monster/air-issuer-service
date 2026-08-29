import { MerklizedRootPosition } from '@mocanetwork/identity-js-sdk';
import { HttpService } from '@nestjs/axios';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { parse, stringify } from 'csv/sync';
import fs from 'fs';
import _ from 'lodash';

import { AppModule } from '../app.module';

import { DStorageAPIService } from '../dstorage/services/dstorage-api.service';
import { CredentialIssuingService } from '../iden3/services/credential-issuing.service';
import { PartnerJwtService } from '../services/partner-jwt.service';

import { AIR_API } from '../common/api-origin-dictionary';
import { encryptText } from '../common/utils/encryption';
import { hexStrToBuffer } from '../common/utils/string';
import { ProofType } from '../issuer/enums/proof-type.enum';

type CredentialType = {
  id: string;
  url: string;
  type: string;
};

type InitializeUserResponse = {
  userId: string | null;
  did: string | null;
  publicKey: string | null;
  status: string | null;
};

type BatchIssueVcItem = {
  credentialSubject: { id: string } & Record<any, any>;
  email: string;
  expiration: number;
};

async function batchIssueVcCsv({ id, url, type }: CredentialType, items: BatchIssueVcItem[]) {
  const result: string[][] = [];

  if (items.length === 0) {
    console.info('No records to be imported.');
    return [];
  }

  const app = await NestFactory.create(AppModule);
  await app.init();

  const credentialIssuingService = app.get(CredentialIssuingService);
  const axiosRef = app.get(HttpService).axiosRef;
  const configService = app.get(ConfigService);
  const dStorageApiService = app.get(DStorageAPIService);
  const partnerJwtService = app.get(PartnerJwtService);

  const NODE_ENV = configService.getOrThrow<string>('NODE_ENV');
  const PARTNER_ID: string = configService.getOrThrow('PARTNER_ID');
  const AIR_API_ORIGIN = AIR_API[NODE_ENV];
  if (AIR_API_ORIGIN === undefined) throw new Error(`Invalid NODE_ENV: ${NODE_ENV}`);

  for (const { credentialSubject, email, expiration } of items) {
    try {
      const partnerJwt = await partnerJwtService.generateJwt({ email }, {});
      const identity = await axiosRef
        .post<InitializeUserResponse>(
          `${AIR_API_ORIGIN}/v2/auth/initialize-user`,
          { partnerJwt },
          { headers: { 'x-partner-id': PARTNER_ID } },
        )
        .then((e) => e.data);
      if (!identity.did || !identity.publicKey) {
        result.push([email, 'Unable to resolve user']);
        console.error(`Unable to resolve user: ${email}`);
        continue;
      }
      const { did, publicKey } = identity;
      credentialSubject.id = did;

      const credential = await credentialIssuingService.issue({
        credentialSchema: url,
        credentialSubject,
        expiration,
        merklizedRootPosition: MerklizedRootPosition.Value,
        type,
      });
      const data = JSON.stringify(credential);
      const encryptedData = await encryptText(data, hexStrToBuffer(publicKey), { encoding: 'base64' });
      const dstorageResponse = await dStorageApiService.createObject(
        {
          holderDid: identity.did,
          proofType: ProofType.BJJ_SIG_2021,
          schemaId: id,
          expiresAt: new Date(expiration * 1_000).toISOString(),
          data: encryptedData.encryptedData,
          iv: encryptedData.iv,
          authTag: encryptedData.authTag,
          encryptedKey: encryptedData.dataEncPublicKey,
          externalId: credential.id,
        },
        { 'x-partner-auth': partnerJwt },
      );
      result.push([email, dstorageResponse.data.storagePath]);
    } catch (error: any) {
      const axiosData = error.response?.data;
      if (axiosData?.message === 'Invalid email address') {
        result.push([email, axiosData?.message]);
      } else {
        result.push([email, `${error.name}: ${error.message}`]);
        console.error(error);
      }
    }
  }

  return result;
}

void (async () => {
  const SCHEMA_ID = process.argv[2];
  const SCHEMA_URL = process.argv[3];
  const SCHEMA_TYPE = process.argv[4];
  const CSV_FILE = process.argv[5];

  if (SCHEMA_ID === undefined || SCHEMA_URL === undefined || SCHEMA_TYPE === undefined || CSV_FILE === undefined) {
    console.log('Missing Arg/s, required args:');
    console.log(' - arg1: Schema ID');
    console.log(' - arg1: Schema URL');
    console.log(' - arg2: Schema Type\n');
    console.log(' - arg3: CSV File Path');
    console.log('');
    console.log('Example:');
    console.log('pnpm run batch-issue-vc-csv -- \\');
    console.log('  01KKX3Q7DEK0GM2TCKMMHA \\');
    console.log('  https://credential.api.staging.air3.com/dstorage/download/01KKX3Q7DFFWNMD85T17X8 \\');
    console.log('  mocabasher \\');
    console.log('  ./path-to-file.csv');
    process.exit(1);
  }

  const fileContent = fs.readFileSync(CSV_FILE);
  const csvInput = parse<Record<string, string>>(fileContent, { columns: true });

  const credentialRefs: BatchIssueVcItem[] = [];
  for (const row of csvInput) {
    const record: BatchIssueVcItem = {
      credentialSubject: { id: row.holderDid },
      expiration: Math.floor(new Date(row.expiration).getTime() / 1000),
      email: row.email,
    };

    for (const key of Object.keys(row)) {
      if (!key.startsWith('credentialSubject.')) continue;
      const keyPath = key.split('.');
      _.set(record, keyPath, JSON.parse(row[key]));
    }
    credentialRefs.push(record);
  }

  const result = await batchIssueVcCsv({ id: SCHEMA_ID, url: SCHEMA_URL, type: SCHEMA_TYPE }, credentialRefs);
  const csvOutput = stringify(result, { header: false });
  fs.writeFileSync(`${new Date().getTime()}_result.csv`, csvOutput);

  process.exit(0);
})();
