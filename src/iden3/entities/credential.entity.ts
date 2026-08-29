import { defineEntity, p } from '@mikro-orm/postgresql';
import { W3CCredential } from '@mocanetwork/identity-js-sdk';

export const CredentialSchema = defineEntity({
  name: 'Credential',
  properties: {
    id: p.bigint().primary(),
    holder: p.text().index(),
    document: p.json<W3CCredential & { proof: any }>(),
    nonce: p.bigint<'string'>().unique(),
    createdAt: p.datetime().defaultRaw('NOW()'),
  },
});

export class Credential extends CredentialSchema.class {}

CredentialSchema.setClass(Credential);
