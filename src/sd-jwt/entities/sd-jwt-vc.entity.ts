import { defineEntity, p } from '@mikro-orm/postgresql';

export const SdJwtVcSchema = defineEntity({
  name: 'SdJwtVc',
  properties: {
    id: p.bigint().primary(),
    holder: p.text().index(),
    jwt: p.text(),
    nonce: p.bigint<'string'>().unique(),
    revoked: p.boolean().default(false),
    createdAt: p.datetime().defaultRaw('NOW()'),
    updatedAt: p.datetime().defaultRaw('NOW()'),
  },
});

export class SdJwtVc extends SdJwtVcSchema.class {}

SdJwtVcSchema.setClass(SdJwtVc);
