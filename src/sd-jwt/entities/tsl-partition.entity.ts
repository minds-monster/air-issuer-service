import { defineEntity, p } from '@mikro-orm/postgresql';

export const TSLPartitionSchema = defineEntity({
  name: 'TSLPartition',
  tableName: 'tsl_partition',
  properties: {
    id: p.bigint().primary().autoincrement(false),
    bits: p.integer().unsigned().default(1),
    list: p.blob().comment('zlib deflated'),
    updatedAt: p.datetime().defaultRaw('NOW()'),
  },
});

export class TSLPartition extends TSLPartitionSchema.class {
  get status_list() {
    return {
      bits: this.bits,
      lst: Buffer.from(this.list).toString('base64url'),
    };
  }
}

TSLPartitionSchema.setClass(TSLPartition);
