import { EntityManager, QueryOrder } from '@mikro-orm/postgresql';
import { Injectable, NotFoundException, NotImplementedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { BitsPerStatus, StatusList, StatusType } from '@owf/token-status-list';

import { PartnerJwtService } from '../../services/partner-jwt.service';
import { SdJwtVc } from '../entities/sd-jwt-vc.entity';
import { TSLPartition } from '../entities/tsl-partition.entity';

export const BIT_LENGTH: BitsPerStatus = 1;

@Injectable()
export class TokenStatusListService {
  private readonly issuerOrigin = this.configService.getOrThrow<string>('ISSUER_ORIGIN');
  public readonly partitionSize: number | null = null;

  // TODO: Cache
  private readonly cache: Record<string, { exp: Date; jwt: string }> = {};

  constructor(
    private readonly entityManager: EntityManager,
    private readonly configService: ConfigService,
    private readonly partnerJwtService: PartnerJwtService,
  ) {
    const partitionSize = this.configService.get<'string'>('SD_JWT_TSL_PARTITION_SIZE');
    if (partitionSize) this.partitionSize = Number(partitionSize);
  }

  async fetchTSLPartition(id: number): Promise<string> {
    if (!this.partitionSize) throw new NotImplementedException('Not Supported');

    const partition = await this.entityManager.findOne(TSLPartition, { id });
    if (partition === null) throw new NotFoundException('not_found');

    const sub = `${this.issuerOrigin}/statuslist/${id}`;
    const iat = Math.floor(partition.updatedAt.getTime() / 1_000);
    const jwt = await this.partnerJwtService.signToken({
      protectedHeader: { typ: 'statuslist+jwt' },
      payload: {
        sub,
        iat,
        status_list: partition.status_list,
      },
    });

    return jwt;
  }

  async publish() {
    if (!this.partitionSize) throw new NotImplementedException('Not Supported');

    const maxBit = await this.entityManager
      .findOne(SdJwtVc, { id: { $ne: null } }, { orderBy: [{ id: QueryOrder.DESC }] })
      .then((e) => BigInt(e?.id?.toString() ?? '0'));

    if (maxBit === 0n) return;

    let totalPartitions = maxBit / BigInt(this.partitionSize);
    if (maxBit % BigInt(this.partitionSize) > 0n) totalPartitions += 1n;

    for (let partition = 0; partition < totalPartitions; partition++) {
      const offset = partition * this.partitionSize;
      const statusList = new StatusList(new Array<number>(Number(this.partitionSize)).fill(0), 1);
      const batch = await this.entityManager.find(
        SdJwtVc,
        { id: { $gt: offset, $lte: offset + this.partitionSize }, revoked: true },
        { fields: ['id'], orderBy: [{ id: QueryOrder.ASC }] },
      );
      batch.forEach((e) => {
        const index = Number(e.id) - 1 - offset;
        statusList.setStatus(index, StatusType.Invalid);
      });

      let tslPartition = await this.entityManager.findOne(TSLPartition, { id: partition });
      tslPartition ??= new TSLPartition();
      tslPartition.id ??= BigInt(partition);
      tslPartition.bits ??= BIT_LENGTH;
      tslPartition.list = statusList.compressStatusListToBytes();
      tslPartition.updatedAt = new Date();

      await this.entityManager.persist(tslPartition).flush();
    }
  }

  // NOTE: Don't run, prone to race condition
  private async updateStatus(id: bigint, status: StatusType) {
    if (!this.partitionSize) return;

    const globalIndex = id - 1n;
    const partition = BigInt(globalIndex) / BigInt(this.partitionSize);
    const index = globalIndex % BigInt(this.partitionSize);

    let tslPartition = await this.entityManager.findOne(TSLPartition, { id: partition });
    let statusList = tslPartition?.list && StatusList.decompressStatusListFromBytes(tslPartition.list, BIT_LENGTH);
    statusList ??= new StatusList(new Array<number>(Number(this.partitionSize)).fill(0), BIT_LENGTH);
    statusList.setStatus(Number(index), status);

    tslPartition ??= new TSLPartition();
    tslPartition.id ??= BigInt(partition);
    tslPartition.bits ??= BIT_LENGTH;
    tslPartition.list = statusList.compressStatusListToBytes();
    tslPartition.updatedAt = new Date();

    await this.entityManager.persist(tslPartition).flush();
  }
}
