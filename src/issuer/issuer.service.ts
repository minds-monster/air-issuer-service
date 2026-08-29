import { EntityManager, FilterQuery, FindOptions } from '@mikro-orm/postgresql';
import { Injectable, NotFoundException } from '@nestjs/common';

import { CredentialIssuingService } from '../iden3/services/credential-issuing.service';
import { Revocation } from '../iden3/entities/revocation.entity';
import { SdJwtVc } from '../sd-jwt/entities/sd-jwt-vc.entity';
import { CredentialIssuance } from './entities/credential-issuance.entity';

import { encryptText } from '../common/utils/encryption';
import { hexStrToBuffer } from '../common/utils/string';
import { DStorageAPIService } from '../dstorage/services/dstorage-api.service';
import { SdJwtVcService } from '../sd-jwt/services/sd-jwt-vc.service';
import { PartnerJwtService } from '../services/partner-jwt.service';

import Iden3Schemas from './schemas';
import { BaseSchema as Iden3BaseSchema } from './schemas/base-schema';

import SdJwtVCSchemas from './sd-jwt-vc-schemas';
import { BaseSchema as SdJwtVCBaseSchema } from './sd-jwt-vc-schemas/base-schema';

import { ProofType } from './enums/proof-type.enum';

@Injectable()
export class IssuerService {
  private readonly schemas: {
    [ProofType.BJJ_SIG_2021]: Iden3BaseSchema[];
    [ProofType.SD_JWT_VC]: SdJwtVCBaseSchema<any>[];
  };
  private readonly schemaIdMap: {
    [ProofType.BJJ_SIG_2021]: { [schemaId: string]: Iden3BaseSchema };
    [ProofType.SD_JWT_VC]: { [schemaId: string]: SdJwtVCBaseSchema<any> };
  };

  constructor(
    private readonly entityManager: EntityManager,
    private readonly dStorageApiService: DStorageAPIService,
    private readonly partnerJwtService: PartnerJwtService,

    // NOTE: Treat CredentialIssuingService as a separate http service.
    // Intended design is HTTP Interaction. For ease of integration,
    // temporarily exposed the underlying service.
    private readonly credentialIssuingService: CredentialIssuingService,
    private readonly sdJwtVcService: SdJwtVcService,
  ) {
    this.schemas = {
      [ProofType.BJJ_SIG_2021]: Iden3Schemas,
      [ProofType.SD_JWT_VC]: SdJwtVCSchemas,
    };

    this.schemaIdMap = {
      [ProofType.BJJ_SIG_2021]: {},
      [ProofType.SD_JWT_VC]: {},
    };

    Iden3Schemas.forEach((e) => {
      this.schemaIdMap[ProofType.BJJ_SIG_2021][e.schemaId] = e;
    });

    SdJwtVCSchemas.forEach((e) => {
      this.schemaIdMap[ProofType.SD_JWT_VC][e.schemaId] = e;
    });
  }

  async availableVc(
    holder: { userId: string; holderDID: string; pubKey: string },
    filters?: { schemaId?: string; proofType?: ProofType },
  ): Promise<object> {
    const VCs: any[] = [];

    for (const proofType of Object.keys(this.schemas) as ProofType[]) {
      console.log(proofType);
      console.log(filters?.proofType);
      if (filters?.proofType !== undefined && filters?.proofType !== proofType) {
        continue;
      }
      for (const schema of this.schemas[proofType]) {
        if (![schema.schemaId, undefined].includes(filters?.schemaId)) {
          continue;
        }

        const { credentialSubject } = await schema.generateCredentialData(holder.userId);
        const payload = JSON.stringify(credentialSubject);
        const encryptedData = await this.credentialIssuingService.encrypt(payload, holder.pubKey, {
          encoding: 'base64',
        });

        VCs.push({
          holderDID: holder.holderDID,
          schemaId: schema.schemaId,
          credentialSubject: encryptedData,
          proofType,
        });
      }
    }

    return { data: VCs };
  }

  async issueVc(
    schemaId: string,
    holder: { userId: string; holderDID: string; pubKey: string },
    proofType?: ProofType,
  ): Promise<void> {
    proofType ??= ProofType.BJJ_SIG_2021;

    await this.entityManager.transactional(async (em) => {
      const issued =
        proofType === ProofType.SD_JWT_VC
          ? await this.issueSdJwtVc(schemaId, holder)
          : await this.issueBjjSig(schemaId, holder);
      const { credential, credentialIssuance, id: credentialId } = issued;

      const payload = JSON.stringify(credential);
      const encryptedData = await encryptText(payload, hexStrToBuffer(holder.pubKey), { encoding: 'base64' });

      await em.persist(credentialIssuance).flush();

      const partnerJwt = await this.partnerJwtService.generateJwt({}, {});
      const dstorageInfo = await this.dStorageApiService.createObject(
        {
          holderDid: holder.holderDID,
          schemaId,
          expiresAt: credentialIssuance.expiresAt.toISOString(),
          data: encryptedData.encryptedData,
          iv: encryptedData.iv,
          authTag: encryptedData.authTag,
          encryptedKey: encryptedData.dataEncPublicKey,
          externalId: credentialId,
        },
        { 'x-partner-auth': partnerJwt },
      );
      credentialIssuance.dstorageInfo = dstorageInfo.data;

      await em.persist(credentialIssuance).flush();
    });
  }

  /**
   * Issue an SD-JWT-VC and return it to the caller.
   *
   * Deliberately not `issueVc`. That path encrypts the credential to the
   * holder's public key and pushes it to Moca DStorage, returning nothing —
   * right for a credential a person will later present through the AIR wallet,
   * useless for a headless agent, which cannot decrypt it and has no browser in
   * which to run the AIR verifier. A bearer-presented credential has to come
   * back over the wire, so this skips the encrypt/DStorage leg entirely.
   *
   * The CredentialIssuance row is still written, so `revocation-status` and
   * `issuance-history` behave exactly as they do for any other credential.
   */
  async issueSdJwtVcDirect(
    schemaId: string,
    holderDID: string,
    claimsOverride: Record<string, unknown>,
    userId?: string,
  ): Promise<{ credential: string; credentialId: string; nonce: string; expiresAt: string }> {
    const schema = this.schemaIdMap[ProofType.SD_JWT_VC][schemaId];
    if (schema === undefined) throw new NotFoundException(`Invalid Schema: ${schemaId}`);

    return await this.entityManager.transactional(async (em) => {
      const { credential, credentialIssuance, id } = await schema.issue(userId ?? holderDID, {
        holderDID,
        issuingService: this.sdJwtVcService,
        em,
        claimsOverride,
      });

      await em.persist(credentialIssuance).flush();

      return {
        credential,
        credentialId: id,
        nonce: credentialIssuance.revocationNonce,
        expiresAt: credentialIssuance.expiresAt.toISOString(),
      };
    });
  }

  /**
   * Revoke by nonce without involving the iden3 stack.
   *
   * `CredentialIssuingService.revoke` first asserts that the iden3 identity
   * wallet finished booting from SEED — irrelevant to an SD-JWT credential, and
   * a way for revocation to fail for reasons unrelated to it. Revocation status
   * is just a row count on Revocation (see `isRevoked`), so writing that row is
   * both necessary and sufficient. Revocation is the one operation that should
   * have no avoidable dependencies.
   */
  async revokeSdJwt(nonce: string): Promise<{ revoked: boolean }> {
    await this.entityManager.transactional(async (em) => {
      const existing = await em.findOne(Revocation, { nonce });
      if (!existing) {
        const revocation = new Revocation();
        revocation.nonce = nonce;
        revocation.createdAt = new Date();
        em.persist(revocation);
      }
      await em.nativeUpdate(CredentialIssuance, { revocationNonce: nonce }, { revokedAt: new Date() });
      await em.nativeUpdate(SdJwtVc, { nonce }, { revoked: true });
      await em.flush();
    });
    return { revoked: true };
  }

  private async issueBjjSig(schemaId: string, holder: { userId: string; holderDID: string }) {
    const schema = this.schemaIdMap[ProofType.BJJ_SIG_2021][schemaId];
    if (schema === undefined) throw new NotFoundException(`Invalid Schema: ${schemaId}`);

    return await schema.issue(holder.userId, {
      holderDID: holder.holderDID,
      issuingService: this.credentialIssuingService,
    });
  }

  private async issueSdJwtVc(schemaId: string, holder: { userId: string; holderDID: string }) {
    const schema = this.schemaIdMap[ProofType.SD_JWT_VC][schemaId];
    if (schema === undefined) throw new NotFoundException(`Invalid Schema: ${schemaId}`);

    return await schema.issue(holder.userId, {
      holderDID: holder.holderDID,
      issuingService: this.sdJwtVcService,
    });
  }

  async credentialStatus(nonce: string) {
    return this.credentialIssuingService.credentialStatus(nonce);
  }

  async issuanceHistory(query: {
    page?: number;
    limit?: number;
    order?: string;
    holderDid?: string;
    schemaId?: string;
    revocationNonce?: string;
  }) {
    const page = query.page ?? 1;
    const limit = query.limit ?? 25;
    const [orderKey, orderDirection] = (query.order ?? 'id_asc').split(/_(?=asc|desc$)/);

    const filters: FilterQuery<NoInfer<CredentialIssuance>> = {};

    if (query.holderDid !== undefined) filters.holderDid = query.holderDid;
    if (query.schemaId !== undefined) filters.schemaId = query.schemaId;
    if (query.revocationNonce !== undefined) filters.revocationNonce = query.revocationNonce;

    const findOptions: FindOptions<CredentialIssuance> = {
      limit,
      offset: (page - 1) * limit,
      orderBy: { [orderKey]: orderDirection },
    };

    const [records, total] = await this.entityManager.findAndCount(CredentialIssuance, filters, findOptions);
    const data = records.map((e) => {
      return {
        holderDid: e.holderDid,
        schemaId: e.schemaId,
        revocationNonce: e.revocationNonce.toString(),
        createdAt: e.createdAt.toISOString(),
        expiresAt: e.expiresAt.toISOString(),
        revokedAt: e.revokedAt?.toISOString() ?? null,
        type: 'bjj',
      };
    });

    return {
      data,
      pagination: { page, limit, total },
    };
  }

  async revocationStatus(nonce: string) {
    const isRevoked = await this.credentialIssuingService.isRevoked(nonce);
    return { isRevoked };
  }

  async revoke(revocationNonce: string): Promise<void> {
    await this.entityManager.transactional(async (em) => {
      const revocation = await this.credentialIssuingService.revoke(revocationNonce);
      await em.nativeUpdate(CredentialIssuance, { revocationNonce }, { revokedAt: revocation.createdAt });
    });
  }
}
