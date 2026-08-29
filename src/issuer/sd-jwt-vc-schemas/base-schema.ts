import { EntityManager } from '@mikro-orm/postgresql';
import { DisclosureFrame } from '@sd-jwt/core';
import { SdJwtVcPayload } from '@sd-jwt/sd-jwt-vc';
import { randomBytes, randomUUID } from 'node:crypto';
import { SdJwtVcService } from '../../sd-jwt/services/sd-jwt-vc.service';
import { CredentialIssuance } from '../entities/credential-issuance.entity';

export abstract class BaseSchema<T extends Record<string, unknown>> {
  abstract readonly schemaId: string;
  abstract readonly vct?: string;
  abstract readonly ['vct#integrity']?: string; // TODO: Dashboard integrity implementation
  abstract readonly disclosureFrame: DisclosureFrame<T>;
  abstract readonly expirySec: number;

  async claimableVCs(sub: string): Promise<{ credentialSubject: T; expiration: number }> {
    return await this.generateCredentialData(sub);
  }

  async issue(
    userId: string,
    opts: {
      holderDID: string;
      issuingService: SdJwtVcService;
      cnf?: { jwk: JsonWebKey };
      em?: EntityManager;
      /**
       * Per-request claim values, merged over whatever generateCredentialData
       * derives. Some credentials carry facts that belong to the issuance
       * request rather than to the subject's stored data — which Mind, which
       * scopes — and generateCredentialData only receives a userId, so it has
       * no way to produce them.
       */
      claimsOverride?: Partial<T>;
    },
  ): Promise<{ id: string; credentialIssuance: CredentialIssuance; credential: string }> {
    const { holderDID, issuingService: sdJwtVcService } = opts;

    const { credentialSubject: baseClaims } = await this.generateCredentialData(userId);
    const id = `urn:${randomUUID()}`;
    const nonce = this.generateNonce().toString();

    const iat = Math.floor(Date.now() / 1_000);
    const exp = iat + this.expirySec;

    const claims: T & SdJwtVcPayload = {
      ...baseClaims,
      ...(opts.claimsOverride ?? {}),
      // Below the override on purpose: identity, expiry and revocation handle
      // are the issuer's to set, and a caller must not be able to supply them.
      id,
      nonce,
      vct: this.vct ?? this.schemaId,
      sub: holderDID,
      exp: Math.floor(Date.now() / 1_000) + this.expirySec,
    };

    if (opts.cnf) claims.cnf = opts.cnf;
    if (this['vct#integrity']) claims['vct#integrity'] = this['vct#integrity'];

    const credentialIssuance = new CredentialIssuance();

    credentialIssuance.holderDid = holderDID;
    credentialIssuance.schemaId = this.schemaId;
    credentialIssuance.revocationNonce = nonce;
    credentialIssuance.createdAt = new Date(iat * 1_000);
    credentialIssuance.expiresAt = new Date(exp * 1_000);
    credentialIssuance.dstorageInfo = null;
    credentialIssuance.revokedAt = null;

    const credential = await sdJwtVcService.issue(claims, this.disclosureFrame, { em: opts?.em });
    return {
      id,
      credentialIssuance,
      credential,
    };
  }

  private generateNonce() {
    const buffer = randomBytes(8);
    buffer[0] &= 0x7f;
    return buffer.readBigInt64BE(0);
  }

  abstract generateCredentialData(userId: string): Promise<{ credentialSubject: T; expiration: number }>;
}
