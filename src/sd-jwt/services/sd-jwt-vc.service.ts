import { EntityManager } from '@mikro-orm/postgresql';
import { Injectable, NotFoundException, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { digest, generateSalt } from '@owf/crypto';
import { StatusType } from '@owf/token-status-list';
import { DisclosureFrame, HashAlgorithm } from '@sd-jwt/core';
import { SDJwtVcInstance, SdJwtVcPayload } from '@sd-jwt/sd-jwt-vc';
import { base64url, CompactJWSHeaderParameters, FlattenedSign, importPKCS8 } from 'jose';
import { randomBytes, randomUUID } from 'node:crypto';

import { SdJwtVc } from '../entities/sd-jwt-vc.entity';
import { TokenStatusListService } from './token-status-list.service';

@Injectable()
export class SdJwtVcService implements OnModuleInit {
  /**
   * The `iss` of every SD-JWT-VC, and the origin a verifier resolves issuer
   * metadata from (`${iss}/.well-known/jwt-vc-issuer`). It must be a URL the
   * verifier can actually reach.
   *
   * Kept separate from ISSUER_ORIGIN, which is the `iss` of the *partner* JWT
   * sent to Moca's AIR API and is validated against a whitelisted issuer on
   * their side. Repointing that at a local tunnel would break partner auth, so
   * the two are configured independently even though a hosted deployment would
   * normally set them the same.
   */
  private readonly issuerOrigin =
    this.configService.get<string>('SD_JWT_ISSUER_ORIGIN') ??
    this.configService.getOrThrow<string>('ISSUER_ORIGIN');
  private readonly partnerId = this.configService.getOrThrow<string>('PARTNER_ID');
  private readonly partnerPrivateKeyAlg = this.configService.get<string>('PARTNER_PRIVATE_KEY_ALG') ?? 'ES256';
  private readonly partnerPrivateKeyDer = this.configService.getOrThrow<string>('PARTNER_PRIVATE_KEY_DER');
  private readonly partnerPrivateKeyKid = this.configService.getOrThrow<string>('PARTNER_PRIVATE_KEY_KID');
  private readonly sdJwtHashAlg = this.configService.get<HashAlgorithm>('SD_JWT_HASH_ALG') ?? 'sha-256';

  private sdJwtVcInstance!: SDJwtVcInstance;

  constructor(
    private readonly configService: ConfigService,
    private readonly entityManager: EntityManager,
    private readonly tokenStatusListService: TokenStatusListService,
  ) {}

  async onModuleInit() {
    let pkcs8 = '-----BEGIN PRIVATE KEY-----\n';
    pkcs8 += this.partnerPrivateKeyDer;
    pkcs8 += '\n-----END PRIVATE KEY-----';
    const privateKey = await importPKCS8(pkcs8, this.partnerPrivateKeyAlg);

    this.sdJwtVcInstance = new SDJwtVcInstance({
      hashAlg: this.sdJwtHashAlg,
      signAlg: this.partnerPrivateKeyAlg,
      hasher: digest,
      signer: (data) => this.sign(data, privateKey),
      saltGenerator: generateSalt,
    });
  }

  async issue<Payload extends SdJwtVcPayload>(
    basePayload: Payload,
    disclosureFrame?: DisclosureFrame<Payload>,
    opts?: { em?: EntityManager },
  ) {
    const em = opts?.em ?? this.entityManager;

    const header: object = { kid: this.partnerPrivateKeyKid };
    const id = `urn:${randomUUID()}`;
    const nonce = BigInt(`0x${randomBytes(8).toString('hex')}`).toString();
    const iat = Math.floor(Date.now() / 1000);

    const payload: Payload = {
      ...basePayload,
      id: basePayload.id ?? id,
      nonce: basePayload.nonce ?? nonce,
      iat: basePayload.iat ?? iat,

      iss: this.issuerOrigin,
      // cnf: // Must be passed by the caller
      // status: // TODO: draft-ietf-oauth-status-list-21
    };

    const sdJwtVc = new SdJwtVc();
    sdJwtVc.holder = payload.sub!;
    sdJwtVc.jwt = 'pending';
    sdJwtVc.nonce = payload.nonce as string;
    sdJwtVc.revoked = false;
    sdJwtVc.createdAt = new Date(payload.iat! * 1_000);

    await em.persist(sdJwtVc).flush();

    if (this.tokenStatusListService.partitionSize) {
      const index = Number(sdJwtVc.id) - 1;
      const partition = Math.floor(index / this.tokenStatusListService.partitionSize);

      payload.status = {
        status_list: {
          idx: index % this.tokenStatusListService.partitionSize,
          uri: `${this.issuerOrigin}/statuslist/${partition}`,
        },
      };
    }
    sdJwtVc.jwt = await this.sdJwtVcInstance.issue(payload, disclosureFrame, { header });

    await em.persist(sdJwtVc).flush();

    return sdJwtVc.jwt;
  }

  private async sign(data: string, privateKey: CryptoKey): Promise<string> {
    const [headerb64, payloadb64] = data.split('.');
    const header = Buffer.from(headerb64, 'base64url').toString('utf-8');
    const protectedHeader = <CompactJWSHeaderParameters>JSON.parse(header);
    const payload = base64url.decode(payloadb64);

    const flattedSign = new FlattenedSign(payload);
    flattedSign.setProtectedHeader(protectedHeader);
    const { signature } = await flattedSign.sign(privateKey);

    return signature;
  }

  async revoke(nonce: string) {
    const sdJwtVc = await this.entityManager.findOne(SdJwtVc, { nonce });
    if (sdJwtVc === null) throw new NotFoundException('Revocation nonce not found');
    if (sdJwtVc.revoked) return sdJwtVc;

    sdJwtVc.revoked = true;
    sdJwtVc.updatedAt = new Date();
    await this.entityManager.persist(sdJwtVc).flush();

    return sdJwtVc;
  }

  async isRevoked(nonce: string): Promise<boolean> {
    return await this.entityManager.count(SdJwtVc, { nonce, revoked: true }).then((e) => e > 0);
  }
}
