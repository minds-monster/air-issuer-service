import { Injectable, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { importPKCS8, JWTHeaderParameters, JWTPayload, SignJWT } from 'jose';

const EXPIRY_MS = 15 * 60_000;
const CACHE_EXPIRY_THRESHOLD_MS = 2 * 60_000;

@Injectable()
export class PartnerJwtService implements OnModuleInit {
  private readonly partnerId = this.configService.getOrThrow<string>('PARTNER_ID');
  private readonly der = this.configService.getOrThrow<string>('PARTNER_PRIVATE_KEY_DER');
  private readonly alg = this.configService.get<string>('PARTNER_PRIVATE_KEY_ALG') ?? 'ES256';
  private readonly kid = this.configService.getOrThrow<string>('PARTNER_PRIVATE_KEY_KID');
  private readonly issuerOrigin = this.configService.getOrThrow<string>('ISSUER_ORIGIN');

  private jwtCache: { [cacheId: string]: string } = {};

  private partnerPrivateKey: CryptoKey;

  constructor(private readonly configService: ConfigService) {}

  async onModuleInit() {
    let pkcs8 = '-----BEGIN PRIVATE KEY-----\n';
    pkcs8 += this.der;
    pkcs8 += '\n-----END PRIVATE KEY-----';

    this.partnerPrivateKey = await importPKCS8(pkcs8, this.alg);
  }

  async generateJwt(claims: { email?: string; scope?: string }, opts?: { aud?: string }): Promise<string> {
    const cacheId = claims?.email ?? '_global';
    const cache = this.jwtCache[cacheId];
    if (cache) return cache;

    const expiry = new Date(Date.now() + EXPIRY_MS);
    const headers: JWTHeaderParameters = {
      alg: this.alg,
      kid: this.kid,
    };

    const signJwt = new SignJWT({ ...claims, partnerId: this.partnerId });
    signJwt.setProtectedHeader(headers);
    signJwt.setExpirationTime(expiry);
    signJwt.setIssuer(this.issuerOrigin);
    signJwt.setIssuedAt(new Date());

    if (opts?.aud) signJwt.setAudience(opts.aud);

    const jwt = await signJwt.sign(this.partnerPrivateKey);
    this.jwtCache[cacheId] = jwt;

    const cacheExpiry = expiry.getTime() - Date.now() - CACHE_EXPIRY_THRESHOLD_MS;
    setTimeout(() => delete this.jwtCache[cacheId], cacheExpiry);

    return jwt;
  }

  async signToken(params: { protectedHeader: Partial<JWTHeaderParameters>; payload: JWTPayload }): Promise<string> {
    const headers: JWTHeaderParameters = {
      ...params.protectedHeader,
      alg: this.alg,
      kid: this.kid,
    };

    const signJwt = new SignJWT({ ...params.payload, partnerId: this.partnerId });
    signJwt.setProtectedHeader(headers);
    signJwt.setIssuer(this.issuerOrigin);

    if (params.payload.iat !== undefined) signJwt.setIssuedAt(new Date());

    return signJwt.sign(this.partnerPrivateKey);
  }
}
