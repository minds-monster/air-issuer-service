import { BaseSchema } from './base-schema';

/**
 * XDataAccess — the dashboard-registered AIR credential recording that a Mind was
 * granted access to the adam-id vault.
 *
 * This is the *durable record*, not the thing a Mind presents. An AIR credential is
 * encrypted to the holder's public key and stored in DStorage; it is never returned to
 * the issuer, and verifying one requires the AIR browser widget with the holder's
 * consent to decrypt. A headless Mind can do none of that. What a Mind actually sends
 * on each request is the SD-JWT-VC from `../sd-jwt-vc-schemas/schema_adam_id_access`,
 * which is server-verifiable and bearer-presentable.
 *
 * So the two exist for different reasons: this one is network-recognised provenance that
 * anyone trusting the AIR verifier can check; that one is the runtime credential. Neither
 * substitutes for the other.
 *
 * `scopes` is a SPACE-DELIMITED STRING, not an array — the registered JSON-LD context
 * types it `xsd:string`, and iden3 merklization follows the context, not our preference.
 * Space-delimited matches the OAuth `scope` convention that adam-id's `scopesFromClaims`
 * already parses, so the value stays interchangeable with the SD-JWT's array form.
 */
const EXPIRY_SEC = 24 * 60 * 60; // match the SD-JWT credential's 24h

export interface XDataAccessClaims {
  mindId: string;
  /** Space-delimited, e.g. "tweets.read analytics.read". */
  scopes: string;
  audience: string;
  label: string;
}

export default class Schema extends BaseSchema {
  public readonly schemaId = '01KZ91Q7HRK18J1M08S1KP';
  public readonly schemaType = 'XDataAccess';
  public readonly schemaUrl =
    'https://credential-testnet.api.sandbox.air3.com/dstorage/download/01KZ91Q7HSB227FEKYNSBC';
  public readonly schemaContextUrl =
    'https://credential-testnet.api.sandbox.air3.com/dstorage/download/01KZ91Q7HSYYVN80EY28D5';

  /**
   * Per-grant values, set by the caller before `issue()`.
   *
   * The iden3 BaseSchema hands `generateCredentialData` only a userId, and unlike the
   * SD-JWT path there is no `claimsOverride` seam on it. Rather than change upstream's
   * iden3 base class, the runner sets these first — see scripts/issue-air-credential.ts.
   * All four are required by the registered schema, so there are no safe defaults to
   * fall back on.
   */
  public pending: XDataAccessClaims | null = null;

  generateCredentialData(userId: string) {
    if (!this.pending) {
      throw new Error(
        'XDataAccess claims were not set. Assign `schema.pending` before issuing — ' +
          'the registered schema requires mindId, scopes, audience and label, and this ' +
          'credential must not be issued with placeholder values.',
      );
    }
    const { mindId, scopes, audience, label } = this.pending;
    if (!mindId || !scopes || !audience || !label) {
      throw new Error('XDataAccess requires mindId, scopes, audience and label to be non-empty.');
    }

    return Promise.resolve({
      credentialSubject: { mindId, scopes, audience, label },
      expiration: Math.floor(Date.now() / 1000) + EXPIRY_SEC,
    });
  }
}
