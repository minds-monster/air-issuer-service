import { DisclosureFrame } from '@sd-jwt/core';
import { BaseSchema } from './base-schema';

/**
 * Access credential for the adam-id vault.
 *
 * Issued to a headless agent (a Hello Minds "Mind") so it can read a private X
 * archive over MCP. The vault verifies this server-side with `jose` against the
 * JWKS at `${SD_JWT_ISSUER_ORIGIN}/.well-known/jwt-vc-issuer`, then intersects
 * `scopes` with a grant held locally on the vault machine. The credential can
 * therefore be over-broad without being dangerous — it is a ceiling, not an
 * authorization by itself.
 *
 * Everything the vault gates on is DELIBERATELY NOT selectively disclosed.
 * Selective disclosure protects a holder from a verifier; here the verifier is
 * the vault owner, so there is nothing to protect, and hiding `scopes` behind a
 * disclosure would mean a holder who simply omits it presents a credential that
 * verifies while asserting nothing. Only `label` — cosmetic, used for audit
 * lines — sits behind `_sd`.
 */
type Claim = {
  /** Hello Minds Mind id. The vault matches its grant table on this. */
  mind_id: string;
  /** Requested vault scopes, e.g. ["tweets.read"]. */
  scopes: string[];
  /** Human-readable name, for the vault's audit log. */
  label: string;
  /** Pins the credential to one vault; the vault rejects a mismatch. */
  audience: string;
  /** Opaque reference tying this credential back to a local grant. */
  grant_ref?: string;
};

class SchemaAdamIdAccess extends BaseSchema<Claim> {
  public readonly schemaId = 'adam-id-access-v1';
  public readonly vct = 'https://adam.id/vct/adam-id-access/v1';
  public readonly ['vct#integrity'] = undefined;

  public readonly disclosureFrame: DisclosureFrame<Claim> = {
    _sd: ['label'],
  };

  /**
   * 24 hours. The credential is a pure bearer token — `cnf` key binding is not
   * implemented, and a Mind has no secret store, so this will end up sitting in
   * a conversation transcript. Expiry is the main thing bounding that exposure.
   */
  public readonly expirySec = 24 * 60 * 60;

  /**
   * Placeholder claims.
   *
   * Real values arrive through `claimsOverride` on `issue()`, because the per-
   * grant facts (which Mind, which scopes) are request data, not something this
   * schema can derive from a user id. `scopes` defaults to EMPTY on purpose: a
   * credential minted without an explicit grant should authorize nothing, and
   * the vault rejects a credential asserting no recognised scopes outright.
   */
  async generateCredentialData(userId: string) {
    return Promise.resolve({
      credentialSubject: {
        mind_id: userId,
        scopes: [] as string[],
        label: userId,
        audience: 'adam-id',
      },
      expiration: Math.floor(Date.now() / 1000) + this.expirySec,
    });
  }
}

export default new SchemaAdamIdAccess();
