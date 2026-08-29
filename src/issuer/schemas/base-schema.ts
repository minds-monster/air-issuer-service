import { EntityManager } from '@mikro-orm/postgresql';
import { MerklizedRootPosition, W3CCredential } from '@mocanetwork/identity-js-sdk';
import { CredentialIssuingService } from '../../iden3/services/credential-issuing.service';
import { CredentialIssuance } from '../entities/credential-issuance.entity';

export abstract class BaseSchema {
  schemaId: string;
  schemaType: string;
  schemaUrl: string;
  schemaContextUrl: string;

  async claimableVCs(userId: string): Promise<any> {
    return await this.generateCredentialData(userId);
  }

  async issue(
    userId: string,
    opts: {
      holderDID: string;
      issuingService: CredentialIssuingService;
      em?: EntityManager;
    },
  ): Promise<{ id: string; credentialIssuance: CredentialIssuance; credential: W3CCredential }> {
    const data = await this.generateCredentialData(userId);

    const credential = await opts.issuingService.issue({
      merklizedRootPosition: MerklizedRootPosition.Value,
      credentialSchema: this.schemaUrl,
      type: this.schemaType,
      credentialSubject: {
        id: opts.holderDID,
        ...data.credentialSubject,
      },
      expiration: data.expiration,
      em: opts.em,
    });

    const credentialIssuance = new CredentialIssuance();

    credentialIssuance.holderDid = opts.holderDID;
    credentialIssuance.schemaId = this.schemaId;
    credentialIssuance.revocationNonce = credential.credentialStatus.revocationNonce!.toString();
    credentialIssuance.createdAt = new Date(credential.issuanceDate!);
    credentialIssuance.expiresAt = new Date(credential.expirationDate!);
    credentialIssuance.dstorageInfo = null;
    credentialIssuance.revokedAt = null;

    return {
      id: credential.id,
      credentialIssuance,
      credential,
    };
  }

  abstract generateCredentialData(userId: string): Promise<{ credentialSubject: object; expiration: number }>;
}
