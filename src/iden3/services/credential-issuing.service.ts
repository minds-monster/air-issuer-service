import { EntityManager } from '@mikro-orm/postgresql';
import { Blockchain, DID, DidMethod, NetworkId } from '@mocanetwork/moca-iden3';
import {
  BjjProvider,
  CredentialRequest,
  CredentialStatusType,
  CredentialStorage,
  CredentialWallet,
  IDataStorage,
  Identity,
  IdentityStorage,
  IdentityWallet,
  InMemoryDataSource,
  InMemoryMerkleTreeStorage,
  InMemoryPrivateKeyStore,
  KMS,
  KmsKeyType,
  MerklizedRootPosition,
  Profile,
  SubjectPosition,
  W3CCredential,
} from '@mocanetwork/identity-js-sdk';
import { HttpService } from '@nestjs/axios';
import { Injectable, Logger, OnModuleInit, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomUUID } from 'node:crypto';
import { encryptText } from '../../common/utils/encryption';
import { hexStrToBuffer } from '../../common/utils/string';
import { createDocumentLoader } from '../lib/document-loader';

import { DStorageAPIService } from '../../dstorage/services/dstorage-api.service';
import { Credential } from '../entities/credential.entity';
import { Revocation } from '../entities/revocation.entity';

const NETWORK_ID: Record<string, string> = { production: NetworkId.Main };

@Injectable()
export class CredentialIssuingService implements OnModuleInit {
  private readonly logger = new Logger(CredentialIssuingService.name);
  private readonly nodeEnv = this.configService.get<string>('NODE_ENV') ?? 'sandbox';

  private readonly issuerOrigin: string;
  private readonly documentLoader = createDocumentLoader(this.httpService);
  private readonly dataStorage: IDataStorage;
  private readonly credentialWallet: CredentialWallet;
  private readonly identityWallet: IdentityWallet;

  private readonly method: (typeof DidMethod)[string];
  private readonly blockchain: (typeof Blockchain)[string];
  private readonly networkId: (typeof NetworkId)[string];

  private issuerDID: DID;

  constructor(
    private readonly configService: ConfigService,
    private readonly dStorageAPIService: DStorageAPIService,
    private readonly httpService: HttpService,
    private readonly entityManager: EntityManager,
  ) {
    this.method = this.configService.get('IDEN3_METHOD') ?? DidMethod.Air;
    this.blockchain = this.configService.get('IDEN3_BLOCKCHAIN') ?? Blockchain.Id;
    this.networkId = NETWORK_ID[this.nodeEnv] ?? this.configService.get<string>('IDEN3_NETWORK_ID') ?? NetworkId.Testnet;

    this.issuerOrigin = this.configService.getOrThrow<string>('ISSUER_ORIGIN').trim().replace(/\/+$/, '');
    this.dataStorage = {
      credential: new CredentialStorage(new InMemoryDataSource<W3CCredential>()),
      identity: new IdentityStorage(new InMemoryDataSource<Identity>(), new InMemoryDataSource<Profile>()),
      mt: new InMemoryMerkleTreeStorage(40),
      states: { getRpcProvider: () => null } as any,
    };
    const memoryKeyStore = new InMemoryPrivateKeyStore();
    const bjjProvider = new BjjProvider(KmsKeyType.BabyJubJub, memoryKeyStore);
    const kms = new KMS();
    kms.registerKeyProvider(KmsKeyType.BabyJubJub, bjjProvider);

    this.credentialWallet = new CredentialWallet(this.dataStorage);
    this.identityWallet = new IdentityWallet(kms, this.dataStorage, this.credentialWallet);
  }

  async onModuleInit() {
    const seed = this.configService.getOrThrow<string>('SEED');
    const issuerIdentity = await this.identityWallet.createIdentity({
      method: this.method,
      blockchain: this.blockchain,
      networkId: this.networkId,
      seed: hexStrToBuffer(seed),
      revocationOpts: {
        type: CredentialStatusType.SparseMerkleTreeProof,
        id: `${this.issuerOrigin}/credential-status`,
        nonce: 0,
        genesisPublishingDisabled: false,
      },
    });
    this.issuerDID = issuerIdentity.did;
    this.logger.log(`Issuer DID: ${this.issuerDID.string()}`);
  }

  async issue(opts: {
    credentialSchema: string;
    type: string;
    merklizedRootPosition: MerklizedRootPosition;
    credentialSubject: { id: string } & Record<string, any>;
    expiration: number;
    em?: EntityManager;
  }) {
    this.assertSetupState();

    const em = opts.em ?? this.entityManager;
    const credentialRequest: CredentialRequest = {
      ...opts,
      merklizedRootPosition: MerklizedRootPosition.Value,
      subjectPosition: SubjectPosition.Index,
      revocationOpts: {
        type: CredentialStatusType.SparseMerkleTreeProof,
        id: `${this.issuerOrigin}/credential-status`,
      },
    };

    const credential = await this.identityWallet.issueCredential(this.issuerDID, credentialRequest, {
      documentLoader: this.documentLoader,
    });

    const credentialDoc = credential.toJSON();

    const credentialRecord = new Credential();
    credentialRecord.holder = opts.credentialSubject.id;
    credentialRecord.document = credentialDoc;
    credentialRecord.nonce = credentialDoc.credentialStatus.revocationNonce!.toString();
    credentialRecord.createdAt = new Date();

    await em.persist(credentialRecord).flush();
    return credentialDoc;
  }

  async credentialStatus(nonce: string) {
    // TODO: implement tree state management
    // when MTP-based credentials becomes enabled.
    // const treeStateSnapshot = ...;

    const {
      proof,
      treeState: { state, claimsRoot, rootOfRoots, revocationRoot },
    } = await this.identityWallet.generateNonRevocationMtpWithNonce(this.issuerDID, BigInt(nonce));

    return {
      mtp: {
        ...proof.toJSON(),
        // NOTE: fake `existence` logic
        existence: await this.isRevoked(nonce),
      },
      issuer: {
        state: state.hex(),
        claimsTreeRoot: claimsRoot.hex(),
        rootOfRoots: rootOfRoots.hex(),
        revocationTreeRoot: revocationRoot.hex(),
      },
    };
  }

  async revoke(nonce: string) {
    this.assertSetupState();

    const existing = await this.entityManager.findOne(Revocation, { nonce });
    if (existing) return existing;

    const revocation = new Revocation();
    revocation.nonce = nonce;
    revocation.createdAt = new Date();
    await this.entityManager.persist(revocation).flush();

    return revocation;
  }

  async isRevoked(nonce: string): Promise<boolean> {
    return await this.entityManager.count(Revocation, { nonce }).then((e) => e > 0);
  }

  async encrypt(text: string, pubKeyHexString: string, opts?: { encoding: 'hex' | 'base64' }) {
    // NOTE: Temporarily placed here just for example integration ease
    const pubKey = hexStrToBuffer(pubKeyHexString);
    return await encryptText(text, pubKey, opts);
  }

  private assertSetupState() {
    if (!this.issuerDID) {
      throw new ServiceUnavailableException('Server initializing');
    }
  }
}
