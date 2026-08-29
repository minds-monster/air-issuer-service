import { Body, Controller, Get, Header, HttpCode, Param, Post, Query, UseGuards } from '@nestjs/common';
import { AdminApiKeyGuard } from './common/guards/admin-api-key.guard';
import { ApiKeyGuard } from './common/guards/api-key.guard';

import { IssuerService } from './issuer/issuer.service';
import { TokenStatusListService } from './sd-jwt/services/token-status-list.service';

import { AvailableVcRequestBodyDto } from './issuer/dtos/available-vc-request-body.dto';
import { IssuanceHistoryRequestQueryDto } from './issuer/dtos/issuance-history-request-query.dto';
import { IssueSdJwtRequestBodyDto } from './issuer/dtos/issue-sd-jwt-request-body.dto';
import { IssueVcRequestBodyDto } from './issuer/dtos/issue-vc-request-body.dto';
import { NonceParamDto } from './issuer/dtos/nonce-param.dto';
import { NonceRequestBodyDto } from './issuer/dtos/nonce-request-body.dto';
import { RevocationStatusRequestQueryDto } from './issuer/dtos/revocation-status-request-query-dto';
import { StatusListRequestParamDto } from './issuer/dtos/status-list-request-param.dto';

@Controller()
export class AppController {
  constructor(
    private readonly issuerService: IssuerService,
    private readonly tokenStatusListService: TokenStatusListService,
  ) {}

  @UseGuards(ApiKeyGuard)
  @Post('available-vc')
  async availableVc(@Body() body: AvailableVcRequestBodyDto) {
    return await this.issuerService.availableVc(
      {
        holderDID: body.holderDID,
        pubKey: body.pubKey,
        userId: body.userId,
      },
      {
        schemaId: body.schemaId,
        proofType: body.proofType,
      },
    );
  }

  @UseGuards(ApiKeyGuard)
  @Post('issue-vc')
  async issueVc(@Body() body: IssueVcRequestBodyDto) {
    return await this.issuerService.issueVc(
      body.schemaId,
      {
        holderDID: body.holderDID,
        encryptionKey: body.encryptionKey ?? body.pubKey,
        userId: body.userId,
        signingKey: body.signingKey ?? undefined,
      },
      body.proofType,
    );
  }

  @Get('statuslist/:partition')
  @Header('content-type', 'application/statuslist+jwt')
  async statusList(@Param() { partition }: StatusListRequestParamDto) {
    return this.tokenStatusListService.fetchTSLPartition(partition);
  }

  @Get('credential-status/:nonce')
  async credentialStatus(@Param() { nonce }: NonceParamDto) {
    return await this.issuerService.credentialStatus(nonce);
  }

  @Get('revocation-status/:nonce')
  async revocationStatus(@Param() { nonce }: NonceParamDto, @Query() query: RevocationStatusRequestQueryDto) {
    return await this.issuerService.revocationStatus(nonce, query.proofType);
  }

  @UseGuards(AdminApiKeyGuard)
  @Get('admin/issuance-history')
  async adminIssuanceHistory(@Query() query: IssuanceHistoryRequestQueryDto) {
    return await this.issuerService.issuanceHistory(query ?? {});
  }

  @UseGuards(AdminApiKeyGuard)
  @Post('admin/revoke')
  async adminRevoke(@Body() body: NonceRequestBodyDto) {
    await this.issuerService.revoke(body.nonce, body.proofType);
  }

  @UseGuards(AdminApiKeyGuard)
  @Post('admin/publish-token-status-list')
  @HttpCode(200)
  async adminPublishTokenStatusList() {
    await this.tokenStatusListService.publish();
  }

  /**
   * Mint an SD-JWT-VC and return it.
   *
   * Admin-guarded rather than api-key-guarded: unlike `/issue-vc`, which AIR
   * calls on a holder's behalf and which never hands the credential back, this
   * returns a bearer credential directly to whoever asks. That is an operator
   * action, not something the AIR platform should be able to trigger.
   */
  @UseGuards(AdminApiKeyGuard)
  @Post('admin/issue-sd-jwt')
  async adminIssueSdJwt(@Body() body: IssueSdJwtRequestBodyDto) {
    return await this.issuerService.issueSdJwtVcDirect(body.schemaId, body.holderDID, {
      mind_id: body.mindId,
      scopes: body.scopes,
      label: body.label ?? body.mindId,
      audience: body.audience ?? 'adam-id',
      ...(body.grantRef ? { grant_ref: body.grantRef } : {}),
    });
  }

  /** Revoke by nonce without requiring the iden3 wallet to have booted. */
  @UseGuards(AdminApiKeyGuard)
  @Post('admin/revoke-sd-jwt')
  async adminRevokeSdJwt(@Body() body: NonceRequestBodyDto) {
    return await this.issuerService.revokeSdJwt(body.nonce);
  }
}
