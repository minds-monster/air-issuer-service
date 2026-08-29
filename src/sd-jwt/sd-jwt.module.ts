import { Module } from '@nestjs/common';

import { DStorageModule } from '../dstorage/dstorage.module';
import { PartnerJwtService } from '../services/partner-jwt.service';
import { SdJwtVcService } from './services/sd-jwt-vc.service';
import { TokenStatusListService } from './services/token-status-list.service';

@Module({
  imports: [DStorageModule],
  controllers: [],
  providers: [SdJwtVcService, TokenStatusListService, PartnerJwtService],
  exports: [SdJwtVcService, TokenStatusListService],
})
export class SdJwtModule {}
