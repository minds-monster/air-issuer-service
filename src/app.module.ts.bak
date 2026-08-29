import { MikroOrmModule } from '@mikro-orm/nestjs';
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import mikroOrmConfig from './mikro-orm.config';

import { DStorageModule } from './dstorage/dstorage.module';
import { HttpModule } from './dynamic-modules/http-module';
import { Iden3Module } from './iden3/iden3.module';
import { SdJwtModule } from './sd-jwt/sd-jwt.module';
import { IssuerModule } from './issuer/issuer.module';

import { AppController } from './app.controller';
import { WellKnownController } from './well-known.controller';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    MikroOrmModule.forRoot(mikroOrmConfig),

    DStorageModule,
    HttpModule,
    IssuerModule,
    Iden3Module,
    SdJwtModule,
  ],
  controllers: [AppController, WellKnownController],
  providers: [],
})
export class AppModule {}
