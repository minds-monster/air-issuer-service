import { IsEnum, IsNotEmpty, IsOptional, IsString, Matches } from 'class-validator';
import { ProofType } from '../enums/proof-type.enum';
import { DID_REGEXP } from '../../iden3/constants';

export class AvailableVcRequestBodyDto {
  @IsString()
  @IsNotEmpty()
  @Matches(DID_REGEXP, { message: 'Invalid holderDID Format' })
  holderDID: string;

  @IsString()
  @IsNotEmpty()
  pubKey: string;

  @IsString()
  @IsNotEmpty()
  userId: string;

  @IsOptional()
  @IsString()
  @IsNotEmpty()
  schemaId?: string;

  @IsOptional()
  @IsEnum(ProofType)
  @IsNotEmpty()
  proofType?: ProofType;
}
